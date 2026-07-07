# VeriAudit - Orchestrator (Hardcoded state machine)
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from veriaudit.core.event_ledger import EventLedger
from veriaudit.core.finding_state_machine import FindingStateMachine
from veriaudit.core.invariants import InvariantEngine
from veriaudit.core.judge_engine import JudgeEngine
from veriaudit.core.contradiction_detector import ContradictionDetector
from veriaudit.core.container_pool import ContainerPool
from veriaudit.core.scheduler import Scheduler
from veriaudit.core.schema import (
    AuditEvent,
    AuditMode,
    AuditPlan,
    AuditReport,
    AuditRequest,
    EventType,
    Finding,
    FindingStatus,
    ProjectProfile,
    gen_id,
    Paths,
)
from veriaudit.adapters.registry import AdapterRegistry

from .base_agent import BaseAgent


class Orchestrator:
    """
    Hardcoded state machine that orchestrates the audit pipeline.
    Agents internally use ReAct, but the sequence of phases is fixed.
    """

    def __init__(self,
                 agents: Dict[str, BaseAgent],
                 adapters: AdapterRegistry,
                 ledger: EventLedger,
                 invariants: InvariantEngine,
                 judge_engine: JudgeEngine,
                 contradiction_detector: ContradictionDetector,
                 container_pool: ContainerPool,
                 state_machine: FindingStateMachine,
                 config: Dict[str, Any] | None = None):
        self._agents = agents
        self._adapters = adapters
        self._ledger = ledger
        self._invariants = invariants
        self._judge = judge_engine
        self._contradiction = contradiction_detector
        self._containers = container_pool
        self._state_machine = state_machine
        self._config = config or {}

        self._current_correlation_id: str = ""
        self._current_task_id: str = ""
        self._all_findings: List[Finding] = []
        self._events: List[AuditEvent] = []
        self._profile: Optional[ProjectProfile] = None
        self._plan: Optional[AuditPlan] = None
        self._container_id: str = ""

    # =================================================================
    # Main Entry Point
    # =================================================================

    def audit(self, request: AuditRequest) -> AuditReport:
        """Execute a complete audit. This is the system's only external entry point."""
        start_time = datetime.now(timezone.utc)
        self._current_correlation_id = gen_id("corr")
        self._current_task_id = request.task_id or gen_id("task")

        # Write session start event
        self._ledger.append(AuditEvent(
            correlation_id=self._current_correlation_id,
            task_id=self._current_task_id,
            event_type=EventType.AUDIT_SESSION_CREATED,
            agent_id="orchestrator",
            payload={"repo_url": request.repo_url, "mode": request.mode.value, "commit": request.commit},
        ))

        try:
            # Phase 1: Init — clone, detect language, profile
            self._init_phase(request)

            # Phase 2: Build — create container, configure build
            self._build_phase(request.mode)

            # Phase 3: Recon — import CPG, find entrypoints
            self._recon_phase(request.mode)

            # Phase 4: Static Scan — run SAST tools, normalize
            self._static_scan_phase(request.mode)

            # Phase 5: CPG/Taint — reachability analysis
            self._cpg_taint_phase(request.mode)

            # Phase 6: Exploit — generate triggers, run fuzz, self-verify
            self._exploit_phase(request.mode)

            # Phase 7: Contradiction detection
            self._contradiction_phase()

            # Phase 8: Validation — independent re-verification
            self._validation_phase(request.mode)

            # Phase 9: Judge — deterministic rules + LLM fallback
            self._judge_phase()

            # Phase 10: Report
            report = self._report_phase(request)

            # Finalize
            report.started_at = start_time
            report.completed_at = datetime.now(timezone.utc)
            report.duration_seconds = (report.completed_at - report.started_at).total_seconds()
            report.status = "completed"

            self._ledger.append(AuditEvent(
                correlation_id=self._current_correlation_id,
                task_id=self._current_task_id,
                event_type=EventType.AUDIT_SESSION_COMPLETED,
                agent_id="orchestrator",
                payload={"duration_seconds": report.duration_seconds},
            ))

            return report

        except Exception as e:
            self._ledger.append(AuditEvent(
                correlation_id=self._current_correlation_id,
                task_id=self._current_task_id,
                event_type=EventType.ERROR_OCCURRED,
                agent_id="orchestrator",
                payload={"error_message": str(e)},
            ))
            return AuditReport(
                correlation_id=self._current_correlation_id,
                task_id=self._current_task_id,
                status="failed",
                errors=[str(e)],
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )
        finally:
            if self._container_id:
                try:
                    self._containers.stop(self._container_id)
                except Exception:
                    pass

    # =================================================================
    # Phase Implementations
    # =================================================================

    def _init_phase(self, request: AuditRequest):
        """Phase 1: Clone repo, detect language, create ProjectProfile."""
        from veriaudit.mcp_servers.repo_mcp import RepoMCP

        repo = RepoMCP()
        repo_url = request.repo_url
        repo_path = repo_url

        # Clone if URL
        if repo_url.startswith("http://") or repo_url.startswith("https://"):
            result = repo.clone_repo(url=repo_url, commit=request.commit)
            repo_path = result["repo_path"]

        # Detect language
        lang_result = repo.detect_language(repo_path=repo_path)

        # Extract manifest
        manifest = repo.extract_manifest(repo_path=repo_path)

        language = lang_result.get("primary_language", "unknown")

        # Load adapters
        try:
            lang_adapter = self._adapters.get_language(language)
            build_system = lang_adapter.detect_build_system(repo_path)
            sast_tools = lang_adapter.get_sast_tools(request.mode.value)
            vuln_classes = lang_adapter.get_vulnerability_classes()
        except Exception:
            build_system = lang_result.get("build_system", "unknown")
            sast_tools = ["semgrep"]
            vuln_classes = ["command-injection", "path-traversal", "hardcoded-secret"]

        self._profile = ProjectProfile(
            correlation_id=self._current_correlation_id,
            task_id=self._current_task_id,
            repo_url=request.repo_url,
            commit_sha=request.commit,
            repo_path=repo_path,
            language=language,
            build_system=build_system,
            frameworks=lang_result.get("frameworks", []),
            file_count=manifest.get("file_count", 0),
            total_loc=manifest.get("total_loc", 0),
            has_fuzz_targets=manifest.get("has_fuzz_dir", False),
            sast_tools=sast_tools,
            active_vuln_classes=vuln_classes,
            complexity="medium",
        )

        self._plan = AuditPlan(
            correlation_id=self._current_correlation_id,
            mode=request.mode,
            sast_tools=sast_tools,
            active_vuln_classes=vuln_classes,
            estimated_hours=2 if request.mode == AuditMode.QUICK else 4,
        )

    def _build_phase(self, mode: AuditMode):
        """Phase 2: Create container, configure build environments."""
        if not self._profile:
            return

        # Only for compiled languages with sanitizer support
        try:
            lang_adapter = self._adapters.get_language(self._profile.language)
        except Exception:
            return

        if not lang_adapter.get_sanitizer_config():
            return  # Interpreted language, no build needed

        try:
            build_adapter = self._adapters.get_build(self._profile.build_system)
        except Exception:
            return

        if not build_adapter.can_sanitize():
            return

        from veriaudit.mcp_servers.build_mcp import BuildMCP
        builder = BuildMCP()

        env_result = builder.create_build_env(
            language=self._profile.language,
            build_system=self._profile.build_system,
        )
        self._container_id = env_result.get("container_id", "")

        if mode in (AuditMode.STANDARD, AuditMode.DEEP):
            builder.configure_build(self._container_id, self._profile.repo_path, "asan")
            builder.configure_build(self._container_id, self._profile.repo_path, "fuzzer")

    def _recon_phase(self, mode: AuditMode):
        """Phase 3: Import CPG, find entry points and dangerous calls."""
        pass  # Quick mode skips this

    def _static_scan_phase(self, mode: AuditMode):
        """Phase 4: Run all SAST tools in parallel, normalize results."""
        if not self._profile:
            return

        from veriaudit.mcp_servers.sast_mcp import SASTMCP
        sast = SASTMCP()

        all_raw = []

        # Run tools based on mode
        for tool_name in self._profile.sast_tools:
            if tool_name == "semgrep":
                result = sast.run_semgrep(self._profile.repo_path, self._profile.language)
                all_raw.extend(result.get("findings", []))
            elif tool_name == "codeql":
                result = sast.run_codeql(self._profile.repo_path, self._profile.language)
                all_raw.extend(result.get("findings", []))
            elif tool_name == "cppcheck":
                result = sast.run_cppcheck(self._profile.repo_path)
                all_raw.extend(result.get("findings", []))
            elif tool_name == "clang_tidy":
                result = sast.run_clang_tidy(self._profile.repo_path, "")
                all_raw.extend(result.get("findings", []))
            elif tool_name == "gitleaks":
                result = sast.run_gitleaks(self._profile.repo_path)
                all_raw.extend(result.get("findings", []))

        # Normalize
        norm_result = sast.normalize_findings(all_raw, self._profile.repo_path)
        raw_findings_dicts = norm_result.get("findings", [])

        # Convert to Finding objects with CANDIDATE status
        findings = []
        for fd in raw_findings_dicts:
            # normalize_findings returns flat dicts with file_path, line_start, etc.
            loc = fd.get("location", {})
            file_path = loc.get("file") if loc else fd.get("file_path", "")
            line_start = loc.get("line_start") if loc else fd.get("line_start", 0)
            line_end = loc.get("line_end") if loc else fd.get("line_end")
            code_snippet = fd.get("code_snippet", "")
            severity_val = fd.get("severity", "info")
            cwe_val = fd.get("cwe")

            f = Finding(
                correlation_id=self._current_correlation_id,
                status=FindingStatus.CANDIDATE,
                source_tool=fd.get("source_tool", "unknown"),
                rule_id=fd.get("rule_id", ""),
                location={
                    "file": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "code_snippet": code_snippet,
                },
                message=fd.get("message", ""),
                severity=severity_val,
                cwe=cwe_val,
                confidence=fd.get("confidence", "medium"),
            )
            findings.append(f)

        self._all_findings = findings

    def _cpg_taint_phase(self, mode: AuditMode):
        """Phase 5: Reachability analysis via CPG."""
        pass  # Deep mode feature

    def _exploit_phase(self, mode: AuditMode):
        """Phase 6: Run fuzz on C/C++ projects with sanitizer builds."""
        if not self._profile or not self._container_id:
            return
        if not self._all_findings:
            return

        try:
            lang_adapter = self._adapters.get_language(self._profile.language)
        except Exception:
            return

        if not lang_adapter.get_sanitizer_config():
            return  # Only compiled languages with sanitizer support

        # Quick mode: skip fuzz
        if mode == AuditMode.QUICK:
            return

        from veriaudit.mcp_servers.fuzz_mcp import FuzzMCP
        from veriaudit.mcp_servers.exploit_mcp import ExploitMCP

        fuzz = FuzzMCP()
        exploit = ExploitMCP()

        # Step 1: Discover fuzz targets
        discover_result = fuzz.discover_targets(self._profile.repo_path)
        targets = discover_result.get("targets", [])

        print(f"    Fuzz: found {len(targets)} existing targets")

        # Step 2: If no existing targets, try to generate a harness
        if not targets:
            # Pick a likely function from static findings
            mem_findings = [f for f in self._all_findings
                            if f.source_tool in ("semgrep", "codeql")
                            and f.rule_id and ("buffer" in f.rule_id.lower()
                                or "memory" in f.rule_id.lower()
                                or "mem" in f.rule_id.lower())]
            if not mem_findings:
                print("    Fuzz: no memory-related findings to fuzz")
                return

            # Generate harness for the first memory finding
            target_finding = mem_findings[0]
            func_name = target_finding.location.function or "target_func"
            harness_result = fuzz.generate_harness(
                func_name, target_finding.location.file,
                self._profile.language, self._profile.repo_path,
            )
            harness_path = harness_result.get("harness_path", "")
            if not harness_path:
                return
            targets = [{"name": harness_result.get("build_target_name", "fuzz-harness"),
                        "file": harness_path, "engine": "libfuzzer",
                        "build_target": harness_result.get("build_target_name", "fuzz-harness")}]

        # Step 3: Build and run fuzz
        for target in targets[:3]:  # Max 3 targets
            target_name = target["name"]
            print(f"    Fuzz: building {target_name}...")

            build_result = fuzz.build_target(
                self._container_id, self._profile.repo_path,
                target_name, self._base_build_dir(),
            )

            binary = build_result.get("binary_path", "")
            if not binary:
                continue

            # Generate corpus
            corpus_result = fuzz.generate_corpus(
                self._profile.repo_path, "/tmp/fuzz_corpus", self._profile.language,
            )
            corpus_dir = corpus_result.get("corpus_dir", "/tmp/fuzz_corpus")

            # Run fuzzer
            timeout = 60 if mode == AuditMode.STANDARD else 3600  # 1 min vs 1 hour
            print(f"    Fuzz: running {target_name} for {timeout}s...")
            run_result = fuzz.run_fuzzer(
                self._container_id, binary, corpus_dir,
                timeout_seconds=timeout, artifact_dir="/tmp/fuzz_crashes",
            )

            crashes = run_result.get("crashes", [])
            print(f"    Fuzz: {len(crashes)} crashes found")

            if not crashes:
                # Mark relevant findings as inconclusive (fuzzed but no crash)
                for f in self._all_findings:
                    if f.status == FindingStatus.CANDIDATE:
                        try:
                            self._state_machine.mark_inconclusive(
                                f, "fuzz completed — no crash triggered", self._ledger)
                        except Exception:
                            pass
                continue

            # Step 4: Process crashes — deduplicate, minimize, verify with ASan
            dedup_result = fuzz.deduplicate_crashes(crashes)
            unique_crashes = dedup_result.get("deduplicated", crashes)

            for crash in unique_crashes[:5]:
                crash_input = crash.get("input_file", "")
                if not crash_input:
                    continue

                # Minimize
                min_result = fuzz.minimize_crash(
                    self._container_id, crash_input, binary,
                )
                minimized_input = min_result.get("minimized_input", crash_input)

                # Verify with ASan
                asan_result = exploit.run_under_asan(
                    self._container_id, binary, minimized_input,
                )

                if not asan_result.get("has_asan_report"):
                    continue

                # Check release crash
                release_result = exploit.run_release_crash_test(
                    self._container_id, binary, minimized_input,
                )

                # Get backtrace
                gdb_result = exploit.run_under_gdb(
                    self._container_id, binary, minimized_input,
                )

                # Create evidence events
                self._ledger.append(AuditEvent(
                    correlation_id=self._current_correlation_id,
                    event_type=EventType.EXPLOIT_SANITIZER_REPORT,
                    agent_id="exploit_agent",
                    payload={
                        "error_type": asan_result.get("error_type", ""),
                        "asan_summary": asan_result.get("asan_summary", ""),
                        "crash_input": minimized_input,
                        "top_frames": self._parse_stack_frames(gdb_result.get("backtrace", "")),
                    },
                ))

                # If crash confirmed, promote the matching static findings
                crash_location = self._extract_crash_location(gdb_result.get("backtrace", ""))
                if crash_location:
                    for f in self._all_findings:
                        if (f.status == FindingStatus.CANDIDATE
                                and f.location.file == crash_location.get("file")):
                            try:
                                self._state_machine.mark_reachable(
                                    f, "fuzz crash at this location", self._ledger)
                                self._state_machine.mark_exploitable(
                                    f, f"ASan {asan_result.get('error_type', 'crash')} confirmed",
                                    self._ledger)
                            except Exception:
                                pass

        # Clean up container if done
        if self._container_id and mode == AuditMode.STANDARD:
            # Keep container for Deep mode
            pass

    def _base_build_dir(self) -> str:
        """Get the base build directory for the current project."""
        if self._profile:
            return f"{self._profile.repo_path}/build_fuzz"
        return "/workspace/build_fuzz"

    def _parse_stack_frames(self, backtrace: str) -> list:
        """Parse GDB backtrace into frame list."""
        frames = []
        for line in backtrace.split("\n"):
            line = line.strip()
            if line.startswith("#") and " in " in line:
                parts = line.split()
                func = parts[3] if len(parts) > 3 else ""
                location = parts[-1] if parts else ""
                if " at " in line:
                    location = line.split(" at ")[-1]
                frames.append({"function": func, "file": location})
        return frames

    def _extract_crash_location(self, backtrace: str) -> dict:
        """Extract the project-source crash location from a backtrace."""
        from veriaudit.core.schema import SYSTEM_LIB_PREFIXES
        for line in backtrace.split("\n"):
            line = line.strip()
            if line.startswith("#") and " at " in line:
                location = line.split(" at ")[-1].strip()
                if not any(location.startswith(p) for p in SYSTEM_LIB_PREFIXES):
                    parts = location.split(":")
                    return {"file": parts[0], "line": int(parts[1]) if len(parts) > 1 else 0}
        return {}

    def _contradiction_phase(self):
        """Phase 7: Detect cross-finding contradictions."""
        if not self._all_findings:
            return
        contradictions = self._contradiction.detect(self._all_findings)
        # Log contradictions
        for c in contradictions:
            self._ledger.append(AuditEvent(
                correlation_id=self._current_correlation_id,
                event_type=EventType.ERROR_OCCURRED,
                agent_id="contradiction_detector",
                payload={"finding_a": c.finding_a, "finding_b": c.finding_b,
                         "reason": c.reason, "severity": c.severity},
            ))

    def _validation_phase(self, mode: AuditMode):
        """Phase 8: Independent re-verification with self-correction."""
        pass

    def _judge_phase(self):
        """Phase 9: Deterministic rules + LLM fallback."""
        for f in self._all_findings:
            try:
                judged = self._judge.judge(f, self._events)
                if judged.matched_rule_id:
                    self._ledger.append(AuditEvent(
                        correlation_id=self._current_correlation_id,
                        finding_id=f.finding_id,
                        event_type=EventType.JUDGE_RULING_MADE,
                        agent_id="judge_engine",
                        payload={
                            "finding_id": f.finding_id,
                            "ruling": judged.status.value,
                            "matched_rule_id": judged.matched_rule_id,
                            "reason": judged.ruling_reason,
                        },
                    ))
            except Exception:
                pass

    def _report_phase(self, request: AuditRequest) -> AuditReport:
        """Phase 10: Generate reports."""
        from veriaudit.mcp_servers.report_mcp import ReportMCP

        report_mcp = ReportMCP()
        output_dir = os.path.join(Paths.RESULTS_DIR, self._current_task_id)

        # Serialize findings to dicts
        findings_dicts = []
        for f in self._all_findings:
            fd = {
                "finding_id": f.finding_id,
                "status": f.status.value,
                "source_tool": f.source_tool,
                "rule_id": f.rule_id,
                "file_path": f.location.file,
                "line_start": f.location.line_start,
                "message": f.message,
                "severity": f.severity.value,
                "cwe": f.cwe.value if f.cwe else None,
                "confidence": f.confidence,
                "ruling_reason": f.ruling_reason,
                "llm_analysis": f.llm_analysis,
            }
            findings_dicts.append(fd)

        profile_dict = {
            "repo_url": self._profile.repo_url if self._profile else request.repo_url,
            "commit_sha": self._profile.commit_sha if self._profile else "",
            "language": self._profile.language if self._profile else "unknown",
            "build_system": self._profile.build_system if self._profile else "unknown",
        }

        report_paths = {}
        report_paths["markdown"] = report_mcp.generate_markdown_report(
            findings_dicts, profile_dict, output_dir=output_dir,
        )["report_path"]
        report_paths["html"] = report_mcp.generate_html_report(
            findings_dicts, profile_dict, output_dir=output_dir,
        )["report_path"]
        report_paths["json"] = report_mcp.generate_json_report(
            findings_dicts, profile_dict, output_dir=output_dir,
        )["report_path"]
        report_paths["sarif"] = report_mcp.generate_sarif(
            findings_dicts, profile_dict, output_dir=output_dir,
        )["sarif_path"]

        # Count states
        state_counts = {}
        for f in self._all_findings:
            s = f.status.value
            state_counts[s] = state_counts.get(s, 0) + 1

        return AuditReport(
            correlation_id=self._current_correlation_id,
            task_id=self._current_task_id,
            project_url=request.repo_url,
            commit_sha=(self._profile.commit_sha or "") if self._profile else "",
            mode=request.mode,
            total_raw=len(self._all_findings),
            total_candidates=state_counts.get("candidate", 0),
            total_reachable=state_counts.get("reachable", 0),
            total_exploitable=state_counts.get("exploitable", 0),
            total_confirmed=state_counts.get("confirmed_exploited", 0),
            total_rejected=state_counts.get("rejected", 0),
            total_unreproducible=state_counts.get("unreproducible", 0),
            total_false_positive=state_counts.get("false_positive", 0),
            total_inconclusive=state_counts.get("inconclusive", 0),
            report_paths=report_paths,
        )
