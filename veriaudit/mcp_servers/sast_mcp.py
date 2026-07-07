# VeriAudit - SAST MCP Server
# Provides tools for running static-analysis security testing (SAST) tools:
# semgrep, CodeQL, cppcheck, clang-tidy, gitleaks, plus finding normalization.
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from veriaudit.core.schema import (
    CWE,
    CodeLocation,
    Finding,
    FindingStatus,
    MCPToolCall,
    MCPToolResult,
    RawFinding,
    Severity,
    gen_id,
)
from veriaudit.mcp_servers.base_mcp import BaseMCP

# ---- Paths that should be excluded during normalization ----
DEFAULT_EXCLUDE_PATHS = {
    "test", "tests", "spec", "specs", "__tests__", "t", "testing",
    "vendor", "node_modules",
    "third_party", "thirdparty", "3rdparty",
    "example", "examples", "sample", "samples",
    "doc", "docs", "documentation",
    "build", "dist", "out", "target",
    ".git",
}

# ---- map semgrep severity -> canonical ----
SEVERITY_MAP = {
    "ERROR": "error",
    "WARNING": "warning",
    "INFO": "note",
    "error": "error",
    "warning": "warning",
    "note": "note",
    "info": "note",
}

# ---- CWE extraction pattern from rule messages ----
CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


class SASTMCP(BaseMCP):
    """MCP server for SAST tool execution and finding normalization."""

    # ------------------------------------------------------------------
    # server_name
    # ------------------------------------------------------------------

    @property
    def server_name(self) -> str:
        return "sast_mcp"

    # ==================================================================
    # Tool methods
    # ==================================================================

    # ── run_semgrep ───────────────────────────────────────────────────

    def run_semgrep(self, repo_path: str, language: str,
                    rules_path: str = None,
                    extra_args: List[str] = None) -> dict:
        """
        Run semgrep against the repository and parse JSON output
        into RawFinding dicts.
        """
        start = time.time()
        output_path = "/tmp/semgrep_output.json"

        cmd = ["semgrep", "--config=auto", "--json", "-o", output_path]
        if rules_path:
            cmd.extend(["--config", rules_path])
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(repo_path)

        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=900)

        findings: List[dict] = []
        if result.returncode not in (0, 1):
            # semgrep returns 1 when findings exist (that's "success")
            raise RuntimeError(
                f"semgrep failed (exit {result.returncode}): {result.stderr[:500]}"
            )

        # Parse the JSON output
        if os.path.exists(output_path):
            try:
                with open(output_path, "r", encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                data = {"results": []}
        else:
            # Try parsing from stdout/stderr as fallback
            try:
                data = json.loads(result.stdout or result.stderr or "{}")
            except json.JSONDecodeError:
                data = {"results": []}

        for entry in data.get("results", []):
            rf = self._semgrep_entry_to_raw(entry, repo_path)
            findings.append(rf.model_dump() if hasattr(rf, "model_dump") else rf)

        elapsed = time.time() - start
        return {
            "findings": findings,
            "count": len(findings),
            "duration_seconds": round(elapsed, 3),
            "raw_output_path": output_path,
        }

    # ── run_codeql ────────────────────────────────────────────────────

    def run_codeql(self, repo_path: str, language: str,
                   build_dir: str = None,
                   compile_commands_path: str = None) -> dict:
        """
        Create a CodeQL database, analyze it, and parse SARIF output
        into RawFinding dicts.
        """
        start = time.time()
        db_path = "/tmp/codeql_db"
        sarif_path = "/tmp/codeql_results.sarif"

        # ---- Step 1: Create database ----
        create_cmd = [
            "codeql", "database", "create", db_path,
            "--language", language,
            "--source-root", repo_path,
        ]

        if compile_commands_path and os.path.exists(compile_commands_path):
            create_cmd.extend(["--command", f"cat {compile_commands_path}"])
        elif build_dir and build_dir != repo_path:
            # Use the build directory's command
            create_cmd.extend(["--command", f"cmake --build {build_dir}"])
        else:
            # No build — use build-mode=none for interpreted / script langs
            create_cmd.append("--build-mode=none")

        # Add parallelism
        import os as _os_module
        jobs = _os_module.cpu_count() or 4
        create_cmd.extend(["-j", str(jobs)])

        create_result = subprocess.run(
            create_cmd, capture_output=True, text=True, timeout=1800
        )
        if create_result.returncode != 0:
            # If build-mode=none fails, retry with explicit --build-mode=none
            if "--build-mode=none" not in create_cmd:
                create_cmd.append("--build-mode=none")
                create_result = subprocess.run(
                    create_cmd, capture_output=True, text=True, timeout=1800
                )
            if create_result.returncode != 0:
                raise RuntimeError(
                    f"codeql database create failed: {create_result.stderr[:500]}"
                )

        # ---- Step 2: Analyze ----
        analyze_cmd = [
            "codeql", "database", "analyze", db_path,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "-j", str(jobs),
        ]

        analyze_result = subprocess.run(
            analyze_cmd, capture_output=True, text=True, timeout=1800
        )
        if analyze_result.returncode != 0:
            raise RuntimeError(
                f"codeql database analyze failed: {analyze_result.stderr[:500]}"
            )

        # ---- Step 3: Parse SARIF ----
        findings: List[dict] = []
        if os.path.exists(sarif_path):
            try:
                with open(sarif_path, "r", encoding="utf-8") as fh:
                    sarif_data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                sarif_data = {}

            findings = self._parse_sarif(sarif_data, repo_path)

        elapsed = time.time() - start
        return {
            "findings": findings,
            "count": len(findings),
            "duration_seconds": round(elapsed, 3),
            "sarif_path": sarif_path,
        }

    # ── run_cppcheck ──────────────────────────────────────────────────

    def run_cppcheck(self, repo_path: str,
                     compile_commands_path: str = None) -> dict:
        """
        Run cppcheck against the repository and parse XML output
        into RawFinding dicts.
        """
        start = time.time()
        xml_path = "/tmp/cppcheck_output.xml"

        cmd = [
            "cppcheck",
            "--enable=all",
            "--xml",
            "--xml-version=2",
        ]

        if compile_commands_path and os.path.exists(compile_commands_path):
            cmd.extend(["--project", compile_commands_path])

        cmd.append(repo_path)

        # cppcheck writes XML to stderr by default when using --xml
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1200)

        # cppcheck exit code 0 = no errors found, 1 = errors found (both OK)
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"cppcheck failed (exit {result.returncode}): {result.stderr[:500]}"
            )

        # Parse XML from stderr
        findings = self._parse_cppcheck_xml(result.stderr, repo_path)

        # Save raw XML for reference
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        try:
            with open(xml_path, "w", encoding="utf-8") as fh:
                fh.write(result.stderr)
        except OSError:
            pass

        elapsed = time.time() - start
        return {
            "findings": findings,
            "count": len(findings),
            "duration_seconds": round(elapsed, 3),
        }

    # ── run_bandit ────────────────────────────────────────────────────

    def run_bandit(self, repo_path: str) -> dict:
        """Run bandit (Python security linter) and parse JSON output."""
        import json as _json
        start = time.time()

        cmd = ["bandit", "-r", "-f", "json", "-q", repo_path]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=300, encoding='utf-8', errors='replace')

        findings: List[dict] = []
        if result.stdout:
            try:
                data = _json.loads(result.stdout)
            except _json.JSONDecodeError:
                data = {"results": []}

            for entry in data.get("results", []):
                findings.append({
                    "source_tool": "bandit",
                    "rule_id": f"bandit.{entry.get('test_id', 'unknown')}",
                    "file_path": entry.get("filename", ""),
                    "line_start": entry.get("line_number", 0),
                    "line_end": entry.get("line_number", 0),
                    "code_snippet": entry.get("code", "")[:200],
                    "message": entry.get("issue_text", entry.get("test_name", "")),
                    "severity": entry.get("issue_severity", "medium").lower(),
                    "cwe": self._bandit_cwe(entry.get("test_id", "")),
                    "confidence": entry.get("issue_confidence", "medium").lower(),
                })

        elapsed = time.time() - start
        return {"findings": findings, "count": len(findings), "duration_seconds": round(elapsed, 3)}

    def _bandit_cwe(self, test_id: str) -> str:
        cwe_map = {"B101":"CWE-703","B102":"CWE-78","B301":"CWE-502",
                    "B506":"CWE-502","B601":"CWE-78","B603":"CWE-78",
                    "B608":"CWE-89","B701":"CWE-79"}
        return cwe_map.get(test_id, "")

    # ── run_clang_tidy ────────────────────────────────────────────────

    def run_clang_tidy(self, repo_path: str,
                       compile_commands_path: str,
                       checks: str = None, jobs: int = None) -> dict:
        """
        Run clang-tidy using a compile_commands.json and parse output
        into RawFinding dicts.
        """
        start = time.time()

        if not os.path.exists(compile_commands_path):
            raise FileNotFoundError(
                f"compile_commands.json not found: {compile_commands_path}"
            )

        if jobs is None:
            import os as _os_module
            jobs = _os_module.cpu_count() or 4

        # Build the file list from compile_commands.json
        try:
            with open(compile_commands_path, "r") as fh:
                cc_data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(
                f"Failed to parse compile_commands.json: {exc}"
            )

        source_files = []
        for entry in cc_data:
            fpath = entry.get("file", "")
            if fpath and os.path.isfile(fpath):
                source_files.append(fpath)

        if not source_files:
            raise RuntimeError("No source files found in compile_commands.json")

        # Build clang-tidy command
        cmd = ["clang-tidy", "-p", os.path.dirname(compile_commands_path)]

        if checks:
            cmd.extend(["--checks", checks])
        else:
            # Default security-focused checks
            cmd.extend([
                "--checks",
                "-*,bugprone-*,clang-analyzer-*,cert-*,"
                "cppcoreguidelines-pro-type-*,misc-*,performance-*,"
                "readability-*,-readability-identifier-length,"
                "hicpp-*,android-*",
            ])

        cmd.extend(["-j", str(jobs)])
        cmd.extend(source_files[:200])  # Cap to avoid overload

        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800)

        # clang-tidy outputs one warning per line (or multiple lines per warning)
        findings = self._parse_clang_tidy_output(
            result.stdout + result.stderr, repo_path
        )

        elapsed = time.time() - start
        return {
            "findings": findings,
            "count": len(findings),
            "duration_seconds": round(elapsed, 3),
        }

    # ── run_gitleaks ──────────────────────────────────────────────────

    def run_gitleaks(self, repo_path: str) -> dict:
        """
        Run gitleaks to detect hardcoded secrets and parse JSON output
        into RawFinding dicts.
        """
        start = time.time()
        output_path = "/tmp/gitleaks_output.json"

        cmd = [
            "gitleaks", "detect",
            "--source", repo_path,
            "--no-git",
            "-f", "json",
            "-r", output_path,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300)

        # gitleaks exit code 1 = leaks found (success)
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"gitleaks failed (exit {result.returncode}): {result.stderr[:500]}"
            )

        findings: List[dict] = []
        try:
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            else:
                data = json.loads(result.stdout or "[]")
        except (json.JSONDecodeError, OSError):
            data = []

        for entry in data if isinstance(data, list) else data.get("Leaks", []):
            rf = RawFinding(
                source_tool="gitleaks",
                rule_id=entry.get("RuleID", entry.get("rule_id", "unknown-secret")),
                file_path=entry.get("File", entry.get("file", "")),
                line_start=entry.get("StartLine", entry.get("line", 0)) or 0,
                line_end=entry.get("EndLine", None),
                code_snippet=entry.get("Match", entry.get("Secret", ""))[:200],
                message=(
                    f"Hardcoded secret detected: {entry.get('Description', entry.get('rule_id', ''))}"
                ),
                severity="error",
                cwe="CWE-798",
                confidence="high",
            )
            findings.append(rf.model_dump())

        elapsed = time.time() - start
        return {
            "findings": findings,
            "count": len(findings),
            "duration_seconds": round(elapsed, 3),
        }

    # ── normalize_findings ────────────────────────────────────────────

    def normalize_findings(self, raw_findings: List[dict],
                           repo_path: str) -> dict:
        """
        Deduplicate, filter, sort, and convert RawFinding dicts into
        Finding dicts.
        """
        # ---- Convert to RawFinding objects ----
        parsed: List[RawFinding] = []
        for item in raw_findings:
            try:
                rf = RawFinding(**item)
                parsed.append(rf)
            except Exception:
                # Skip malformed entries
                continue

        total_raw = len(parsed)

        # ---- Step 1: Deduplicate ----
        # Key: (file, nearby_line, tool, rule_id); keep highest confidence
        dedup_groups: Dict[str, List[RawFinding]] = defaultdict(list)

        for rf in parsed:
            # Normalize line to a bucket (line // 3) for approximate matching
            line_bucket = rf.line_start // 3 if rf.line_start else 0
            key = f"{rf.file_path}:{line_bucket}:{rf.source_tool}:{rf.rule_id}"
            dedup_groups[key].append(rf)

        confidence_rank = {"high": 3, "medium": 2, "low": 1}
        deduped: List[RawFinding] = []
        for group in dedup_groups.values():
            # Keep the entry with the highest confidence
            best = max(group, key=lambda x: confidence_rank.get(x.confidence, 0))
            deduped.append(best)

        after_dedup = len(deduped)

        # ---- Step 2: Filter out noise paths ----
        filtered: List[RawFinding] = []
        repo_path_normalized = os.path.abspath(repo_path).lower().replace("\\", "/").rstrip("/")
        for rf in deduped:
            path_lower = rf.file_path.lower().replace("\\", "/")
            # Compute path relative to repo root
            rel_path = path_lower
            if path_lower.startswith(repo_path_normalized + "/"):
                rel_path = path_lower[len(repo_path_normalized) + 1:]
            # Get directory components of the relative path
            components = set(rel_path.split("/")[:-1])  # dirs only, not filename
            if components & DEFAULT_EXCLUDE_PATHS:
                continue
            filtered.append(rf)

        after_filter = len(filtered)

        # ---- Step 3: Sort by severity (error > warning > note) ----
        severity_rank = {"error": 0, "warning": 1, "note": 2}
        filtered.sort(key=lambda x: severity_rank.get(x.severity, 99))

        # ---- Step 4: Convert to Finding dicts ----
        findings: List[dict] = []
        for rf in filtered:
            finding = Finding(
                finding_id=gen_id("F"),
                source_tool=rf.source_tool,
                rule_id=rf.rule_id,
                location=CodeLocation(
                    file=rf.file_path,
                    line_start=rf.line_start,
                    line_end=rf.line_end,
                    code_snippet=rf.code_snippet,
                ),
                message=rf.message,
                severity=self._map_severity(rf.severity),
                cwe=self._match_cwe(rf.cwe),
                confidence=rf.confidence,
                status=FindingStatus.RAW,
            )
            findings.append(finding.model_dump())

        return {
            "findings": findings,
            "total_raw": total_raw,
            "after_dedup": after_dedup,
            "after_filter": after_filter,
        }

    # ==================================================================
    # Tool schemas (OpenAI-compatible)
    # ==================================================================

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": f"{self.server_name}.run_semgrep",
                "description": "Run semgrep static analysis against a repository and return findings.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                        "language": {
                            "type": "string",
                            "description": "Target language (e.g. 'python', 'go', 'java', 'c').",
                        },
                        "rules_path": {
                            "type": "string",
                            "description": "Optional path to custom semgrep rules.",
                        },
                        "extra_args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional extra CLI arguments for semgrep.",
                        },
                    },
                    "required": ["repo_path", "language"],
                },
            },
            {
                "name": f"{self.server_name}.run_codeql",
                "description": "Create a CodeQL database, analyze it, and return SARIF-parsed findings.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                        "language": {
                            "type": "string",
                            "description": "Target language (e.g. 'cpp', 'java', 'python', 'go').",
                        },
                        "build_dir": {
                            "type": "string",
                            "description": "Optional build directory (for compiled languages).",
                        },
                        "compile_commands_path": {
                            "type": "string",
                            "description": "Optional path to compile_commands.json.",
                        },
                    },
                    "required": ["repo_path", "language"],
                },
            },
            {
                "name": f"{self.server_name}.run_cppcheck",
                "description": "Run cppcheck static analysis on C/C++ code and return findings.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                        "compile_commands_path": {
                            "type": "string",
                            "description": "Optional path to compile_commands.json.",
                        },
                    },
                    "required": ["repo_path"],
                },
            },
            {
                "name": f"{self.server_name}.run_clang_tidy",
                "description": "Run clang-tidy using compile_commands.json and return findings.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                        "compile_commands_path": {
                            "type": "string",
                            "description": "Path to compile_commands.json (required).",
                        },
                        "checks": {
                            "type": "string",
                            "description": "Optional clang-tidy checks string.",
                        },
                        "jobs": {
                            "type": "integer",
                            "description": "Number of parallel jobs (defaults to CPU count).",
                        },
                    },
                    "required": ["repo_path", "compile_commands_path"],
                },
            },
            {
                "name": f"{self.server_name}.run_gitleaks",
                "description": "Run gitleaks to detect hardcoded secrets in the repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                    },
                    "required": ["repo_path"],
                },
            },
            {
                "name": f"{self.server_name}.normalize_findings",
                "description": "Deduplicate, filter, sort, and convert raw SAST findings into standardized Finding objects.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "raw_findings": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "List of RawFinding dicts from SAST tools.",
                        },
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository (used for path filtering).",
                        },
                    },
                    "required": ["raw_findings", "repo_path"],
                },
            },
        ]

    # ==================================================================
    # Internal: SAST output parsers
    # ==================================================================

    def _semgrep_entry_to_raw(self, entry: dict,
                              repo_path: str) -> RawFinding:
        """Convert a single semgrep result entry to a RawFinding."""
        extra = entry.get("extra", {})
        severity = SEVERITY_MAP.get(
            extra.get("severity", "warning"), "warning"
        )

        # Extract CWE from metadata if present
        cwe = None
        metadata = extra.get("metadata", {})
        if isinstance(metadata, dict):
            for key in ("cwe", "CWE"):
                val = metadata.get(key)
                if val:
                    cwe = f"CWE-{val}" if not str(val).startswith("CWE-") else str(val)
                    break
        if not cwe:
            msg = extra.get("message", "")
            match = CWE_PATTERN.search(msg)
            if match:
                cwe = f"CWE-{match.group(1)}"

        return RawFinding(
            source_tool="semgrep",
            rule_id=entry.get("check_id", "unknown"),
            file_path=entry.get("path", ""),
            line_start=entry.get("start", {}).get("line", 0),
            line_end=entry.get("end", {}).get("line", None),
            code_snippet=extra.get("lines", "")[:500],
            message=extra.get("message", "")[:1000],
            severity=severity,
            cwe=cwe,
            confidence="medium",
        )

    def _parse_sarif(self, sarif_data: dict,
                     repo_path: str) -> List[dict]:
        """Parse a SARIF result object into RawFinding dicts."""
        findings: List[dict] = []
        runs = sarif_data.get("runs", [])

        for run in runs:
            tool_name = "codeql"
            tool_info = run.get("tool", {})
            driver = tool_info.get("driver", {})
            if isinstance(driver, dict):
                tool_name = driver.get("name", "codeql")

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                message = result.get("message", {})
                msg_text = message.get("text", "") if isinstance(message, dict) else str(message)

                severity = "warning"
                level = result.get("level", "warning")
                if level in ("error", "warning", "note"):
                    severity = level

                # Get the first location
                locations = result.get("locations", [])
                file_path = ""
                line_start = 0
                line_end = None
                code_snippet = None

                if locations:
                    loc = locations[0]
                    phys = loc.get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    file_path = artifact.get("uri", "")
                    region = phys.get("region", {})
                    line_start = region.get("startLine", 0)
                    line_end = region.get("endLine", None)
                    snippet = region.get("snippet", {})
                    if isinstance(snippet, dict):
                        code_snippet = snippet.get("text", "")

                # Extract CWE from taxa
                cwe = None
                for taxon in result.get("taxa", []):
                    taxon_id = taxon.get("id", "")
                    cwe_match = CWE_PATTERN.search(taxon_id)
                    if cwe_match:
                        cwe = f"CWE-{cwe_match.group(1)}"
                        break

                # Also check rule properties
                if not cwe:
                    rule_info = result.get("properties", {})
                    for tag in rule_info.get("tags", []):
                        cwe_match = CWE_PATTERN.search(str(tag))
                        if cwe_match:
                            cwe = f"CWE-{cwe_match.group(1)}"
                            break

                rf = RawFinding(
                    source_tool=tool_name,
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code_snippet,
                    message=msg_text[:1000],
                    severity=severity,
                    cwe=cwe,
                    confidence="medium",
                )
                findings.append(rf.model_dump())

        return findings

    def _parse_cppcheck_xml(self, xml_text: str,
                            repo_path: str) -> List[dict]:
        """Parse cppcheck XML (version 2) output into RawFinding dicts."""
        findings: List[dict] = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return findings

        errors_tag = root if root.tag == "errors" else root.find("errors")
        if errors_tag is None:
            return findings

        for error_elem in errors_tag.findall("error"):
            rule_id = error_elem.get("id", "unknown")
            severity = error_elem.get("severity", "warning")
            msg = error_elem.get("msg", "")

            # Map cppcheck severity to canonical
            cppcheck_sev_map = {
                "error": "error",
                "warning": "warning",
                "style": "note",
                "performance": "note",
                "portability": "note",
                "information": "note",
            }
            canonical_sev = cppcheck_sev_map.get(severity, "warning")

            for loc_elem in error_elem.findall("location"):
                file_path = loc_elem.get("file", "")
                line_start = int(loc_elem.get("line", 0))

                # Resolve relative paths against repo_path
                if not os.path.isabs(file_path):
                    file_path = os.path.join(repo_path, file_path)

                rf = RawFinding(
                    source_tool="cppcheck",
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    code_snippet=None,
                    message=msg[:1000],
                    severity=canonical_sev,
                    cwe=None,
                    confidence="medium",
                )
                findings.append(rf.model_dump())

        return findings

    def _parse_clang_tidy_output(self, text: str,
                                 repo_path: str) -> List[dict]:
        """Parse clang-tidy output lines into RawFinding dicts."""
        findings: List[dict] = []

        # clang-tidy output format:
        # /path/to/file:line:col: warning: message [check-name]
        # or
        # /path/to/file:line:col: error: message [check-name]
        pattern = re.compile(
            r"^(.+?):(\d+):(\d+):\s*(warning|error|note):\s*(.+?)\s*\[(.+?)\]\s*$",
            re.MULTILINE,
        )

        for match in pattern.finditer(text):
            file_path = match.group(1)
            line_start = int(match.group(2))
            col = match.group(3)
            severity = match.group(4)
            message = match.group(5).strip()
            rule_id = match.group(6).strip()

            if not os.path.isabs(file_path):
                file_path = os.path.join(repo_path, file_path)

            rf = RawFinding(
                source_tool="clang_tidy",
                rule_id=rule_id,
                file_path=file_path,
                line_start=line_start,
                line_end=None,
                code_snippet=None,
                message=message[:1000],
                severity=severity,
                cwe=None,
                confidence="medium",
            )
            findings.append(rf.model_dump())

        return findings

    # ==================================================================
    # Internal: helpers
    # ==================================================================

    @staticmethod
    def _map_severity(sev: str) -> Severity:
        """Map a string severity to the Severity enum."""
        mapping = {
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "note": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(sev, Severity.INFO)

    @staticmethod
    def _match_cwe(cwe_str: Optional[str]) -> Optional[CWE]:
        """Try to match a CWE string to the CWE enum."""
        if not cwe_str:
            return None
        try:
            return CWE(cwe_str)
        except ValueError:
            return None
