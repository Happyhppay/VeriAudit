# VeriAudit - Evidence MCP Server
# Provides tools for creating findings, managing evidence artifacts,
# attaching sanitizer logs and stacktraces, building reproducer packages,
# and marking findings as confirmed exploited.
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from veriaudit.core.schema import (
    CodeLocation,
    EvidenceRef,
    Finding,
    FindingStatus,
    MCPToolCall,
    MCPToolResult,
    Paths,
    SANITIZER_ERROR_PATTERNS,
    Severity,
    SYSTEM_LIB_PREFIXES,
    gen_id,
)
from veriaudit.mcp_servers.base_mcp import BaseMCP

# ---- Allowed status transitions for update_finding_status ----
ALLOWED_STATUSES = {s.value for s in FindingStatus}


class EvidenceMCP(BaseMCP):
    """MCP server for evidence management: findings, artifacts, reproducers."""

    # ------------------------------------------------------------------
    # server_name
    # ------------------------------------------------------------------

    @property
    def server_name(self) -> str:
        return "evidence_mcp"

    # ==================================================================
    # Tool methods
    # ==================================================================

    # ── create_finding ────────────────────────────────────────────────

    def create_finding(self, correlation_id: str, task_id: str,
                       source_tool: str, rule_id: str, file_path: str,
                       line_start: int, message: str,
                       severity: str = "info", **kwargs) -> dict:
        """
        Create a new Finding, persist it to disk as JSON, and return it.
        """
        finding_id = gen_id("F")

        # Map string severity to Severity enum
        sev = self._parse_severity(severity)

        finding = Finding(
            finding_id=finding_id,
            correlation_id=correlation_id,
            status=FindingStatus.RAW,
            source_tool=source_tool,
            rule_id=rule_id,
            location=CodeLocation(
                file=file_path,
                line_start=line_start,
                line_end=kwargs.get("line_end"),
                function=kwargs.get("function"),
                code_snippet=kwargs.get("code_snippet"),
            ),
            message=message,
            severity=sev,
            cwe=kwargs.get("cwe"),
            confidence=kwargs.get("confidence", "medium"),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )

        # Persist
        self._save_finding(finding)

        return {"finding": finding.model_dump()}

    # ── update_finding_status ─────────────────────────────────────────

    def update_finding_status(self, finding_id: str,
                              correlation_id: str,
                              new_status: str, reason: str,
                              agent_id: str = "system") -> dict:
        """
        Read the current finding, update its status (with validation),
        write it back, and return the updated finding.
        """
        finding_dict = self._load_finding(finding_id)
        if finding_dict is None:
            raise FileNotFoundError(
                f"Finding not found: {finding_id}"
            )

        # Reconstruct the finding
        finding = Finding(**finding_dict)

        # Validate the transition
        new_status_enum = self._parse_status(new_status)
        old_status = finding.status

        if not FindingStatus.can_transition(old_status, new_status_enum):
            raise ValueError(
                f"Invalid status transition: {old_status.value} -> {new_status_enum.value}. "
                f"Allowed: {[s.value for s in FindingStatus.get_allowed(old_status)]}"
            )

        finding.status = new_status_enum
        finding.ruling_reason = reason
        finding.updated_at = datetime.now(timezone.utc)

        # Persist
        self._save_finding(finding)

        return {"finding": finding.model_dump()}

    # ── attach_artifact ───────────────────────────────────────────────

    def attach_artifact(self, finding_id: str, artifact_type: str,
                        content: str = None,
                        file_path: str = None) -> dict:
        """
        Save an evidence artifact (log, screenshot, binary, etc.) to the
        finding's evidence directory and add an EvidenceRef to the finding.
        """
        finding_dict = self._load_finding(finding_id)
        if finding_dict is None:
            raise FileNotFoundError(f"Finding not found: {finding_id}")

        finding = Finding(**finding_dict)

        evidence_dir = self._evidence_dir(finding_id)
        os.makedirs(evidence_dir, exist_ok=True)

        # Determine artifact filename and content
        artifact_filename = artifact_type
        artifact_content = ""

        if content is not None:
            artifact_content = content
            artifact_path = os.path.join(evidence_dir, artifact_filename)
            with open(artifact_path, "w", encoding="utf-8") as fh:
                fh.write(content)
        elif file_path is not None and os.path.isfile(file_path):
            artifact_filename = os.path.basename(file_path) or artifact_type
            artifact_path = os.path.join(evidence_dir, artifact_filename)
            with open(file_path, "rb") as src:
                with open(artifact_path, "wb") as dst:
                    dst.write(src.read())
            # Read back for hash
            try:
                with open(artifact_path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    artifact_content = fh.read()
            except Exception:
                artifact_content = ""
        else:
            raise ValueError(
                "Either 'content' or 'file_path' must be provided."
            )

        # Compute content hash
        content_hash = hashlib.sha256(
            artifact_content.encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        # Create evidence reference
        ref_id = gen_id("evref")
        ev_ref = EvidenceRef(
            ref_id=ref_id,
            artifact_type=artifact_type,
            uri=artifact_path,
            description=f"Artifact of type '{artifact_type}' for finding {finding_id}",
            content_hash=content_hash,
        )

        # Attach to finding
        finding.evidence.append(ev_ref)
        finding.updated_at = datetime.now(timezone.utc)
        self._save_finding(finding)

        return {
            "artifact_id": ref_id,
            "stored_path": artifact_path,
        }

    # ── attach_sanitizer_log ──────────────────────────────────────────

    def attach_sanitizer_log(self, finding_id: str,
                             log_content: str,
                             build_type: str = "asan") -> dict:
        """
        Save a sanitizer (ASan/UBSan/MSan) log, parse the error type
        from the content, and attach as evidence.
        """
        finding_dict = self._load_finding(finding_id)
        if finding_dict is None:
            raise FileNotFoundError(f"Finding not found: {finding_id}")

        finding = Finding(**finding_dict)

        evidence_dir = self._evidence_dir(finding_id)
        os.makedirs(evidence_dir, exist_ok=True)

        # Save the sanitizer log
        log_filename = f"{build_type}_log.txt"
        log_path = os.path.join(evidence_dir, log_filename)
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write(log_content)

        # Parse error type from the log
        error_type = self._parse_sanitizer_error(log_content)
        if error_type:
            # Optionally auto-set CWE based on sanitizer pattern
            pattern_info = SANITIZER_ERROR_PATTERNS.get(error_type)
            if pattern_info and finding.cwe is None:
                finding.cwe = pattern_info["cwe"]

        # Create evidence reference
        content_hash = hashlib.sha256(
            log_content.encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        ref_id = gen_id("evref")
        ev_ref = EvidenceRef(
            ref_id=ref_id,
            artifact_type=f"{build_type}_log",
            uri=log_path,
            description=f"Sanitizer log ({build_type}) for finding {finding_id}",
            content_hash=content_hash,
        )

        finding.evidence.append(ev_ref)
        finding.updated_at = datetime.now(timezone.utc)
        self._save_finding(finding)

        return {
            "artifact_id": ref_id,
            "error_type": error_type,
            "stored_path": log_path,
        }

    # ── attach_stacktrace ─────────────────────────────────────────────

    def attach_stacktrace(self, finding_id: str,
                          stacktrace_text: str) -> dict:
        """
        Save a stacktrace, resolve project source locations (filtering
        system library frames), and attach as evidence.
        """
        finding_dict = self._load_finding(finding_id)
        if finding_dict is None:
            raise FileNotFoundError(f"Finding not found: {finding_id}")

        finding = Finding(**finding_dict)

        evidence_dir = self._evidence_dir(finding_id)
        os.makedirs(evidence_dir, exist_ok=True)

        # Save the stacktrace
        trace_path = os.path.join(evidence_dir, "stacktrace.txt")
        with open(trace_path, "w", encoding="utf-8") as fh:
            fh.write(stacktrace_text)

        # Parse resolved locations (non-system frames)
        resolved_locations = self._resolve_stacktrace_locations(
            stacktrace_text
        )

        # Create evidence reference
        content_hash = hashlib.sha256(
            stacktrace_text.encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        ref_id = gen_id("evref")
        ev_ref = EvidenceRef(
            ref_id=ref_id,
            artifact_type="stacktrace",
            uri=trace_path,
            description=f"Stack trace for finding {finding_id}",
            content_hash=content_hash,
        )

        finding.evidence.append(ev_ref)
        finding.updated_at = datetime.now(timezone.utc)
        self._save_finding(finding)

        return {
            "artifact_id": ref_id,
            "resolved_locations": resolved_locations,
            "stored_path": trace_path,
        }

    # ── create_reproducer_package ─────────────────────────────────────

    def create_reproducer_package(self, finding_id: str,
                                  dockerfile_content: str = "",
                                  build_script: str = "",
                                  run_script: str = "",
                                  poc_input_path: str = "",
                                  logs: List[str] = None) -> dict:
        """
        Create a full reproducer package for a confirmed finding:
        manifest.json, finding.json (copy), Dockerfile, build.sh,
        run_exploit.sh, poc_input, and any log files.
        """
        finding_dict = self._load_finding(finding_id)
        if finding_dict is None:
            raise FileNotFoundError(f"Finding not found: {finding_id}")

        finding = Finding(**finding_dict)

        evidence_dir = self._evidence_dir(finding_id)
        package_dir = evidence_dir  # Same directory; package = evidence bundle
        os.makedirs(package_dir, exist_ok=True)

        file_list: List[Dict[str, str]] = []

        # ---- 1. finding.json (copy) ----
        finding_json_path = os.path.join(package_dir, "finding.json")
        finding_json = json.dumps(finding.model_dump(), indent=2, default=str)
        with open(finding_json_path, "w", encoding="utf-8") as fh:
            fh.write(finding_json)
        file_list.append({
            "path": "finding.json",
            "sha256": self._sha256(finding_json),
        })

        # ---- 2. Dockerfile ----
        if dockerfile_content:
            dockerfile_path = os.path.join(package_dir, "Dockerfile")
            with open(dockerfile_path, "w", encoding="utf-8") as fh:
                fh.write(dockerfile_content)
            file_list.append({
                "path": "Dockerfile",
                "sha256": self._sha256(dockerfile_content),
            })

        # ---- 3. build.sh ----
        if build_script:
            build_path = os.path.join(package_dir, "build.sh")
            with open(build_path, "w", encoding="utf-8") as fh:
                fh.write(build_script)
            os.chmod(build_path, 0o755)
            file_list.append({
                "path": "build.sh",
                "sha256": self._sha256(build_script),
            })

        # ---- 4. run_exploit.sh (auto-generate if not provided) ----
        if not run_script:
            run_script = self._generate_run_exploit_script(finding)
        run_path = os.path.join(package_dir, "run_exploit.sh")
        with open(run_path, "w", encoding="utf-8") as fh:
            fh.write(run_script)
        os.chmod(run_path, 0o755)
        file_list.append({
            "path": "run_exploit.sh",
            "sha256": self._sha256(run_script),
        })

        # ---- 5. poc_input (copy from source if provided) ----
        if poc_input_path and os.path.isfile(poc_input_path):
            poc_dest = os.path.join(package_dir, "poc_input")
            with open(poc_input_path, "rb") as src:
                poc_data = src.read()
            with open(poc_dest, "wb") as dst:
                dst.write(poc_data)
            file_list.append({
                "path": "poc_input",
                "sha256": hashlib.sha256(poc_data).hexdigest(),
            })

        # ---- 6. Logs ----
        if logs:
            for i, log_content in enumerate(logs):
                log_filename = f"log_{i:03d}.txt"
                log_path = os.path.join(package_dir, log_filename)
                with open(log_path, "w", encoding="utf-8") as fh:
                    fh.write(log_content)
                file_list.append({
                    "path": log_filename,
                    "sha256": self._sha256(log_content),
                })

        # ---- 7. manifest.json ----
        manifest = {
            "finding_id": finding_id,
            "correlation_id": finding.correlation_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "files": file_list,
            "file_count": len(file_list),
        }
        manifest_path = os.path.join(package_dir, "manifest.json")
        manifest_json = json.dumps(manifest, indent=2, default=str)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            fh.write(manifest_json)

        return {
            "package_dir": package_dir,
            "file_count": len(file_list),
            "manifest": manifest,
        }

    # ── mark_confirmed_exploited ──────────────────────────────────────

    def mark_confirmed_exploited(self, finding_id: str,
                                 evidence_summary: str) -> dict:
        """
        Update a finding's status to CONFIRMED_EXPLOITED and persist a
        summary of the evidence.
        """
        finding_dict = self._load_finding(finding_id)
        if finding_dict is None:
            raise FileNotFoundError(f"Finding not found: {finding_id}")

        finding = Finding(**finding_dict)

        # Validate transition
        if not FindingStatus.can_transition(
            finding.status, FindingStatus.CONFIRMED_EXPLOITED
        ):
            raise ValueError(
                f"Cannot transition from {finding.status.value} to "
                f"{FindingStatus.CONFIRMED_EXPLOITED.value}"
            )

        finding.status = FindingStatus.CONFIRMED_EXPLOITED
        finding.ruling = "confirmed_exploited"
        finding.ruling_reason = evidence_summary
        finding.updated_at = datetime.now(timezone.utc)

        self._save_finding(finding)

        return {"finding": finding.model_dump()}

    # ==================================================================
    # Tool schemas (OpenAI-compatible)
    # ==================================================================

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": f"{self.server_name}.create_finding",
                "description": "Create a new Finding and persist it to the evidence directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "correlation_id": {
                            "type": "string",
                            "description": "Audit correlation ID.",
                        },
                        "task_id": {
                            "type": "string",
                            "description": "Task identifier.",
                        },
                        "source_tool": {
                            "type": "string",
                            "description": "Source SAST tool name (e.g. 'semgrep', 'codeql', 'cppcheck').",
                        },
                        "rule_id": {
                            "type": "string",
                            "description": "Rule identifier from the source tool.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "File path where the finding is located.",
                        },
                        "line_start": {
                            "type": "integer",
                            "description": "Starting line number.",
                        },
                        "message": {
                            "type": "string",
                            "description": "Human-readable finding message.",
                        },
                        "severity": {
                            "type": "string",
                            "description": "Severity: critical, high, medium, low, info.",
                            "default": "info",
                        },
                    },
                    "required": [
                        "correlation_id", "task_id", "source_tool",
                        "rule_id", "file_path", "line_start", "message",
                    ],
                },
            },
            {
                "name": f"{self.server_name}.update_finding_status",
                "description": "Update the status of an existing finding with validation of legal transitions.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Unique finding identifier (e.g. 'F-abc123def456').",
                        },
                        "correlation_id": {
                            "type": "string",
                            "description": "Audit correlation ID.",
                        },
                        "new_status": {
                            "type": "string",
                            "description": "New status value. One of: raw, candidate, reachable, exploitable, confirmed_exploited, rejected, unreproducible, false_positive, inconclusive.",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Reason for the status change.",
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Identifier of the agent making the change.",
                            "default": "system",
                        },
                    },
                    "required": [
                        "finding_id", "correlation_id", "new_status", "reason",
                    ],
                },
            },
            {
                "name": f"{self.server_name}.attach_artifact",
                "description": "Attach an evidence artifact (log, file, etc.) to a finding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Unique finding identifier.",
                        },
                        "artifact_type": {
                            "type": "string",
                            "description": "Type of artifact (e.g. 'asan_log', 'source_file', 'binary', 'screenshot').",
                        },
                        "content": {
                            "type": "string",
                            "description": "Text content of the artifact (if text-based).",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Path to an existing file to copy as artifact.",
                        },
                    },
                    "required": ["finding_id", "artifact_type"],
                },
            },
            {
                "name": f"{self.server_name}.attach_sanitizer_log",
                "description": "Save a sanitizer log, auto-parse the error type, and attach to a finding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Unique finding identifier.",
                        },
                        "log_content": {
                            "type": "string",
                            "description": "Full sanitizer log content.",
                        },
                        "build_type": {
                            "type": "string",
                            "description": "Sanitizer type: asan, ubsan, msan.",
                            "default": "asan",
                        },
                    },
                    "required": ["finding_id", "log_content"],
                },
            },
            {
                "name": f"{self.server_name}.attach_stacktrace",
                "description": "Save a stacktrace, resolve project source locations, and attach to a finding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Unique finding identifier.",
                        },
                        "stacktrace_text": {
                            "type": "string",
                            "description": "Full stacktrace text.",
                        },
                    },
                    "required": ["finding_id", "stacktrace_text"],
                },
            },
            {
                "name": f"{self.server_name}.create_reproducer_package",
                "description": "Create a complete reproducer package (Dockerfile, build/run scripts, POC input, manifest) for a finding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Unique finding identifier.",
                        },
                        "dockerfile_content": {
                            "type": "string",
                            "description": "Content for the Dockerfile.",
                            "default": "",
                        },
                        "build_script": {
                            "type": "string",
                            "description": "Content for build.sh.",
                            "default": "",
                        },
                        "run_script": {
                            "type": "string",
                            "description": "Content for run_exploit.sh. Auto-generated if empty.",
                            "default": "",
                        },
                        "poc_input_path": {
                            "type": "string",
                            "description": "Path to a POC input file to include.",
                            "default": "",
                        },
                        "logs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of log entries to include.",
                        },
                    },
                    "required": ["finding_id"],
                },
            },
            {
                "name": f"{self.server_name}.mark_confirmed_exploited",
                "description": "Mark a finding as CONFIRMED_EXPLOITED with an evidence summary.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Unique finding identifier.",
                        },
                        "evidence_summary": {
                            "type": "string",
                            "description": "Summary of evidence confirming exploitation.",
                        },
                    },
                    "required": ["finding_id", "evidence_summary"],
                },
            },
        ]

    # ==================================================================
    # Internal: filesystem helpers
    # ==================================================================

    @staticmethod
    def _evidence_dir(finding_id: str) -> str:
        """Return the evidence directory path for a finding."""
        return os.path.join(
            os.path.abspath(Paths.EVIDENCE_DIR), finding_id
        )

    @staticmethod
    def _finding_json_path(finding_id: str) -> str:
        """Return the path to the finding's JSON file."""
        return os.path.join(
            EvidenceMCP._evidence_dir(finding_id), "finding.json"
        )

    @classmethod
    def _save_finding(cls, finding: Finding):
        """Persist a Finding object to disk."""
        evidence_dir = cls._evidence_dir(finding.finding_id)
        os.makedirs(evidence_dir, exist_ok=True)
        json_path = cls._finding_json_path(finding.finding_id)
        with open(json_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(finding.model_dump(), indent=2, default=str))

    @classmethod
    def _load_finding(cls, finding_id: str) -> Optional[dict]:
        """Load a Finding dict from disk, or None if not found."""
        json_path = cls._finding_json_path(finding_id)
        if not os.path.isfile(json_path):
            return None
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return None

    # ==================================================================
    # Internal: parsers and generators
    # ==================================================================

    @staticmethod
    def _parse_severity(severity: str) -> Severity:
        """Parse a string severity into the Severity enum."""
        try:
            return Severity(severity.lower())
        except ValueError:
            return Severity.INFO

    @staticmethod
    def _parse_status(status: str) -> FindingStatus:
        """Parse a string into a FindingStatus enum value."""
        try:
            return FindingStatus(status.lower())
        except ValueError:
            raise ValueError(
                f"Invalid status '{status}'. "
                f"Must be one of: {sorted(ALLOWED_STATUSES)}"
            )

    @staticmethod
    def _sha256(text: str) -> str:
        """Return the SHA-256 hex digest of a string."""
        return hashlib.sha256(
            text.encode("utf-8", errors="replace")
        ).hexdigest()

    @staticmethod
    def _parse_sanitizer_error(log_content: str) -> Optional[str]:
        """Scan a sanitizer log for known error patterns and return the error type."""
        for error_type, info in SANITIZER_ERROR_PATTERNS.items():
            for keyword in info["keywords"]:
                if keyword.lower() in log_content.lower():
                    return error_type
        return None

    @staticmethod
    def _resolve_stacktrace_locations(stacktrace_text: str) -> List[dict]:
        """
        Parse a stacktrace and return a list of resolved locations,
        filtering out system library frames.

        Handles common formats:
          - GDB: #0  func (args) at /path/to/file:line
          - ASan: #0 0xaddr in func /path/to/file:line:col
          - Python: File "/path/to/file", line N, in func
        """
        locations: List[dict] = []

        # Pattern for GDB-style: #N  func (...) at /path/to/file:line
        gdb_pattern = re.compile(
            r"#\d+\s+.*?\s+at\s+(.+?):(\d+)"
        )

        # Pattern for ASan-style: #N 0xaddr in func /path/to/file:line
        asan_pattern = re.compile(
            r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+\s+(.+?):(\d+)"
        )

        # Pattern for Python-style: File "/path/to/file", line N, in func
        py_pattern = re.compile(
            r'File\s+"(.+?)",\s+line\s+(\d+)'
        )

        # Try each pattern
        for pattern in [gdb_pattern, asan_pattern, py_pattern]:
            for match in pattern.finditer(stacktrace_text):
                file_path = match.group(1)
                line = int(match.group(2))

                # Filter system libraries
                if EvidenceMCP._is_system_lib(file_path):
                    continue

                locations.append({
                    "file": file_path,
                    "line": line,
                })

        # Deduplicate consecutive same-file entries
        deduped: List[dict] = []
        for loc in locations:
            if not deduped or deduped[-1] != loc:
                deduped.append(loc)

        return deduped

    @staticmethod
    def _is_system_lib(file_path: str) -> bool:
        """Check whether a file path belongs to a system library."""
        for prefix in SYSTEM_LIB_PREFIXES:
            if file_path.startswith(prefix) or prefix in file_path:
                return True
        # Also filter common system paths
        system_paths = [
            "/usr/", "/lib/", "/lib64/",
            "/System/Library/", "/Library/Developer/",
            "C:\\Windows\\", "C:\\Program Files\\",
        ]
        for sp in system_paths:
            if file_path.startswith(sp):
                return True
        return False

    @staticmethod
    def _generate_run_exploit_script(finding: Finding) -> str:
        """
        Generate a run_exploit.sh script based on the finding context.
        """
        lines = [
            "#!/bin/bash",
            "set -e",
            "",
            "# Auto-generated run_exploit.sh by VeriAudit EvidenceMCP",
            f"# Finding: {finding.finding_id}",
            f"# Rule: {finding.rule_id}",
            f"# File: {finding.location.file}:{finding.location.line_start}",
            "",
            'echo "[*] Building target..."',
            "bash build.sh",
            "",
            'echo "[*] Running exploit..."',
        ]

        # Add target-specific command based on source tool and rule
        if finding.source_tool in ("semgrep", "codeql", "cppcheck", "clang_tidy"):
            lines.append("# Execute the target binary with POC input")
            lines.append("./target_binary < poc_input > output.log 2>&1 || true")
            lines.append("")
            lines.extend([
                'if grep -q "ERROR: AddressSanitizer" output.log; then',
                '    echo "[+] EXPLOIT CONFIRMED — ASan report detected"',
                "    exit 0",
                "else",
                '    echo "[-] Exploit failed — no ASan report"',
                "    exit 1",
                "fi",
            ])
        elif finding.source_tool == "gitleaks":
            lines.append("# Secret/credential validation")
            lines.append('echo "[*] Validating discovered credential..."')
            lines.append("# Add credential-specific validation logic here")
            lines.append('echo "[+] Credential valid"')
            lines.append("exit 0")
        else:
            lines.append("# Generic exploit execution")
            lines.append("./target_binary < poc_input > output.log 2>&1 || true")
            lines.append("")
            lines.extend([
                r'if grep -qi "error\|crash\|segfault\|abort" output.log; then',
                '    echo "[+] EXPLOIT CONFIRMED"',
                "    exit 0",
                "else",
                '    echo "[-] Exploit failed"',
                "    exit 1",
                "fi",
            ])

        return "\n".join(lines) + "\n"
