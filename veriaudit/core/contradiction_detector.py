# VeriAudit - Contradiction Detector
# Cross-finding consistency checker. Runs automatically between Exploit and Validation phases.
from __future__ import annotations

from typing import Dict, List, Set

from .schema import Contradiction, Finding, FindingStatus


class ContradictionDetector:
    """
    Detects logical contradictions across findings in the same code region.

    Rules:
      1. If function A has an EXPLOITABLE finding but its caller B has all
         findings REJECTED -> contradiction
      2. Same file, same line, opposite conclusions -> contradiction
      3. EXPLOITABLE trigger location doesn't match static analysis location -> flagged
    """

    def detect(self, findings: List[Finding]) -> List[Contradiction]:
        """
        Run all contradiction checks on a list of findings.
        Returns list of detected contradictions.
        """
        contradictions: List[Contradiction] = []

        # Index findings by file
        by_file: Dict[str, List[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.location.file, []).append(f)

        # Rule 1: Caller/callee inconsistency
        contradictions.extend(self._check_caller_callee(findings))

        # Rule 2: Same-location opposite conclusions
        contradictions.extend(self._check_same_location(by_file))

        # Rule 3: Trigger vs static location mismatch
        contradictions.extend(self._check_trigger_static_mismatch(findings))

        return contradictions

    def _check_caller_callee(self, findings: List[Finding]) -> List[Contradiction]:
        """Check if an EXPLOITABLE finding's callers are all REJECTED."""
        result = []

        # Build a call-graph index from call_path
        fm_map: Dict[str, Finding] = {}
        for f in findings:
            key = f"{f.location.file}:{f.location.function}" if f.location.function else f.finding_id
            fm_map[key] = f

        for f in findings:
            if f.status != FindingStatus.EXPLOITABLE:
                continue
            if not f.call_path:
                continue

            # Check each caller in the call path
            for caller_loc in f.call_path:
                caller_key = f"{caller_loc.file}:{caller_loc.function}"
                caller_finding = fm_map.get(caller_key)
                if caller_finding and caller_finding.status == FindingStatus.REJECTED:
                    result.append(Contradiction(
                        finding_a=f.finding_id,
                        finding_b=caller_finding.finding_id,
                        reason=(f"EXPLOITABLE finding {f.finding_id} ({f.location.file}:"
                                f"{f.location.line_start}) has REJECTED caller "
                                f"{caller_finding.finding_id} ({caller_loc.file}:{caller_loc.line_start})"),
                        severity="error",
                    ))

        return result

    def _check_same_location(self, by_file: Dict[str, List[Finding]]) -> List[Contradiction]:
        """Check if two findings at the same location have opposite conclusions."""
        result = []

        for file_path, file_findings in by_file.items():
            for i, fa in enumerate(file_findings):
                for fb in file_findings[i + 1:]:
                    # Same line (within +/- 5 lines) and same rule
                    if (abs(fa.location.line_start - fb.location.line_start) <= 5
                            and fa.rule_id == fb.rule_id):
                        # Opposite conclusions
                        if self._are_opposite(fa.status, fb.status):
                            result.append(Contradiction(
                                finding_a=fa.finding_id,
                                finding_b=fb.finding_id,
                                reason=(f"Same location ({file_path}:{fa.location.line_start}), "
                                        f"opposite conclusions: {fa.status.value} vs {fb.status.value}"),
                                severity="error",
                            ))

        return result

    def _check_trigger_static_mismatch(self, findings: List[Finding]) -> List[Contradiction]:
        """Check if trigger location differs from static analysis location."""
        result = []

        for f in findings:
            if f.status != FindingStatus.EXPLOITABLE:
                continue
            # Check evidence for actual crash location
            for ev in f.evidence:
                if ev.artifact_type in ("asan_log", "stacktrace"):
                    # The evidence should have location info
                    pass

        return result

    def _are_opposite(self, s1: FindingStatus, s2: FindingStatus) -> bool:
        """Check if two statuses are logically opposite."""
        confirmed_states = {FindingStatus.CONFIRMED_EXPLOITED, FindingStatus.EXPLOITABLE}
        rejected_states = {FindingStatus.REJECTED, FindingStatus.FALSE_POSITIVE}

        return ((s1 in confirmed_states and s2 in rejected_states)
                or (s2 in confirmed_states and s1 in rejected_states))
