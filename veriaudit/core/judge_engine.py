# VeriAudit - Judge Engine
# Deterministic ruling: 16 rules prioritized. LLM fallback only for unmatched cases.
from __future__ import annotations

from typing import List, Optional

from .schema import (
    AuditEvent,
    Finding,
    FindingStatus,
    JudgeRule,
    SANITIZER_ERROR_PATTERNS,
    SYSTEM_LIB_PREFIXES,
)


class JudgeEngine:
    """
    Deterministic judge engine.
    Tries each rule in priority order. First match wins.
    If no rule matches, returns None (caller should use LLM-as-Judge).
    """

    def __init__(self, rules: Optional[List[JudgeRule]] = None):
        self._rules = sorted(
            rules or DEFAULT_JUDGE_RULES,
            key=lambda r: r.priority,
        )

    @property
    def rules(self) -> List[JudgeRule]:
        return self._rules

    def judge(self, finding: Finding,
              events: List[AuditEvent]) -> Finding:
        """
        Run deterministic judgment on a finding.
        Returns the finding with updated status/ruling if a rule matched,
        or the finding unchanged if no rule matched (callers check matched_rule_id).
        """
        for rule in self._rules:
            if self._evaluate_rule(rule, finding, events):
                finding.status = rule.verdict
                finding.ruling = rule.verdict.value
                finding.ruling_reason = f"Rule {rule.rule_id}: {rule.condition}"
                finding.matched_rule_id = rule.rule_id
                from datetime import datetime, timezone
                finding.updated_at = datetime.now(timezone.utc)
                return finding

        # No rule matched — leave finding unchanged (LLM fallback needed)
        return finding

    def has_match(self, finding: Finding,
                   events: List[AuditEvent]) -> bool:
        """Check if any rule matches this finding."""
        for rule in self._rules:
            if self._evaluate_rule(rule, finding, events):
                return True
        return False

    # ========== Rule Evaluation ==========

    def _evaluate_rule(self, rule: JudgeRule,
                        finding: Finding,
                        events: List[AuditEvent]) -> bool:
        """Evaluate a single rule against a finding and its events."""
        rid = rule.rule_id
        f_events = [e for e in events
                     if e.finding_id == finding.finding_id
                     or e.payload.get("finding_id") == finding.finding_id]

        evaluators = {
            "R001": self._eval_R001,
            "R002": self._eval_R002,
            "R003": self._eval_R003,
            "R004": self._eval_R004,
            "R005": self._eval_R005,
            "R006": self._eval_R006,
            "R007": self._eval_R007,
            "R008": self._eval_R008,
            "R009": self._eval_R009,
            "R010": self._eval_R010,
            "R011": self._eval_R011,
            "R012": self._eval_R012,
            "R013": self._eval_R013,
            "R014": self._eval_R014,
            "R015": self._eval_R015,
            "R016": self._eval_R016,
            "R101": self._eval_R101,
            "R102": self._eval_R102,
            "R103": self._eval_R103,
            "R104": self._eval_R104,
        }

        evaluator = evaluators.get(rid)
        if evaluator:
            return evaluator(finding, f_events)
        return False

    def _has_asan_report(self, events: List[AuditEvent]) -> Optional[str]:
        """Check if there's an ASan report and return the error type."""
        for e in events:
            if e.event_type.value == "exploit.sanitizer_report":
                return e.payload.get("error_type", "")
        return None

    def _has_stable_repro(self, events: List[AuditEvent],
                           threshold: int = 10) -> bool:
        """Check if repro meets stability threshold."""
        for e in events:
            success = e.payload.get("runs_successful", 0)
            total = e.payload.get("runs_total", 0)
            if total >= threshold and success >= threshold:
                return True
            # Also check stability rating
            rating = e.payload.get("stability_rating", "")
            if rating == "RELIABLE":
                return True
        return False

    def _has_project_stack_frames(self, events: List[AuditEvent]) -> bool:
        """Check that at least one stack frame is in project code (not system libs)."""
        for e in events:
            frames = e.payload.get("top_frames", [])
            for frame in frames:
                fpath = frame.get("file", "")
                if not any(fpath.startswith(p) for p in SYSTEM_LIB_PREFIXES):
                    return True
        return False

    def _get_repro_count(self, events: List[AuditEvent]) -> int:
        for e in events:
            total = e.payload.get("runs_total", 0)
            success = e.payload.get("runs_successful", 0)
            if total > 0:
                return success
        return 0

    def _has_oob_confirmed(self, events: List[AuditEvent]) -> bool:
        for e in events:
            if e.payload.get("oob_callback_received") or e.payload.get("confirmed"):
                return True
        return False

    def _has_timing_confirm(self, events: List[AuditEvent]) -> bool:
        for e in events:
            observed = e.payload.get("timing_observed", 0)
            expected = e.payload.get("expected_delay", 5)
            if observed > expected - 0.5:
                return True
        return False

    def _has_credential_validated(self, events: List[AuditEvent]) -> bool:
        for e in events:
            if e.payload.get("credential_valid"):
                return True
        return False

    def _has_path_traversal_confirm(self, events: List[AuditEvent]) -> bool:
        for e in events:
            if e.payload.get("accessed_outside_intended"):
                return True
        return False

    def _has_release_crash(self, events: List[AuditEvent]) -> bool:
        for e in events:
            if e.payload.get("crashed") or e.payload.get("release_crashed"):
                return True
        return False

    # ===== Individual rule evaluators =====

    def _eval_R001(self, f, events) -> bool:
        """ASan heap-buffer-overflow WRITE + 10/10 repro + project frames"""
        error_type = self._has_asan_report(events)
        return (error_type == "heap-buffer-overflow"
                and self._has_stable_repro(events, threshold=10)
                and self._has_project_stack_frames(events))

    def _eval_R002(self, f, events) -> bool:
        """ASan heap-use-after-free + 10/10"""
        error_type = self._has_asan_report(events)
        return (error_type == "heap-use-after-free"
                and self._has_stable_repro(events, threshold=10))

    def _eval_R003(self, f, events) -> bool:
        """ASan double-free + 10/10"""
        error_type = self._has_asan_report(events)
        return (error_type == "double-free"
                and self._has_stable_repro(events, threshold=10))

    def _eval_R004(self, f, events) -> bool:
        """UBSan integer overflow + 10/10 repro"""
        error_type = self._has_asan_report(events)
        return ("overflow" in (error_type or "")
                and self._has_stable_repro(events, threshold=10))

    def _eval_R005(self, f, events) -> bool:
        """OOB DNS/HTTP callback confirmed"""
        return self._has_oob_confirmed(events)

    def _eval_R006(self, f, events) -> bool:
        """Time-based injection SLEEP(N) > N-0.5s + 3/3"""
        return self._has_timing_confirm(events) and self._has_stable_repro(events, threshold=3)

    def _eval_R007(self, f, events) -> bool:
        """Credential validated as active"""
        return self._has_credential_validated(events)

    def _eval_R008(self, f, events) -> bool:
        """Path traversal confirmed"""
        return self._has_path_traversal_confirm(events)

    def _eval_R009(self, f, events) -> bool:
        """ASan report + repro 3-7/10"""
        asan = self._has_asan_report(events)
        count = self._get_repro_count(events)
        return asan is not None and 3 <= count < 8

    def _eval_R010(self, f, events) -> bool:
        """ASan report + repro < 3/10"""
        asan = self._has_asan_report(events)
        count = self._get_repro_count(events)
        return asan is not None and count < 3

    def _eval_R011(self, f, events) -> bool:
        """Assert-only crash"""
        for e in events:
            if "__assert_fail" in (e.payload.get("stacktrace", "")
                                   or e.payload.get("backtrace", "")
                                   or ""):
                return True
        return False

    def _eval_R012(self, f, events) -> bool:
        """All stack frames in third-party libs"""
        has_project = self._has_project_stack_frames(events)
        has_asan = self._has_asan_report(events) is not None
        return has_asan and not has_project

    def _eval_R013(self, f, events) -> bool:
        """Static path exists, no dynamic confirmation"""
        has_dynamic = (self._has_asan_report(events)
                       or self._has_oob_confirmed(events)
                       or self._has_timing_confirm(events)
                       or self._has_credential_validated(events)
                       or self._has_path_traversal_confirm(events))
        has_call_path = bool(f.call_path)
        return has_call_path and not has_dynamic

    def _eval_R014(self, f, events) -> bool:
        """Credential validation returned invalid"""
        for e in events:
            if e.payload.get("credential_valid") is False:
                return True
        return False

    def _eval_R015(self, f, events) -> bool:
        """File/line does not exist (LLM hallucination)"""
        # This is checked elsewhere (file existence verification)
        # Marked as false positive if we have explicit evidence
        for e in events:
            if e.payload.get("file_does_not_exist"):
                return True
        return False

    def _eval_R016(self, f, events) -> bool:
        """Sanitizer report but release does not crash"""
        asan = self._has_asan_report(events)
        release_crashed = self._has_release_crash(events)
        return asan is not None and not release_crashed

    def _eval_R101(self, f, events) -> bool:
        """SAST high severity + high confidence + has CWE → VERIFIED_STATIC"""
        return (f.severity.value in ("high", "critical")
                and f.confidence == "high"
                and f.cwe is not None)

    def _eval_R102(self, f, events) -> bool:
        """SAST high severity + medium confidence"""
        return f.severity.value in ("high", "critical") and f.confidence == "medium"

    def _eval_R103(self, f, events) -> bool:
        """SAST medium severity + any confidence"""
        return f.severity.value == "medium"

    def _eval_R104(self, f, events) -> bool:
        """SAST low/info severity"""
        return f.severity.value in ("low", "info")


# Default 16 Judge Rules
DEFAULT_JUDGE_RULES = [
    JudgeRule(rule_id="R001", condition="ASan heap-buffer-overflow WRITE + 10/10 repro + project stack frames",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.98, priority=1),
    JudgeRule(rule_id="R002", condition="ASan heap-use-after-free + 10/10 repro",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.98, priority=1),
    JudgeRule(rule_id="R003", condition="ASan double-free + 10/10 repro",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.98, priority=1),
    JudgeRule(rule_id="R004", condition="UBSan integer overflow + 10/10 repro",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.90, priority=2),
    JudgeRule(rule_id="R005", condition="OOB DNS/HTTP callback confirmed",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.95, priority=1),
    JudgeRule(rule_id="R006", condition="Time-based blind SLEEP(N) > N-0.5s + 3/3",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.90, priority=2),
    JudgeRule(rule_id="R007", condition="Credential validated as active",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.95, priority=1),
    JudgeRule(rule_id="R008", condition="Path traversal confirmed outside intended directory",
              verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.95, priority=1),
    JudgeRule(rule_id="R009", condition="ASan report + repro 3-7/10",
              verdict=FindingStatus.UNREPRODUCIBLE, confidence=0.85, priority=3),
    JudgeRule(rule_id="R010", condition="ASan report + repro < 3/10",
              verdict=FindingStatus.UNREPRODUCIBLE, confidence=0.90, priority=4),
    JudgeRule(rule_id="R011", condition="Assert-only crash",
              verdict=FindingStatus.REJECTED, confidence=0.95, priority=3),
    JudgeRule(rule_id="R012", condition="All stack frames in third-party libraries",
              verdict=FindingStatus.REJECTED, confidence=0.90, priority=3),
    JudgeRule(rule_id="R013", condition="Static path exists but no dynamic trigger confirmed",
              verdict=FindingStatus.INCONCLUSIVE, confidence=0.80, priority=4),
    JudgeRule(rule_id="R014", condition="Credential validation returned invalid",
              verdict=FindingStatus.FALSE_POSITIVE, confidence=0.95, priority=3),
    JudgeRule(rule_id="R015", condition="Reported file/line does not exist",
              verdict=FindingStatus.FALSE_POSITIVE, confidence=0.99, priority=1),
    JudgeRule(rule_id="R016", condition="Sanitizer report but release build does not crash",
              verdict=FindingStatus.FALSE_POSITIVE, confidence=0.85, priority=3),

    # --- Static-only rules (no dynamic evidence needed) ---
    JudgeRule(rule_id="R101", condition="SAST high severity + high confidence + has CWE",
              verdict=FindingStatus.VERIFIED_STATIC, confidence=0.85, priority=10),
    JudgeRule(rule_id="R102", condition="SAST high severity + medium confidence",
              verdict=FindingStatus.CANDIDATE, confidence=0.70, priority=11),
    JudgeRule(rule_id="R103", condition="SAST medium severity + any confidence",
              verdict=FindingStatus.CANDIDATE, confidence=0.60, priority=12),
    JudgeRule(rule_id="R104", condition="SAST low/info severity — keep as candidate",
              verdict=FindingStatus.CANDIDATE, confidence=0.50, priority=13),
]
