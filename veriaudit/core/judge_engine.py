"""Deterministic Judge Engine — applies priority-ordered rules to Findings.

Person A's module.  The judge evaluates each Finding against a set of
heuristic rules in strict priority order (lowest-numbered first).  The first
matching rule determines the verdict.  If no rule matches, the finding is
marked INCONCLUSIVE.

Design invariants
-----------------
- Purely deterministic: same inputs → same outputs every time.
- No side effects beyond the Finding and the state-machine transition event.
- Terminal-state findings are returned as-is — no re-evaluation.
- Rule matching is dispatched by rule_id; unknown rule_ids are no-ops.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Callable, ClassVar, Dict, List, Optional

from typing import Set as _Set

from veriaudit.core.event_ledger import EventLedger
from veriaudit.core.finding_state_machine import FindingStateMachine
from veriaudit.core.schema import (
    DEFAULT_RULES,
    AuditEvent,
    Finding,
    FindingStatus,
    JudgeRule,
)

# ────────────────────────────────────────────────────────────
# Terminal states — replicated here because FindingStatus(str, Enum)
# stringifies class-level sets/dicts into enum members (same issue
# the FindingStateMachine works around with _TRANSITIONS/_TERMINAL).
# ────────────────────────────────────────────────────────────
_TERMINAL_STATES: _Set[FindingStatus] = {
    FindingStatus.REJECTED_STATIC,
    FindingStatus.DYNAMIC_NOT_IMPLEMENTED,
    FindingStatus.INCONCLUSIVE,
}

# ---------------------------------------------------------------------------
# Sentinel patterns for R001 — file paths that indicate a non-existent or
# placeholder entry.
# ---------------------------------------------------------------------------
_SENTINEL_PATTERNS: tuple[str, ...] = (
    "N/A",
    "<unknown>",
    "???",
    "unknown",
    "(none)",
    "__unknown__",
    "__deleted__",
    "__sentinel__",
    "/dev/null",
    "null",
)

# Directories whose findings are unconditionally rejected by R002.
_REJECTED_DIR_PREFIXES: tuple[str, ...] = (
    "vendor/",
    "test/",
    "tests/",
    "fixture/",
    "fixtures/",
    "third_party/",
    "node_modules/",
    ".venv/",
    "__pycache__/",
)

# R003 safe/unsafe keyword heuristics — compiled once at module level.
_SAFE_KEYWORDS_RE = re.compile(
    r"\b(safe|parameteri[sz]ed|prepared|sanitized|escaped)\b", re.IGNORECASE
)
_BYPASS_KEYWORDS_RE = re.compile(
    r"\b(bypass|unsafe|inject|exploit|vulnerable)\b", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Rule-match dispatcher type
# ---------------------------------------------------------------------------
_RuleMatcher = Callable[[Finding], bool]


class JudgeEngine:
    """Deterministic judge: iterate rules by priority, first match wins."""

    # Map of rule_id → private matcher method name.  Populated at class
    # level so custom subclasses can override individual matchers.
    _MATCHER_REGISTRY: ClassVar[Dict[str, str]] = {
        "R001": "_match_r001",
        "R002": "_match_r002",
        "R003": "_match_r003",
        "R004": "_match_r004",
        "R005": "_match_r005",
        "R006": "_match_r006",
        "R007": "_match_r007",
        "R008": "_match_r008",
    }

    # ── public API ──────────────────────────────────────────────

    def __init__(self, rules: Optional[List[JudgeRule]] = None) -> None:
        """Initialise the judge with a rule set.

        Args:
            rules: Ordered list of JudgeRules.  Defaults to DEFAULT_RULES.
                   Rules are sorted by priority (ascending) at init time.
        """
        source = list(rules) if rules is not None else list(DEFAULT_RULES)
        self._rules: List[JudgeRule] = sorted(source, key=lambda r: r.priority)
        self._matchers: Dict[str, _RuleMatcher] = self._build_matchers()

    @property
    def rules(self) -> List[JudgeRule]:
        """Return a copy of the rules in priority order."""
        return list(self._rules)

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def judge(
        self,
        finding: Finding,
        events: List[AuditEvent],
        ledger: EventLedger,
        state_machine: Optional[FindingStateMachine] = None,
    ) -> Finding:
        """Evaluate *finding* against all rules and return the adjudicated result.

        Rules are tested in priority order (lowest number first).  The first
        rule whose heuristic matches determines the outcome.  If no rule
        matches the finding is marked INCONCLUSIVE.

        Args:
            finding:       The Finding to adjudicate.
            events:        Historical AuditEvents (reserved; not currently
                           used in rule matching).
            ledger:        Append-only EventLedger for audit trail.
            state_machine: Optional state machine for recording transitions.
                           If None, the finding status is updated directly.

        Returns:
            The same *finding* instance with updated status, ruling,
            ruling_reason, and matched_rule_id.

        Raises:
            InvalidStateTransition:  If the state machine rejects the
                                     transition (e.g. terminal state).
            TerminalStateModification: If the finding is already terminal.
        """
        # short-circuit: terminal findings are immutable
        if FindingStatus(finding.status) in _TERMINAL_STATES:
            return finding

        # ── try each rule in priority order ───────────────────
        for rule in self._rules:
            matcher = self._matchers.get(rule.rule_id)
            if matcher is not None and matcher(finding):
                self._apply_verdict(finding, rule, ledger, state_machine)
                return finding

        # ── fallthrough: no rule matched ──────────────────────
        self._apply_verdict(
            finding,
            JudgeRule(
                rule_id="R999",
                condition="No judge rule matched the finding",
                verdict=FindingStatus.INCONCLUSIVE,
                confidence=0.0,
                priority=999,
            ),
            ledger,
            state_machine,
        )
        return finding

    # ── rule matchers (R001 – R008) ────────────────────────────

    @staticmethod
    def _match_r001(finding: Finding) -> bool:
        """R001: file_path is empty or a sentinel placeholder."""
        fp = finding.file_path.strip()
        if not fp:
            return True
        return any(
            fp == sentinel or fp.startswith(sentinel) for sentinel in _SENTINEL_PATTERNS
        )

    @staticmethod
    def _match_r002(finding: Finding) -> bool:
        """R002: file_path resides in a non-business directory."""
        fp = finding.file_path.strip().lower()
        return any(fp.startswith(prefix) for prefix in _REJECTED_DIR_PREFIXES)

    @staticmethod
    def _match_r003(finding: Finding) -> bool:
        """R003: LLM analysis indicates safe/parameterized usage with no bypass
        path."""
        analysis = finding.llm_analysis
        if not analysis or not analysis.strip():
            return False
        has_safe = bool(_SAFE_KEYWORDS_RE.search(analysis))
        has_bypass = bool(_BYPASS_KEYWORDS_RE.search(analysis))
        return has_safe and not has_bypass

    @staticmethod
    def _match_r004(finding: Finding) -> bool:
        """R004: VERIFIED_STATIC with evidence → escalate to dynamic validation."""
        return (
            finding.status == FindingStatus.VERIFIED_STATIC
            and len(finding.evidence) > 0
        )

    @staticmethod
    def _match_r005(finding: Finding) -> bool:
        """R005: LLM analysis present but no tool-based evidence → INCONCLUSIVE."""
        return (
            bool(finding.llm_analysis and finding.llm_analysis.strip())
            and len(finding.evidence) == 0
        )

    @staticmethod
    def _match_r006(finding: Finding) -> bool:
        """R006: Gitleaks finding needs dynamic secret validation."""
        return (
            finding.source_tool == "gitleaks"
            and finding.status == FindingStatus.VERIFIED_STATIC
        )

    @staticmethod
    def _match_r007(finding: Finding) -> bool:
        """R007: All signals agree → confirm VERIFIED_STATIC."""
        return (
            finding.status == FindingStatus.VERIFIED_STATIC
            and bool(finding.llm_analysis and finding.llm_analysis.strip())
            and bool(finding.file_path.strip())
            and finding.line_start > 0
        )

    @staticmethod
    def _match_r008(finding: Finding) -> bool:
        """R008: PENDING_DYNAMIC_VALIDATION → DYNAMIC_NOT_IMPLEMENTED (always)."""
        return finding.status == FindingStatus.PENDING_DYNAMIC_VALIDATION

    # ── internal helpers ───────────────────────────────────────

    @staticmethod
    def _apply_verdict(
        finding: Finding,
        rule: JudgeRule,
        ledger: EventLedger,
        state_machine: Optional[FindingStateMachine],
    ) -> None:
        """Apply a rule verdict to *finding*, recording via the state machine.

        Ruling metadata is always set.  The state-machine transition is
        only invoked when the verdict changes the finding's status
        (R007 is a confirmatory no-op for already-VERIFIED_STATIC).
        """
        finding.ruling = rule.verdict.value
        finding.ruling_reason = rule.condition
        finding.matched_rule_id = rule.rule_id

        current_status = FindingStatus(finding.status)
        if current_status == rule.verdict:
            return

        if state_machine is not None:
            state_machine.transition(
                finding=finding,
                to_status=rule.verdict,
                reason=rule.condition,
                ledger=ledger,
                agent_id="judge_engine",
            )
        else:
            finding.status = rule.verdict  # type: ignore[assignment]
            finding.updated_at = datetime.utcnow()

    def _build_matchers(self) -> Dict[str, _RuleMatcher]:
        """Resolve rule_id → bound matcher method for every known rule."""
        matchers: Dict[str, _RuleMatcher] = {}
        for rule_id, method_name in self._MATCHER_REGISTRY.items():
            method = getattr(self, method_name, None)
            if method is not None:
                matchers[rule_id] = method
        return matchers

    def get_rules(self) -> List[JudgeRule]:
        """Return rules in priority order (convenience alias)."""
        return self.rules
