"""Tests for FindingStateMachine — transition validation, terminal guards, and ledger integration."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest

from veriaudit.core.event_ledger import EventLedger, EVENT_FINDING_PROMOTED, emit_raw_finding
from veriaudit.core.exceptions import InvalidStateTransition, TerminalStateModification
from veriaudit.core.finding_state_machine import FindingStateMachine
from veriaudit.core.schema import Finding, FindingStatus


# ── helpers ───────────────────────────────────────────────────


def make_finding(
    finding_id: str = "F-abc123456789",
    task_id: str = "test-task",
    status: FindingStatus = FindingStatus.RAW,
    source_tool: str = "semgrep",
    rule_id: str = "R001",
    file_path: str = "test.py",
    line_start: int = 1,
    message: str = "test",
) -> Finding:
    """Create a Finding with sensible test defaults."""
    return Finding(
        finding_id=finding_id,
        task_id=task_id,
        status=status,
        source_tool=source_tool,
        rule_id=rule_id,
        file_path=file_path,
        line_start=line_start,
        message=message,
    )


# ── fixtures ──────────────────────────────────────────────────


@pytest.fixture
def ledger(tmp_path):
    """EventLedger backed by a temporary directory."""
    return EventLedger(ledger_dir=str(tmp_path / "ledgers"))


@pytest.fixture
def sm():
    """Fresh FindingStateMachine instance."""
    return FindingStateMachine()


# ──────────────────────────────────────────────────────────────
# 1. Valid transitions
# ──────────────────────────────────────────────────────────────


class TestValidTransitions:
    """Every edge in the transition graph should succeed."""

    def test_raw_to_candidate(self, sm: FindingStateMachine, ledger: EventLedger) -> None:
        """RAW → CANDIDATE: status updated, updated_at changed."""
        finding = make_finding(status=FindingStatus.RAW)
        original_updated_at = finding.updated_at

        result = sm.transition(finding, FindingStatus.CANDIDATE, "LLM judged plausible", ledger)

        assert result is finding
        assert finding.status == FindingStatus.CANDIDATE
        assert finding.updated_at >= original_updated_at

    def test_raw_to_rejected_static(self, sm: FindingStateMachine, ledger: EventLedger) -> None:
        """RAW → REJECTED_STATIC: allowed edge from the graph."""
        finding = make_finding(status=FindingStatus.RAW)
        original_updated_at = finding.updated_at

        result = sm.transition(finding, FindingStatus.REJECTED_STATIC, "False positive", ledger)

        assert result is finding
        assert finding.status == FindingStatus.REJECTED_STATIC
        assert finding.updated_at >= original_updated_at

    def test_candidate_to_verified_static(self, sm: FindingStateMachine, ledger: EventLedger) -> None:
        """CANDIDATE → VERIFIED_STATIC: downstream edge."""
        finding = make_finding(status=FindingStatus.CANDIDATE)
        original_updated_at = finding.updated_at

        result = sm.transition(finding, FindingStatus.VERIFIED_STATIC, "LLM confirmed", ledger)

        assert result is finding
        assert finding.status == FindingStatus.VERIFIED_STATIC
        assert finding.updated_at >= original_updated_at

    def test_candidate_to_rejected_static(self, sm: FindingStateMachine, ledger: EventLedger) -> None:
        """CANDIDATE → REJECTED_STATIC: allowed rejection."""
        finding = make_finding(status=FindingStatus.CANDIDATE)
        original_updated_at = finding.updated_at

        result = sm.transition(finding, FindingStatus.REJECTED_STATIC, "Obvious false positive", ledger)

        assert result is finding
        assert finding.status == FindingStatus.REJECTED_STATIC
        assert finding.updated_at >= original_updated_at

    def test_candidate_to_inconclusive(self, sm: FindingStateMachine, ledger: EventLedger) -> None:
        """CANDIDATE → INCONCLUSIVE: ambiguous result."""
        finding = make_finding(status=FindingStatus.CANDIDATE)
        original_updated_at = finding.updated_at

        result = sm.transition(finding, FindingStatus.INCONCLUSIVE, "Cannot determine statically", ledger)

        assert result is finding
        assert finding.status == FindingStatus.INCONCLUSIVE
        assert finding.updated_at >= original_updated_at

    def test_verified_static_to_pending_dynamic(self, sm: FindingStateMachine, ledger: EventLedger) -> None:
        """VERIFIED_STATIC → PENDING_DYNAMIC_VALIDATION: proceed to next phase."""
        finding = make_finding(status=FindingStatus.VERIFIED_STATIC)
        original_updated_at = finding.updated_at

        result = sm.transition(
            finding, FindingStatus.PENDING_DYNAMIC_VALIDATION, "Ready for dynamic check", ledger
        )

        assert result is finding
        assert finding.status == FindingStatus.PENDING_DYNAMIC_VALIDATION
        assert finding.updated_at >= original_updated_at

    def test_pending_dynamic_to_not_implemented(self, sm: FindingStateMachine, ledger: EventLedger) -> None:
        """PENDING_DYNAMIC_VALIDATION → DYNAMIC_NOT_IMPLEMENTED: executor unavailable."""
        finding = make_finding(status=FindingStatus.PENDING_DYNAMIC_VALIDATION)
        original_updated_at = finding.updated_at

        result = sm.transition(
            finding, FindingStatus.DYNAMIC_NOT_IMPLEMENTED, "No dynamic executor available", ledger
        )

        assert result is finding
        assert finding.status == FindingStatus.DYNAMIC_NOT_IMPLEMENTED
        assert finding.updated_at >= original_updated_at


# ──────────────────────────────────────────────────────────────
# 2. Invalid transitions (raise InvalidStateTransition)
# ──────────────────────────────────────────────────────────────


class TestInvalidTransitions:
    """Non-terminal sources with unreachable targets must raise InvalidStateTransition."""

    def test_raw_to_verified_static_not_allowed(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """RAW → VERIFIED_STATIC: skips CANDIDATE, not reachable."""
        finding = make_finding(status=FindingStatus.RAW)

        with pytest.raises(InvalidStateTransition):
            sm.transition(finding, FindingStatus.VERIFIED_STATIC, "skip candidate", ledger)

    def test_raw_to_inconclusive_not_allowed(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """RAW → INCONCLUSIVE: not in allowed transitions."""
        finding = make_finding(status=FindingStatus.RAW)

        with pytest.raises(InvalidStateTransition):
            sm.transition(finding, FindingStatus.INCONCLUSIVE, "skip everything", ledger)

    def test_verified_static_to_candidate_backwards(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """VERIFIED_STATIC → CANDIDATE: backward transition not allowed."""
        finding = make_finding(status=FindingStatus.VERIFIED_STATIC)

        with pytest.raises(InvalidStateTransition):
            sm.transition(finding, FindingStatus.CANDIDATE, "re-evaluate", ledger)


# ──────────────────────────────────────────────────────────────
# 3. Terminal state guard (raise TerminalStateModification)
# ──────────────────────────────────────────────────────────────


class TestTerminalStateGuard:
    """Once terminal, no transition is allowed — even to an otherwise reachable state."""

    def test_rejected_static_cannot_transition(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """REJECTED_STATIC → anything: terminal guard fires."""
        finding = make_finding(status=FindingStatus.REJECTED_STATIC)

        with pytest.raises(TerminalStateModification):
            sm.transition(finding, FindingStatus.CANDIDATE, "reopen", ledger)

    def test_dynamic_not_implemented_cannot_transition(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """DYNAMIC_NOT_IMPLEMENTED → anything: terminal guard fires."""
        finding = make_finding(status=FindingStatus.DYNAMIC_NOT_IMPLEMENTED)

        with pytest.raises(TerminalStateModification):
            sm.transition(finding, FindingStatus.VERIFIED_STATIC, "back to verified", ledger)

    def test_inconclusive_to_raw_raises_terminal(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """INCONCLUSIVE → RAW: terminal guard fires (raw is not a valid target anyway)."""
        finding = make_finding(status=FindingStatus.INCONCLUSIVE)

        with pytest.raises(TerminalStateModification):
            sm.transition(finding, FindingStatus.RAW, "go back to start", ledger)


# ──────────────────────────────────────────────────────────────
# 4. is_terminal()
# ──────────────────────────────────────────────────────────────


class TestIsTerminal:
    """is_terminal() mirrors the _TERMINAL set exactly."""

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (FindingStatus.RAW, False),
            (FindingStatus.CANDIDATE, False),
            (FindingStatus.VERIFIED_STATIC, False),
            (FindingStatus.PENDING_DYNAMIC_VALIDATION, False),
            (FindingStatus.REJECTED_STATIC, True),
            (FindingStatus.DYNAMIC_NOT_IMPLEMENTED, True),
            (FindingStatus.INCONCLUSIVE, True),
        ],
    )
    def test_is_terminal(
        self, sm: FindingStateMachine, status: FindingStatus, expected: bool
    ) -> None:
        """Given a status, is_terminal returns expected boolean."""
        assert sm.is_terminal(status) == expected


# ──────────────────────────────────────────────────────────────
# 5. get_allowed_transitions()
# ──────────────────────────────────────────────────────────────


class TestGetAllowedTransitions:
    """get_allowed_transitions() returns the correct list for each status."""

    def test_raw_returns_candidate_and_rejected_static(self, sm: FindingStateMachine) -> None:
        """RAW → [CANDIDATE, REJECTED_STATIC]."""
        allowed = sm.get_allowed_transitions(FindingStatus.RAW)
        assert set(allowed) == {FindingStatus.CANDIDATE, FindingStatus.REJECTED_STATIC}

    def test_inconclusive_returns_candidate(self, sm: FindingStateMachine) -> None:
        """INCONCLUSIVE → [CANDIDATE]."""
        allowed = sm.get_allowed_transitions(FindingStatus.INCONCLUSIVE)
        assert allowed == [FindingStatus.CANDIDATE]

    def test_rejected_static_returns_empty(self, sm: FindingStateMachine) -> None:
        """REJECTED_STATIC → []."""
        allowed = sm.get_allowed_transitions(FindingStatus.REJECTED_STATIC)
        assert allowed == []

    def test_unknown_status_returns_empty(self, sm: FindingStateMachine) -> None:
        """Querying get_allowed_transitions for a terminal-only state should still work."""
        allowed = sm.get_allowed_transitions(FindingStatus.DYNAMIC_NOT_IMPLEMENTED)
        assert allowed == []


# ──────────────────────────────────────────────────────────────
# 6. Ledger integration
# ──────────────────────────────────────────────────────────────


class TestLedgerIntegration:
    """Every successful transition produces an audit event in the EventLedger."""

    def test_event_appended_after_transition(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """After RAW → CANDIDATE, a finding_promoted event exists in the ledger."""
        finding = make_finding(status=FindingStatus.RAW)
        # First emit the raw finding so the ledger has a baseline event.
        emit_raw_finding(ledger, finding)

        sm.transition(finding, FindingStatus.CANDIDATE, "promoted by LLM", ledger)

        events = ledger.get_finding_events(finding.finding_id)
        # Should have 2 events: raw_finding_emitted + finding_promoted
        promoted_events = [e for e in events if e.event_type == EVENT_FINDING_PROMOTED]
        assert len(promoted_events) == 1

    def test_event_type_is_finding_promoted(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """The emitted event has event_type 'analysis.finding_promoted'."""
        finding = make_finding(status=FindingStatus.RAW)
        emit_raw_finding(ledger, finding)

        sm.transition(finding, FindingStatus.CANDIDATE, "judge ruling", ledger)

        events = ledger.get_finding_events(finding.finding_id)
        promoted = [e for e in events if e.event_type == EVENT_FINDING_PROMOTED]
        assert len(promoted) == 1
        assert promoted[0].event_type == EVENT_FINDING_PROMOTED

    def test_event_payload_contains_status_fields(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """Payload carries from_status, to_status, reason, agent_id."""
        finding = make_finding(status=FindingStatus.RAW)
        emit_raw_finding(ledger, finding)

        sm.transition(
            finding,
            FindingStatus.CANDIDATE,
            "exploit appears plausible",
            ledger,
            agent_id="llm_judge_01",
        )

        events = ledger.get_finding_events(finding.finding_id)
        promoted = [e for e in events if e.event_type == EVENT_FINDING_PROMOTED]
        payload = promoted[0].payload

        assert payload["from_status"] == "raw"
        assert payload["to_status"] == "candidate"
        assert payload["reason"] == "exploit appears plausible"
        assert payload["agent_id"] == "llm_judge_01"

    def test_custom_agent_id_in_payload(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """Different agent_id values are recorded correctly."""
        finding = make_finding(status=FindingStatus.RAW)
        emit_raw_finding(ledger, finding)

        sm.transition(
            finding,
            FindingStatus.CANDIDATE,
            "sast rule triggered",
            ledger,
            agent_id="sast_engine_v2",
        )

        events = ledger.get_finding_events(finding.finding_id)
        promoted = [e for e in events if e.event_type == EVENT_FINDING_PROMOTED]
        assert promoted[0].payload["agent_id"] == "sast_engine_v2"

    def test_default_agent_id_is_verification_agent(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """When agent_id is not provided, it defaults to 'verification_agent'."""
        finding = make_finding(status=FindingStatus.RAW)
        emit_raw_finding(ledger, finding)

        sm.transition(finding, FindingStatus.CANDIDATE, "auto-promoted", ledger)

        events = ledger.get_finding_events(finding.finding_id)
        promoted = [e for e in events if e.event_type == EVENT_FINDING_PROMOTED]
        assert promoted[0].payload["agent_id"] == "verification_agent"

    def test_multiple_transitions_produce_multiple_events(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """A finding going through multiple states produces one event per transition."""
        finding = make_finding(status=FindingStatus.RAW)
        emit_raw_finding(ledger, finding)

        # RAW → CANDIDATE → VERIFIED_STATIC → PENDING_DYNAMIC_VALIDATION
        sm.transition(finding, FindingStatus.CANDIDATE, "promoted", ledger)
        sm.transition(finding, FindingStatus.VERIFIED_STATIC, "confirmed", ledger)
        sm.transition(finding, FindingStatus.PENDING_DYNAMIC_VALIDATION, "next phase", ledger)

        events = ledger.get_finding_events(finding.finding_id)
        promoted = [e for e in events if e.event_type == EVENT_FINDING_PROMOTED]
        assert len(promoted) == 3

        expected_to_statuses = ["candidate", "verified_static", "pending_dynamic_validation"]
        for evt, expected in zip(promoted, expected_to_statuses):
            assert evt.payload["to_status"] == expected

    def test_event_has_finding_id_and_task_id(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """The ledger event carries the correct finding_id and task_id."""
        finding = make_finding(status=FindingStatus.RAW, finding_id="F-deadbeef1234")
        emit_raw_finding(ledger, finding)

        sm.transition(finding, FindingStatus.CANDIDATE, "transition", ledger)

        events = ledger.get_finding_events(finding.finding_id)
        promoted = [e for e in events if e.event_type == EVENT_FINDING_PROMOTED]
        assert promoted[0].finding_id == "F-deadbeef1234"
        assert promoted[0].task_id == "test-task"

    def test_ledger_is_append_only_no_events_lost(
        self, sm: FindingStateMachine, ledger: EventLedger
    ) -> None:
        """Transitions should only append, never overwrite prior events."""
        finding = make_finding(status=FindingStatus.RAW)
        before_count = len(ledger.get_finding_events(finding.finding_id))

        sm.transition(finding, FindingStatus.CANDIDATE, "promoted", ledger)
        after_count = len(ledger.get_finding_events(finding.finding_id))

        assert after_count > before_count
