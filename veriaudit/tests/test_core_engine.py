"""Tests for VeriAudit core engine — Event Ledger, State Machine, Judge, Invariants."""

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from veriaudit.core.event_ledger import EventLedger
from veriaudit.core.finding_state_machine import FindingStateMachine
from veriaudit.core.invariants import InvariantEngine
from veriaudit.core.judge_engine import JudgeEngine
from veriaudit.core.contradiction_detector import ContradictionDetector
from veriaudit.core.schema import (
    AuditEvent,
    EventType,
    Finding,
    FindingStatus,
    JudgeRule,
    MCPToolCall,
    CodeLocation,
)
from veriaudit.core.exceptions import (
    InvalidStateTransition,
    TerminalStateModification,
    BoundaryViolation,
    InvariantViolation,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def tmp_ledger_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def ledger(tmp_ledger_dir):
    return EventLedger(tmp_ledger_dir)


@pytest.fixture
def sm():
    return FindingStateMachine()


@pytest.fixture
def judge():
    return JudgeEngine()


@pytest.fixture
def invariants():
    return InvariantEngine()


@pytest.fixture
def sample_finding():
    return Finding(
        correlation_id="test-correlation",
        source_tool="semgrep",
        rule_id="test-rule",
        location=CodeLocation(file="test.py", line_start=10),
        message="Test finding",
        severity="high",
    )


# ============================================================
# Event Ledger Tests
# ============================================================

class TestEventLedger:
    def test_append_assigns_sequence_and_hash(self, ledger):
        event = AuditEvent(
            correlation_id="test-session",
            event_type=EventType.AUDIT_SESSION_CREATED,
        )
        result = ledger.append(event)
        assert result.sequence == 1
        assert len(result.hash) == 64
        assert result.prev_hash == "0000000000000000000000000000000000000000000000000000000000000000"

    def test_sequence_increments(self, ledger):
        for i in range(5):
            event = AuditEvent(
                correlation_id="test-seq",
                event_type=EventType.AUDIT_SESSION_CREATED,
            )
            result = ledger.append(event)
            assert result.sequence == i + 1

    def test_hash_chain_is_linked(self, ledger):
        e1 = ledger.append(AuditEvent(
            correlation_id="test-chain",
            event_type=EventType.AUDIT_SESSION_CREATED,
            payload={"step": 1},
        ))
        e2 = ledger.append(AuditEvent(
            correlation_id="test-chain",
            event_type=EventType.REPO_CLONED,
            payload={"step": 2},
        ))
        assert e2.prev_hash == e1.hash
        assert e2.hash != e1.hash

    def test_get_events_returns_sorted(self, ledger):
        for i in range(10):
            ledger.append(AuditEvent(
                correlation_id="test-sorted",
                event_type=EventType.AUDIT_SESSION_CREATED,
            ))
        events = ledger.get_events("test-sorted")
        assert len(events) == 10
        for i in range(1, len(events)):
            assert events[i].sequence > events[i-1].sequence

    def test_get_events_empty_session(self, ledger):
        events = ledger.get_events("nonexistent")
        assert events == []

    def test_get_finding_events(self, ledger):
        fid = "F-test123"
        ledger.append(AuditEvent(
            correlation_id="test-finding", finding_id=fid,
            event_type=EventType.ANALYSIS_RAW_FINDING_EMITTED,
        ))
        ledger.append(AuditEvent(
            correlation_id="test-finding", finding_id="F-other",
            event_type=EventType.ANALYSIS_RAW_FINDING_EMITTED,
        ))
        ledger.append(AuditEvent(
            correlation_id="test-finding", finding_id=fid,
            event_type=EventType.ANALYSIS_FINDING_PROMOTED,
            payload={"to_status": "candidate"},
        ))
        events = ledger.get_finding_events(fid, "test-finding")
        assert len(events) == 2

    def test_project_finding_status_deterministic(self, ledger):
        fid = "F-proj1"
        ledger.append(AuditEvent(
            correlation_id="test-proj", finding_id=fid,
            event_type=EventType.ANALYSIS_RAW_FINDING_EMITTED,
        ))
        ledger.append(AuditEvent(
            correlation_id="test-proj", finding_id=fid,
            event_type=EventType.ANALYSIS_FINDING_PROMOTED,
            payload={"to_status": "candidate"},
        ))
        ledger.append(AuditEvent(
            correlation_id="test-proj", finding_id=fid,
            event_type=EventType.ANALYSIS_FINDING_PROMOTED,
            payload={"to_status": "reachable"},
        ))
        status = ledger.project_finding_status(fid, "test-proj")
        assert status == FindingStatus.REACHABLE

    def test_project_all_findings(self, ledger):
        for fid in ["F-a", "F-b", "F-c"]:
            ledger.append(AuditEvent(
                correlation_id="test-all", finding_id=fid,
                event_type=EventType.ANALYSIS_RAW_FINDING_EMITTED,
            ))
        ledger.append(AuditEvent(
            correlation_id="test-all", finding_id="F-a",
            event_type=EventType.ANALYSIS_FINDING_PROMOTED,
            payload={"to_status": "candidate"},
        ))
        all_statuses = ledger.project_all_findings("test-all")
        assert all_statuses["F-a"] == FindingStatus.CANDIDATE
        assert all_statuses["F-b"] == FindingStatus.RAW
        assert all_statuses["F-c"] == FindingStatus.RAW

    def test_integrity_verification_passes(self, ledger):
        for _ in range(5):
            ledger.append(AuditEvent(
                correlation_id="test-integrity",
                event_type=EventType.AUDIT_SESSION_CREATED,
            ))
        result = ledger.verify_integrity("test-integrity")
        assert result["valid"] is True
        assert result["total_events"] == 5

    def test_integrity_verification_detects_tampering(self, ledger, tmp_ledger_dir):
        for _ in range(5):
            ledger.append(AuditEvent(
                correlation_id="test-tamper",
                event_type=EventType.AUDIT_SESSION_CREATED,
            ))
        # Tamper with the JSONL file
        path = Path(tmp_ledger_dir) / "test-tamper.jsonl"
        lines = path.read_text().split("\n")
        # Modify the second event's hash
        lines[1] = lines[1].replace(lines[1][-64:], "0" * 64)
        path.write_text("\n".join(lines))
        result = ledger.verify_integrity("test-tamper")
        assert result["valid"] is False


# ============================================================
# Finding State Machine Tests
# ============================================================

class TestFindingStateMachine:
    def test_raw_to_candidate_is_legal(self, sm, sample_finding, ledger):
        result = sm.mark_candidate(sample_finding, "passed filter", ledger)
        assert result.status == FindingStatus.CANDIDATE

    def test_candidate_to_reachable_is_legal(self, sm, sample_finding, ledger):
        f = sm.mark_candidate(sample_finding, "filtered", ledger)
        f = sm.mark_reachable(f, "taint path found", ledger)
        assert f.status == FindingStatus.REACHABLE

    def test_reachable_to_exploitable_is_legal(self, sm, sample_finding, ledger):
        f = sm.mark_candidate(sample_finding, "filtered", ledger)
        f = sm.mark_reachable(f, "taint path found", ledger)
        f = sm.mark_exploitable(f, "crash triggered", ledger)
        assert f.status == FindingStatus.EXPLOITABLE

    def test_raw_to_confirmed_is_illegal(self, sm, sample_finding, ledger):
        with pytest.raises(InvalidStateTransition):
            sm.mark_confirmed(sample_finding, "bypassing steps", ledger)

    def test_candidate_to_confirmed_is_illegal(self, sm, sample_finding, ledger):
        f = sm.mark_candidate(sample_finding, "filtered", ledger)
        with pytest.raises(InvalidStateTransition):
            sm.mark_confirmed(f, "no dynamic validation", ledger)

    def test_terminal_cannot_be_modified(self, sm, sample_finding, ledger):
        f = sm.mark_candidate(sample_finding, "filtered", ledger)
        f = sm.mark_reachable(f, "taint path", ledger)
        f = sm.mark_exploitable(f, "crash", ledger)
        f = sm.mark_confirmed(f, "verification passed", ledger)
        # Try to modify again
        with pytest.raises(TerminalStateModification):
            sm.mark_confirmed(f, "double confirm", ledger)

    def test_rejected_is_terminal(self, sm, sample_finding, ledger):
        f = sm.reject(sample_finding, "not reachable", ledger)
        with pytest.raises(TerminalStateModification):
            sm.mark_candidate(f, "re-evaluate", ledger)

    def test_inconclusive_can_be_reanalyzed(self, sm, sample_finding, ledger):
        f = sm.mark_candidate(sample_finding, "filtered", ledger)
        f = sm.mark_inconclusive(f, "timeout during fuzz", ledger)
        # INCONCLUSIVE can go back to CANDIDATE
        f = sm.mark_candidate(f, "re-evaluate", ledger)
        assert f.status == FindingStatus.CANDIDATE

    def test_all_valid_transitions(self, sm, sample_finding, ledger):
        """Test the full happy path: RAW -> CANDIDATE -> REACHABLE -> EXPLOITABLE -> CONFIRMED"""
        f = sm.mark_candidate(sample_finding, "step1", ledger)
        assert f.status == FindingStatus.CANDIDATE
        f = sm.mark_reachable(f, "step2", ledger)
        assert f.status == FindingStatus.REACHABLE
        f = sm.mark_exploitable(f, "step3", ledger)
        assert f.status == FindingStatus.EXPLOITABLE
        f = sm.mark_confirmed(f, "step4", ledger)
        assert f.status == FindingStatus.CONFIRMED_EXPLOITED


# ============================================================
# Judge Engine Tests
# ============================================================

class TestJudgeEngine:
    def test_20_rules_loaded(self, judge):
        assert len(judge.rules) == 20

    def test_rules_sorted_by_priority(self, judge):
        for i in range(len(judge.rules) - 1):
            assert judge.rules[i].priority <= judge.rules[i + 1].priority

    def test_R015_file_not_exist_triggers(self, judge):
        f = Finding(
            correlation_id="test", source_tool="semgrep", rule_id="r",
            location=CodeLocation(file="nonexistent.py", line_start=1),
            message="test",
        )
        events = [AuditEvent(
            correlation_id="test", finding_id=f.finding_id,
            event_type=EventType.EXPLOIT_SANITIZER_REPORT,
            payload={"file_does_not_exist": True},
        )]
        result = judge.judge(f, events)
        assert result.matched_rule_id == "R015"
        assert result.status == FindingStatus.FALSE_POSITIVE

    def test_R013_static_only_inconclusive(self, judge):
        f = Finding(
            correlation_id="test", source_tool="semgrep", rule_id="r",
            location=CodeLocation(file="test.py", line_start=1),
            message="test", call_path=[CodeLocation(file="main.py", line_start=1, function="main")],
        )
        events = []
        result = judge.judge(f, events)
        assert result.matched_rule_id == "R013"
        assert result.status == FindingStatus.INCONCLUSIVE

    def test_no_match_returns_unchanged(self, judge):
        f = Finding(
            correlation_id="test", source_tool="semgrep", rule_id="r",
            location=CodeLocation(file="test.py", line_start=1),
            message="test", severity="critical", confidence="low",
        )
        events = []  # No dynamic evidence, no call_path
        result = judge.judge(f, events)
        # critical+low doesn't match R101 (needs high+high), R102 (needs high+med),
        # R103 (needs medium), or R104 (needs low/info)
        assert result.matched_rule_id is None

    def test_R011_assert_only_crash(self, judge):
        f = Finding(
            correlation_id="test", source_tool="fuzz", rule_id="r",
            location=CodeLocation(file="test.c", line_start=1),
            message="crash",
        )
        events = [AuditEvent(
            correlation_id="test", finding_id=f.finding_id,
            event_type=EventType.EXPLOIT_STACK_TRACE,
            payload={"stacktrace": "__assert_fail at assert.c:42"},
        )]
        result = judge.judge(f, events)
        assert result.matched_rule_id == "R011"
        assert result.status == FindingStatus.REJECTED

    def test_R012_all_third_party_frames(self, judge):
        f = Finding(
            correlation_id="test", source_tool="fuzz", rule_id="r",
            location=CodeLocation(file="test.c", line_start=1),
            message="crash",
        )
        events = [AuditEvent(
            correlation_id="test", finding_id=f.finding_id,
            event_type=EventType.EXPLOIT_SANITIZER_REPORT,
            payload={"error_type": "heap-buffer-overflow",
                     "top_frames": [
                         {"function": "memcpy", "file": "/usr/lib/libc.so.6", "line": 1},
                         {"function": "__libc_start_main", "file": "/usr/lib/libc.so.6", "line": 2},
                     ]},
        )]
        result = judge.judge(f, events)
        # R010 (repro < 3/10) fires first since no stability data and all 3rd-party frames
        assert result.matched_rule_id in ("R010", "R012")

    def test_R005_oob_callback(self, judge):
        f = Finding(
            correlation_id="test", source_tool="exploit", rule_id="r",
            location=CodeLocation(file="test.php", line_start=1),
            message="cmd injection",
        )
        events = [AuditEvent(
            correlation_id="test", finding_id=f.finding_id,
            event_type=EventType.EXPLOIT_POC_EXECUTED,
            payload={"confirmed": True, "oob_callback_received": True},
        )]
        result = judge.judge(f, events)
        assert result.matched_rule_id == "R005"
        assert result.status == FindingStatus.CONFIRMED_EXPLOITED

    def test_R006_timing_injection(self, judge):
        f = Finding(
            correlation_id="test", source_tool="exploit", rule_id="r",
            location=CodeLocation(file="test.php", line_start=1),
            message="sqli",
        )
        events = [AuditEvent(
            correlation_id="test", finding_id=f.finding_id,
            event_type=EventType.EXPLOIT_POC_EXECUTED,
            payload={"timing_observed": 4.8, "expected_delay": 5,
                     "runs_total": 3, "runs_successful": 3},
        )]
        result = judge.judge(f, events)
        assert result.matched_rule_id == "R006"
        assert result.status == FindingStatus.CONFIRMED_EXPLOITED

    def test_R001_asan_write_10of10(self, judge):
        f = Finding(
            correlation_id="test", source_tool="fuzz", rule_id="r",
            location=CodeLocation(file="test.c", line_start=1, function="parse_input"),
            message="crash",
        )
        events = [
            AuditEvent(
                correlation_id="test", finding_id=f.finding_id,
                event_type=EventType.EXPLOIT_SANITIZER_REPORT,
                payload={"error_type": "heap-buffer-overflow"},
            ),
            AuditEvent(
                correlation_id="test", finding_id=f.finding_id,
                event_type=EventType.EXPLOIT_POC_EXECUTED,
                payload={"runs_total": 10, "runs_successful": 10, "stability_rating": "RELIABLE",
                         "top_frames": [{"file": "test.c", "function": "parse_input"}]},
            ),
        ]
        result = judge.judge(f, events)
        assert result.matched_rule_id == "R001"
        assert result.status == FindingStatus.CONFIRMED_EXPLOITED


# ============================================================
# Invariant Tests
# ============================================================

class TestInvariants:
    def test_valid_status_transition(self, invariants):
        assert invariants.check_status_transition(
            FindingStatus.CANDIDATE, FindingStatus.REACHABLE
        )

    def test_invalid_status_transition(self, invariants):
        assert not invariants.check_status_transition(
            FindingStatus.CANDIDATE, FindingStatus.CONFIRMED_EXPLOITED
        )

    def test_boundary_allows_wildcard(self, invariants):
        whitelist = {"test_agent": ["sast_mcp.*"]}
        assert invariants.check_boundary("test_agent", "sast_mcp.run_semgrep", whitelist)
        assert not invariants.check_boundary("test_agent", "fuzz_mcp.run", whitelist)

    def test_boundary_unknown_agent(self, invariants):
        whitelist = {"agent_a": ["repo_mcp.*"]}
        assert not invariants.check_boundary("unknown_agent", "repo_mcp.clone", whitelist)

    def test_lock_ownership_no_lock(self, invariants):
        assert invariants.check_lock_ownership("F-1", "agent_a", {})

    def test_lock_ownership_owner_ok(self, invariants):
        locks = {"F-1": "agent_a"}
        assert invariants.check_lock_ownership("F-1", "agent_a", locks)

    def test_lock_ownership_violation(self, invariants):
        locks = {"F-1": "agent_b"}
        assert not invariants.check_lock_ownership("F-1", "agent_a", locks)


# ============================================================
# Contradiction Detector Tests
# ============================================================

class TestContradictionDetector:
    def test_no_contradictions_empty(self):
        detector = ContradictionDetector()
        result = detector.detect([])
        assert result == []

    def test_no_contradictions_different_locations(self):
        f1 = Finding(
            correlation_id="test", source_tool="a", rule_id="r",
            location=CodeLocation(file="a.py", line_start=10),
            message="test",
        )
        f2 = Finding(
            correlation_id="test", source_tool="a", rule_id="r",
            location=CodeLocation(file="b.py", line_start=100),
            message="test",
        )
        detector = ContradictionDetector()
        result = detector.detect([f1, f2])
        assert result == []

    def test_contradiction_same_location_opposite(self):
        f1 = Finding(
            finding_id="F-a", correlation_id="test", source_tool="a", rule_id="r-same",
            location=CodeLocation(file="a.py", line_start=10),
            message="test", status=FindingStatus.CONFIRMED_EXPLOITED,
        )
        f2 = Finding(
            finding_id="F-b", correlation_id="test", source_tool="b", rule_id="r-same",
            location=CodeLocation(file="a.py", line_start=12),
            message="test", status=FindingStatus.REJECTED,
        )
        detector = ContradictionDetector()
        result = detector.detect([f1, f2])
        assert len(result) == 1
        assert result[0].finding_a == "F-a"
        assert result[0].finding_b == "F-b"

    def test_caller_callee_contradiction(self):
        f_callable = Finding(
            finding_id="F-callee", correlation_id="test", source_tool="a", rule_id="r",
            location=CodeLocation(file="a.py", line_start=10, function="vuln_func"),
            message="test", status=FindingStatus.EXPLOITABLE,
            call_path=[CodeLocation(file="a.py", line_start=5, function="caller_func")],
        )
        f_caller = Finding(
            finding_id="F-caller", correlation_id="test", source_tool="b", rule_id="r2",
            location=CodeLocation(file="a.py", line_start=5, function="caller_func"),
            message="test", status=FindingStatus.REJECTED,
        )
        detector = ContradictionDetector()
        result = detector.detect([f_callable, f_caller])
        assert len(result) == 1
        assert "EXPLOITABLE" in result[0].reason
        assert "REJECTED" in result[0].reason
