"""Comprehensive tests for Event Ledger — append-only JSONL with SHA-256 hash chaining."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime

import pytest

from veriaudit.core.schema import AuditEvent, Finding, FindingStatus
from veriaudit.core.event_ledger import (
    EventLedger,
    GENESIS_HASH,
    emit_raw_finding,
    emit_finding_promoted,
    emit_finding_rejected,
    emit_error,
)


# ── fixtures ──────────────────────────────────────────────────

@pytest.fixture
def ledger_dir(tmp_path):
    """Temporary ledger directory isolated per test."""
    d = tmp_path / "ledgers"
    d.mkdir()
    return str(d)


@pytest.fixture
def ledger(ledger_dir):
    """Fresh EventLedger backed by a temporary directory."""
    return EventLedger(ledger_dir=ledger_dir)


@pytest.fixture
def sample_finding():
    """Minimal valid Finding for use in emit tests."""
    return Finding(
        finding_id="F-aabbccddeeff",
        task_id="task-001",
        source_tool="semgrep",
        rule_id="python.lang.security.audit.sql-injection",
        file_path="src/app.py",
        line_start=42,
        message="Possible SQL injection",
        severity="high",
        cwe="CWE-89",
        confidence="high",
    )


# ── helpers ───────────────────────────────────────────────────

def _make_event(task_id="task-x", **overrides):
    """Quick AuditEvent factory with sensible defaults."""
    kw = {
        "event_id": "evt-ffffffffffff",
        "task_id": task_id,
        "seq": 0,
        "event_type": "test.dummy",
        "payload": {},
        "prev_hash": "",
        "hash": "",
    }
    kw.update(overrides)
    return AuditEvent(**kw)


def _append_event(ledger, task_id="task-x", **overrides):
    """Append via ledger.append() and return the event."""
    return ledger.append(_make_event(task_id=task_id, **overrides))


# ── test append() ─────────────────────────────────────────────

class TestAppend:
    """Tests for EventLedger.append() — hash chaining, seq, thread safety."""

    def test_first_event_uses_genesis_prev_hash(self, ledger):
        evt = _append_event(ledger, task_id="task-a")
        assert evt.seq == 0
        assert evt.prev_hash == GENESIS_HASH
        assert evt.hash == evt.compute_hash()
        assert len(evt.hash) == 64

    def test_second_event_chains_to_first(self, ledger):
        first = _append_event(ledger, task_id="task-a")
        second = _append_event(ledger, task_id="task-a")
        assert second.seq == 1
        assert second.prev_hash == first.hash
        assert second.hash == second.compute_hash()
        assert second.hash != first.hash

    def test_both_events_in_same_ledger_file(self, ledger, ledger_dir):
        _append_event(ledger, task_id="task-a")
        _append_event(ledger, task_id="task-a")
        path = os.path.join(ledger_dir, "task-a.jsonl")
        assert os.path.isfile(path)
        with open(path) as f:
            lines = [ln for ln in f if ln.strip()]
        assert len(lines) == 2

    def test_events_across_tasks_share_global_seq(self, ledger):
        a = _append_event(ledger, task_id="task-a")
        b = _append_event(ledger, task_id="task-b")
        c = _append_event(ledger, task_id="task-a")
        assert a.seq == 0
        assert b.seq == 1
        assert c.seq == 2

    def test_thread_safety_no_seq_collisions(self, ledger_dir):
        """Concurrent appends should produce unique seq numbers."""
        ledger = EventLedger(ledger_dir=ledger_dir)
        errors = []
        seqs: set[int] = set()
        lock = threading.Lock()
        num_events_per_thread = 20

        def worker(worker_id):
            for i in range(num_events_per_thread):
                try:
                    evt = _append_event(
                        ledger, task_id=f"thread-{worker_id}",
                        event_type="test.threaded", payload={"i": i, "worker": worker_id},
                    )
                    with lock:
                        if evt.seq in seqs:
                            errors.append(f"duplicate seq {evt.seq}")
                        seqs.add(evt.seq)
                except Exception as exc:
                    errors.append(str(exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during threaded append: {errors}"
        expected_total = 8 * num_events_per_thread
        assert len(seqs) == expected_total
        assert max(seqs) == expected_total - 1


# ── test get_events() ─────────────────────────────────────────

class TestGetEvents:
    """Tests for EventLedger.get_events()."""

    def test_empty_ledger_returns_empty_list(self, ledger):
        assert ledger.get_events("no-such-task") == []

    def test_two_tasks_isolated(self, ledger):
        e1 = _append_event(ledger, task_id="task-a", payload={"n": 1})
        e2 = _append_event(ledger, task_id="task-a", payload={"n": 2})
        e3 = _append_event(ledger, task_id="task-b", payload={"n": 1})

        a_events = ledger.get_events("task-a")
        b_events = ledger.get_events("task-b")

        assert len(a_events) == 2
        assert len(b_events) == 1
        assert [e.payload["n"] for e in a_events] == [1, 2]
        assert [e.payload["n"] for e in b_events] == [1]

    def test_events_sorted_by_seq(self, ledger):
        # Append out of insertion order — ledger appends must come back sorted by seq.
        e3 = _append_event(ledger, task_id="task-s", payload={"val": "c"})
        e1 = _append_event(ledger, task_id="task-s", payload={"val": "a"})
        e2 = _append_event(ledger, task_id="task-s", payload={"val": "b"})
        events = ledger.get_events("task-s")
        seqs = [e.seq for e in events]
        assert seqs == sorted(seqs)


# ── test get_finding_events() ─────────────────────────────────

class TestGetFindingEvents:
    """Tests for EventLedger.get_finding_events() — cross-task lookup."""

    def test_finding_across_multiple_tasks(self, ledger):
        fid = "F-multi-task"
        _append_event(ledger, task_id="task-a", finding_id=fid,
                      event_type="analysis.raw_finding_emitted", payload={"task": "a"})
        _append_event(ledger, task_id="task-b", finding_id=fid,
                      event_type="analysis.finding_promoted",
                      payload={"from_status": "raw", "to_status": "candidate"})

        events = ledger.get_finding_events(fid)
        assert len(events) == 2
        task_ids = {e.task_id for e in events}
        assert task_ids == {"task-a", "task-b"}

    def test_finding_with_no_events_returns_empty(self, ledger):
        assert ledger.get_finding_events("F-nonexistent") == []

    def test_events_sorted_by_seq(self, ledger):
        fid = "F-sorted"
        _append_event(ledger, task_id="task-x", finding_id=fid,
                      event_type="analysis.raw_finding_emitted", payload={"n": 3})
        _append_event(ledger, task_id="task-x", finding_id=fid,
                      event_type="analysis.finding_promoted", payload={"n": 1})
        _append_event(ledger, task_id="task-x", finding_id=fid,
                      event_type="analysis.finding_rejected", payload={"n": 2})
        events = ledger.get_finding_events(fid)
        seqs = [e.seq for e in events]
        assert seqs == sorted(seqs)


# ── test project_finding_status() ─────────────────────────────

class TestProjectFindingStatus:
    """Tests for EventLedger.project_finding_status()."""

    def test_raw_promoted_to_candidate_returns_candidate(self, ledger):
        fid = "F-promoted"
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.raw_finding_emitted",
                      payload={"status": "raw"})
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.finding_promoted",
                      payload={"from_status": "raw", "to_status": "candidate"})

        assert ledger.project_finding_status(fid) == FindingStatus.CANDIDATE

    def test_raw_rejected_returns_rejected_static(self, ledger):
        fid = "F-rejected"
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.raw_finding_emitted",
                      payload={"status": "raw"})
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.finding_rejected",
                      payload={"from_status": "raw", "reason": "false positive"})

        assert ledger.project_finding_status(fid) == FindingStatus.REJECTED_STATIC

    def test_no_events_returns_raw(self, ledger):
        assert ledger.project_finding_status("F-unknown") == FindingStatus.RAW

    def test_multistep_raw_to_verified_static(self, ledger):
        fid = "F-multistep"
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.raw_finding_emitted",
                      payload={"status": "raw"})
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.finding_promoted",
                      payload={"from_status": "raw", "to_status": "candidate"})
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.finding_promoted",
                      payload={"from_status": "candidate", "to_status": "verified_static"})

        assert ledger.project_finding_status(fid) == FindingStatus.VERIFIED_STATIC


# ── test project_all_findings() ───────────────────────────────

class TestProjectAllFindings:
    """Tests for EventLedger.project_all_findings()."""

    def test_task_with_three_findings_at_different_states(self, ledger):
        _append_event(ledger, task_id="t-multi", finding_id="F-001",
                      event_type="analysis.raw_finding_emitted", payload={"status": "raw"})
        _append_event(ledger, task_id="t-multi", finding_id="F-002",
                      event_type="analysis.raw_finding_emitted", payload={"status": "raw"})
        _append_event(ledger, task_id="t-multi", finding_id="F-002",
                      event_type="analysis.finding_promoted",
                      payload={"from_status": "raw", "to_status": "candidate"})
        _append_event(ledger, task_id="t-multi", finding_id="F-003",
                      event_type="analysis.raw_finding_emitted", payload={"status": "raw"})
        _append_event(ledger, task_id="t-multi", finding_id="F-003",
                      event_type="analysis.finding_rejected",
                      payload={"from_status": "raw", "reason": "test"})

        result = ledger.project_all_findings("t-multi")
        assert result == {
            "F-001": FindingStatus.RAW,
            "F-002": FindingStatus.CANDIDATE,
            "F-003": FindingStatus.REJECTED_STATIC,
        }

    def test_task_with_no_findings_returns_empty(self, ledger):
        _append_event(ledger, task_id="t-empty", event_type="system.error",
                      finding_id=None, payload={"error_message": "boom"})
        assert ledger.project_all_findings("t-empty") == {}

    def test_events_with_null_finding_id_are_skipped(self, ledger):
        _append_event(ledger, task_id="t-skip", finding_id=None,
                      event_type="system.error", payload={"error_message": "xxx"})
        _append_event(ledger, task_id="t-skip", finding_id="F-ok",
                      event_type="analysis.raw_finding_emitted", payload={"status": "raw"})

        result = ledger.project_all_findings("t-skip")
        assert "F-ok" in result
        assert len(result) == 1


# ── test project_finding_history() ────────────────────────────

class TestProjectFindingHistory:
    """Tests for EventLedger.project_finding_history()."""

    def test_raw_finding_history(self, ledger):
        fid = "F-history-raw"
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.raw_finding_emitted",
                      payload={"status": "raw"})

        history = ledger.project_finding_history(fid)
        assert len(history) == 1
        h = history[0]
        assert h["from_status"] is None
        assert h["to_status"] == "raw"
        assert h["reason"] == "initial raw finding"
        assert isinstance(h["seq"], int)
        assert isinstance(h["timestamp"], str)

    def test_promoted_and_rejected_history(self, ledger):
        fid = "F-history-full"
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.raw_finding_emitted",
                      payload={"status": "raw"})
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.finding_promoted",
                      payload={"from_status": "raw", "to_status": "candidate",
                               "reason": "looks real", "agent_id": "judge-1"})
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.finding_rejected",
                      payload={"from_status": "candidate", "reason": "false alarm",
                               "agent_id": "judge-2"})

        history = ledger.project_finding_history(fid)
        assert len(history) == 3
        assert history[1]["from_status"] == "raw"
        assert history[1]["to_status"] == "candidate"
        assert history[1]["reason"] == "looks real"
        assert history[2]["from_status"] == "candidate"
        assert history[2]["to_status"] == "rejected_static"
        assert history[2]["reason"] == "false alarm"

    def test_system_error_not_in_history(self, ledger):
        """Non-finding-status events (like system.error) should be excluded from history."""
        fid = "F-history-err"
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="analysis.raw_finding_emitted",
                      payload={"status": "raw"})
        _append_event(ledger, task_id="t", finding_id=fid,
                      event_type="system.error",
                      payload={"error_message": "something broke"})

        history = ledger.project_finding_history(fid)
        assert len(history) == 1  # only raw_finding, not system.error


# ── test verify_integrity() ───────────────────────────────────

class TestVerifyIntegrity:
    """Tests for EventLedger.verify_integrity()."""

    def test_valid_chain(self, ledger):
        _append_event(ledger, task_id="t-valid", payload={"n": 1})
        _append_event(ledger, task_id="t-valid", payload={"n": 2})
        _append_event(ledger, task_id="t-valid", payload={"n": 3})

        result = ledger.verify_integrity("t-valid")
        assert result["valid"] is True
        assert result["total_events"] == 3
        assert result["first_broken_seq"] is None

    def test_empty_ledger_is_valid(self, ledger):
        result = ledger.verify_integrity("t-empty")
        assert result == {"valid": True, "total_events": 0, "first_broken_seq": None}

    def test_corrupted_hash_detected(self, ledger, ledger_dir):
        _append_event(ledger, task_id="t-bad", payload={"n": 1})
        _append_event(ledger, task_id="t-bad", payload={"n": 2})

        # Corrupt the hash of the second event on disk
        path = os.path.join(ledger_dir, "t-bad.jsonl")
        with open(path) as f:
            lines = f.readlines()
        # Parse second line, corrupt its hash
        evt2 = AuditEvent.model_validate_json(lines[1])
        evt2.hash = "a" * 64  # bogus hash
        lines[1] = evt2.model_dump_json() + "\n"
        with open(path, "w") as f:
            f.writelines(lines)

        result = ledger.verify_integrity("t-bad")
        assert result["valid"] is False
        assert result["total_events"] == 2
        assert result["first_broken_seq"] == 1

    def test_corrupted_prev_hash_detected(self, ledger, ledger_dir):
        _append_event(ledger, task_id="t-chain", payload={"n": 1})
        _append_event(ledger, task_id="t-chain", payload={"n": 2})

        # Corrupt prev_hash of the second event
        path = os.path.join(ledger_dir, "t-chain.jsonl")
        with open(path) as f:
            lines = f.readlines()
        evt2 = AuditEvent.model_validate_json(lines[1])
        evt2.prev_hash = "b" * 64  # break the chain
        evt2.hash = evt2.compute_hash()  # rehash so hash is self-consistent but chain is broken
        lines[1] = evt2.model_dump_json() + "\n"
        with open(path, "w") as f:
            f.writelines(lines)

        result = ledger.verify_integrity("t-chain")
        assert result["valid"] is False
        assert result["first_broken_seq"] == 1

    def test_first_event_wrong_prev_hash(self, ledger, ledger_dir):
        _append_event(ledger, task_id="t-first", payload={"n": 1})

        path = os.path.join(ledger_dir, "t-first.jsonl")
        with open(path) as f:
            lines = f.readlines()
        evt = AuditEvent.model_validate_json(lines[0])
        evt.prev_hash = "c" * 64  # should be GENESIS_HASH
        evt.hash = evt.compute_hash()
        with open(path, "w") as f:
            f.write(evt.model_dump_json() + "\n")

        result = ledger.verify_integrity("t-first")
        assert result["valid"] is False
        assert result["first_broken_seq"] == 0


# ── test emit helpers ─────────────────────────────────────────

class TestEmitHelpers:
    """Tests for standalone emit functions."""

    def test_emit_raw_finding(self, ledger, sample_finding):
        evt = emit_raw_finding(ledger, sample_finding)
        assert evt.event_type == "analysis.raw_finding_emitted"
        assert evt.task_id == sample_finding.task_id
        assert evt.finding_id == sample_finding.finding_id
        assert evt.payload["finding_id"] == sample_finding.finding_id
        assert evt.payload["status"] == "raw"
        assert evt.payload["source_tool"] == "semgrep"
        assert evt.seq == 0
        assert evt.prev_hash == GENESIS_HASH

    def test_emit_finding_promoted(self, ledger, sample_finding):
        # First emit raw so the finding exists
        emit_raw_finding(ledger, sample_finding)

        evt = emit_finding_promoted(
            ledger,
            finding_id=sample_finding.finding_id,
            from_status="raw",
            to_status="candidate",
            reason="verified by LLM",
            agent_id="agent-42",
        )
        assert evt.event_type == "analysis.finding_promoted"
        assert evt.finding_id == sample_finding.finding_id
        assert evt.payload["from_status"] == "raw"
        assert evt.payload["to_status"] == "candidate"
        assert evt.payload["reason"] == "verified by LLM"
        assert evt.payload["agent_id"] == "agent-42"
        assert evt.seq == 1

    def test_emit_finding_rejected(self, ledger, sample_finding):
        emit_raw_finding(ledger, sample_finding)

        evt = emit_finding_rejected(
            ledger,
            finding_id=sample_finding.finding_id,
            reason="false positive — test code",
            agent_id="judge-rule-001",
        )
        assert evt.event_type == "analysis.finding_rejected"
        assert evt.finding_id == sample_finding.finding_id
        assert evt.payload["from_status"] == "raw"  # current projected status
        assert evt.payload["to_status"] == "rejected_static"
        assert evt.payload["reason"] == "false positive — test code"
        assert evt.payload["agent_id"] == "judge-rule-001"

        # Verify status is actually REJECTED_STATIC now
        assert ledger.project_finding_status(sample_finding.finding_id) == FindingStatus.REJECTED_STATIC

    def test_emit_error(self, ledger):
        evt = emit_error(ledger, task_id="task-err", error_message="LLM API timeout")
        assert evt.event_type == "system.error"
        assert evt.task_id == "task-err"
        assert evt.finding_id is None
        assert evt.payload["error_message"] == "LLM API timeout"
        assert evt.seq == 0
        assert evt.prev_hash == GENESIS_HASH

    def test_emit_finding_promoted_derives_task_id(self, ledger, sample_finding):
        """emit_finding_promoted derives task_id from existing finding events."""
        emit_raw_finding(ledger, sample_finding)

        evt = emit_finding_promoted(
            ledger,
            finding_id=sample_finding.finding_id,
            from_status="raw",
            to_status="candidate",
            reason="promotion test",
            agent_id="ag-1",
        )
        assert evt.task_id == sample_finding.task_id

    def test_emit_finding_rejected_derives_task_id_and_from_status(self, ledger, sample_finding):
        """emit_finding_rejected derives task_id and auto-populates from_status."""
        emit_raw_finding(ledger, sample_finding)

        evt = emit_finding_rejected(
            ledger,
            finding_id=sample_finding.finding_id,
            reason="not exploitable",
            agent_id="ag-2",
        )
        assert evt.task_id == sample_finding.task_id
        assert evt.payload["from_status"] == "raw"

    def test_emit_error_finding_id_is_none(self, ledger):
        evt = emit_error(ledger, task_id="t", error_message="disk full")
        # Verify stored event also has finding_id=None
        events = ledger.get_events("t")
        assert len(events) == 1
        assert events[0].finding_id is None
        assert events[0].event_type == "system.error"


# ── edge cases ─────────────────────────────────────────────────

class TestEdgeCases:
    """Additional edge-case / behavior tests."""

    def test_event_id_auto_generated_when_empty(self, ledger):
        evt = _append_event(ledger, task_id="t", event_id="")
        assert evt.event_id.startswith("evt-")
        assert len(evt.event_id) == 16  # "evt-" + 12 hex

    def test_event_id_preserved_when_provided(self, ledger):
        custom_id = "evt-custom-id-here"
        evt = _append_event(ledger, task_id="t", event_id=custom_id)
        assert evt.event_id == custom_id

    def test_multiple_findings_in_timeline(self, ledger):
        """Project status through a realistic multi-finding timeline."""
        emit_raw_finding(ledger, Finding(
            finding_id="F-reject-me", task_id="t-real", source_tool="bandit",
            rule_id="B101", file_path="a.py", line_start=1, message="x",
            severity="low", confidence="low",
        ))
        emit_raw_finding(ledger, Finding(
            finding_id="F-keep-me", task_id="t-real", source_tool="semgrep",
            rule_id="R001", file_path="b.py", line_start=10, message="y",
            severity="high", confidence="high",
        ))
        emit_raw_finding(ledger, Finding(
            finding_id="F-maybe-me", task_id="t-real", source_tool="semgrep",
            rule_id="R002", file_path="c.py", line_start=20, message="z",
            severity="medium", confidence="medium",
        ))

        emit_finding_rejected(ledger, "F-reject-me", "false positive", "ag-x")
        emit_finding_promoted(ledger, "F-keep-me", "raw", "candidate", "looks real", "ag-x")
        emit_finding_promoted(ledger, "F-keep-me", "candidate", "verified_static", "confirmed", "ag-x")

        statuses = ledger.project_all_findings("t-real")
        assert statuses["F-reject-me"] == FindingStatus.REJECTED_STATIC
        assert statuses["F-keep-me"] == FindingStatus.VERIFIED_STATIC
        assert statuses["F-maybe-me"] == FindingStatus.RAW

    def test_seq_persists_across_instances(self, ledger_dir):
        """Re-opening a ledger preserves the next seq counter."""
        l1 = EventLedger(ledger_dir=ledger_dir)
        _append_event(l1, task_id="t")
        _append_event(l1, task_id="t")
        assert l1._seq == 2

        l2 = EventLedger(ledger_dir=ledger_dir)
        assert l2._seq == 2
        _append_event(l2, task_id="t")
        assert l2._seq == 3

    def test_compute_hash_deterministic(self):
        """Same event data → same hash."""
        evt = AuditEvent(
            event_id="evt-test-id-1234", task_id="t", seq=0,
            event_type="test.hash", payload={"a": 1, "b": 2},
            prev_hash=GENESIS_HASH, hash="",
        )
        h1 = evt.compute_hash()
        h2 = evt.compute_hash()
        assert h1 == h2
        assert len(h1) == 64

    def test_compute_hash_changes_with_payload(self):
        """Different payload → different hash."""
        e1 = AuditEvent(
            event_id="evt-1", task_id="t", seq=0, event_type="t",
            payload={"x": 1}, prev_hash=GENESIS_HASH, hash="",
        )
        e2 = AuditEvent(
            event_id="evt-1", task_id="t", seq=0, event_type="t",
            payload={"x": 2}, prev_hash=GENESIS_HASH, hash="",
        )
        assert e1.compute_hash() != e2.compute_hash()

    def test_hash_uses_sorted_keys(self):
        """Dict key order should not affect hash."""
        ts = datetime(2025, 1, 1, 0, 0, 0)
        e1 = AuditEvent(
            event_id="evt-1", task_id="t", seq=0, event_type="t",
            payload={"a": 1, "b": 2}, prev_hash=GENESIS_HASH, hash="",
            timestamp=ts,
        )
        e2 = AuditEvent(
            event_id="evt-1", task_id="t", seq=0, event_type="t",
            payload={"b": 2, "a": 1}, prev_hash=GENESIS_HASH, hash="",
            timestamp=ts,
        )
        assert e1.compute_hash() == e2.compute_hash()
