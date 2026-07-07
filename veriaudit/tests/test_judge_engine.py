"""Tests for JudgeEngine — deterministic rule-based adjudication."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from veriaudit.core.event_ledger import (
    EVENT_FINDING_PROMOTED,
    EventLedger,
    emit_raw_finding,
)
from veriaudit.core.finding_state_machine import FindingStateMachine
from veriaudit.core.judge_engine import JudgeEngine
from veriaudit.core.schema import (
    DEFAULT_RULES,
    Finding,
    FindingStatus,
)


# ── helpers ───────────────────────────────────────────────────


def _mk(
    finding_id: str = "F-000000000001",
    task_id: str = "task-1",
    status: FindingStatus = FindingStatus.RAW,
    source_tool: str = "semgrep",
    file_path: str = "src/app.py",
    line_start: int = 42,
    llm_analysis: str | None = None,
    evidence: List[Dict[str, Any]] | None = None,
    **kwargs: Any,
) -> Finding:
    """Factory for a Finding with convenient defaults."""
    return Finding(
        finding_id=finding_id,
        task_id=task_id,
        status=status,
        source_tool=source_tool,
        rule_id=kwargs.pop("rule_id", "test-rule"),
        file_path=file_path,
        line_start=line_start,
        message=kwargs.pop("message", "Test finding"),
        llm_analysis=llm_analysis,
        evidence=evidence if evidence is not None else [],
        **kwargs,
    )


# ── fixtures ──────────────────────────────────────────────────


@pytest.fixture
def ledger(tmp_path: Path) -> EventLedger:
    """EventLedger backed by a temporary directory."""
    ledger_dir = tmp_path / "ledgers"
    ledger_dir.mkdir()
    return EventLedger(ledger_dir=str(ledger_dir))


@pytest.fixture
def engine() -> JudgeEngine:
    """JudgeEngine with default rules."""
    return JudgeEngine()


@pytest.fixture
def sm() -> FindingStateMachine:
    """FindingStateMachine instance."""
    return FindingStateMachine()


# ═══════════════════════════════════════════════════════════════
# R001 — File path or code line does not exist
# ═══════════════════════════════════════════════════════════════


class TestR001FileNotExist:
    """R001: file_path is empty or a sentinel placeholder."""

    def test_empty_file_path_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given an empty file_path, When judged, Then REJECTED_STATIC with R001."""
        f = _mk(file_path="")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"

    def test_sentinel_na_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given file_path='N/A', When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="N/A")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"

    def test_sentinel_unknown_brackets_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given file_path='<unknown>', When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="<unknown>")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"

    def test_sentinel_question_marks_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given file_path='???', When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="???")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"

    def test_sentinel_devnull_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given file_path='/dev/null', When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="/dev/null")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"

    def test_sentinel_startswith_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given file_path starting with a sentinel (e.g. '/dev/null/foo'), matches."""
        f = _mk(file_path="/dev/null/foo/bar.txt")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"

    def test_normal_file_path_does_not_match(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a normal file_path='src/main.py', When judged, Then R001 does NOT match."""
        # R001 won't match, so a higher-priority rule or fallthrough applies.
        # With no other matching rules, it should fall to R999.
        f = _mk(file_path="src/main.py", status=FindingStatus.RAW)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R001"


# ═══════════════════════════════════════════════════════════════
# R002 — Vendor/test/fixture directory
# ═══════════════════════════════════════════════════════════════


class TestR002NonBusinessDirectory:
    """R002: file_path resides in a non-business directory."""

    def test_vendor_directory_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in vendor/, When judged, Then REJECTED_STATIC with R002."""
        f = _mk(file_path="vendor/lib/dep.py")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_test_directory_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in test/, When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="test/test_auth.py")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_tests_directory_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in tests/, When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="tests/unit/test_auth.py")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_fixture_directory_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in fixture/, When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="fixture/data.json")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_fixtures_directory_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in fixtures/, When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="fixtures/data.json")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_node_modules_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in node_modules/, When judged, Then REJECTED_STATIC."""
        f = _mk(file_path="node_modules/lodash/index.js")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_dotvenv_matches(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in .venv/, When judged, Then REJECTED_STATIC."""
        f = _mk(file_path=".venv/lib/python3.12/site-packages/foo.py")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_src_main_does_not_match(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given a file in src/main/, When judged, Then R002 does NOT match."""
        f = _mk(file_path="src/main/app.py", status=FindingStatus.RAW)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R002"


# ═══════════════════════════════════════════════════════════════
# R003 — Safe API + no bypass
# ═══════════════════════════════════════════════════════════════


class TestR003SafeApi:
    """R003: LLM analysis indicates safe/parameterized usage with no bypass path."""

    def test_parameterized_no_bypass_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given llm_analysis with 'parameterized' and no bypass keyword, matches."""
        f = _mk(llm_analysis="The query is parameterized and uses bound parameters safely.")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R003"

    def test_prepared_statement_no_inject_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given llm_analysis with 'prepared statement' and no 'inject', matches."""
        f = _mk(llm_analysis="Uses prepared statement, no SQL injection possible.")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R003"

    def test_safe_with_bypass_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given 'safe' AND 'bypass' in llm_analysis, R003 does NOT match."""
        f = _mk(
            llm_analysis="The API appears safe but there is a bypass via user input.",
            status=FindingStatus.RAW,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R003"

    def test_sanitized_no_bypass_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given 'sanitized' with no bypass keyword, matches."""
        f = _mk(llm_analysis="Input is sanitized before use, no risk detected.")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R003"

    def test_no_llm_analysis_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given no llm_analysis, R003 does NOT match."""
        f = _mk(llm_analysis=None, status=FindingStatus.RAW)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R003"

    def test_empty_llm_analysis_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given empty llm_analysis, R003 does NOT match."""
        f = _mk(llm_analysis="   ", status=FindingStatus.RAW)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R003"


# ═══════════════════════════════════════════════════════════════
# R004 — Static evidence, no dynamic
# ═══════════════════════════════════════════════════════════════


class TestR004StaticEvidenceNoDynamic:
    """R004: VERIFIED_STATIC + evidence → PENDING_DYNAMIC_VALIDATION."""

    def test_verified_static_with_evidence_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given VERIFIED_STATIC with evidence, matches and promotes to PENDING_DYNAMIC_VALIDATION."""
        f = _mk(
            status=FindingStatus.VERIFIED_STATIC,
            evidence=[{"type": "source_sink", "source": "request.get", "sink": "cursor.execute"}],
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.PENDING_DYNAMIC_VALIDATION
        assert result.matched_rule_id == "R004"

    def test_verified_static_no_evidence_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given VERIFIED_STATIC with empty evidence, R004 does NOT match."""
        f = _mk(status=FindingStatus.VERIFIED_STATIC, evidence=[])
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R004"

    def test_raw_with_evidence_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given RAW status with evidence, R004 requires VERIFIED_STATIC, so no match."""
        f = _mk(
            status=FindingStatus.RAW,
            evidence=[{"type": "source_sink"}],
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R004"


# ═══════════════════════════════════════════════════════════════
# R005 — LLM only, no tool evidence
# ═══════════════════════════════════════════════════════════════


class TestR005LlmOnly:
    """R005: LLM analysis present but no tool-based evidence → INCONCLUSIVE."""

    def test_llm_analysis_empty_evidence_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given llm_analysis and empty evidence list, matches INCONCLUSIVE."""
        f = _mk(
            llm_analysis="This might be an injection but needs further investigation.",
            evidence=[],
            status=FindingStatus.RAW,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.INCONCLUSIVE
        assert result.matched_rule_id == "R005"

    def test_llm_analysis_with_evidence_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given llm_analysis and non-empty evidence, does NOT match (has tool evidence)."""
        f = _mk(
            llm_analysis="Possible vulnerability found.",
            evidence=[{"type": "semgrep_match", "file": "app.py", "line": 42}],
            status=FindingStatus.RAW,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R005"

    def test_no_llm_analysis_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given no llm_analysis, R005 does NOT match."""
        f = _mk(llm_analysis=None, evidence=[], status=FindingStatus.RAW)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R005"

    def test_empty_llm_analysis_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given whitespace-only llm_analysis, R005 does NOT match."""
        f = _mk(llm_analysis="   ", evidence=[], status=FindingStatus.RAW)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R005"


# ═══════════════════════════════════════════════════════════════
# R006 — Gitleaks secret not verified
# ═══════════════════════════════════════════════════════════════


class TestR006Gitleaks:
    """R006: Gitleaks finding needs dynamic secret validation."""

    def test_gitleaks_verified_static_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given gitleaks + VERIFIED_STATIC, matches PENDING_DYNAMIC_VALIDATION."""
        f = _mk(
            source_tool="gitleaks",
            status=FindingStatus.VERIFIED_STATIC,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.PENDING_DYNAMIC_VALIDATION
        assert result.matched_rule_id == "R006"

    def test_gitleaks_raw_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given gitleaks + RAW, R006 requires VERIFIED_STATIC, so no match."""
        f = _mk(source_tool="gitleaks", status=FindingStatus.RAW)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R006"

    def test_semgrep_verified_static_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given semgrep + VERIFIED_STATIC, R006 requires gitleaks, so no match."""
        f = _mk(source_tool="semgrep", status=FindingStatus.VERIFIED_STATIC)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R006"


# ═══════════════════════════════════════════════════════════════
# R007 — Tool + LLM agree
# ═══════════════════════════════════════════════════════════════


class TestR007ToolLlmAgree:
    """R007: All signals agree → confirm VERIFIED_STATIC."""

    def test_verified_static_with_all_signals_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given VERIFIED_STATIC + llm_analysis + valid file + line, confirmatory match."""
        f = _mk(
            status=FindingStatus.VERIFIED_STATIC,
            llm_analysis="Semgrep flagged unsafe use of eval, confirmed by LLM.",
            file_path="src/app.py",
            line_start=42,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        # R007 is confirmatory — status unchanged
        assert result.status == FindingStatus.VERIFIED_STATIC
        assert result.matched_rule_id == "R007"
        assert result.ruling is not None
        assert result.ruling_reason is not None

    def test_no_llm_analysis_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given VERIFIED_STATIC without llm_analysis, R007 does NOT match."""
        f = _mk(status=FindingStatus.VERIFIED_STATIC, llm_analysis=None)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R007"

    def test_raw_with_llm_analysis_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given RAW + llm_analysis, R007 requires VERIFIED_STATIC, so no match."""
        f = _mk(status=FindingStatus.RAW, llm_analysis="Verified safe.")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R007"


# ═══════════════════════════════════════════════════════════════
# R008 — Dynamic not implemented
# ═══════════════════════════════════════════════════════════════


class TestR008DynamicNotImplemented:
    """R008: PENDING_DYNAMIC_VALIDATION → DYNAMIC_NOT_IMPLEMENTED."""

    def test_pending_dynamic_validation_matches(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given PENDING_DYNAMIC_VALIDATION, always matches DYNAMIC_NOT_IMPLEMENTED."""
        f = _mk(status=FindingStatus.PENDING_DYNAMIC_VALIDATION)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.DYNAMIC_NOT_IMPLEMENTED
        assert result.matched_rule_id == "R008"

    def test_other_status_does_not_match(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given VERIFIED_STATIC, R008 requires PENDING_DYNAMIC_VALIDATION."""
        f = _mk(status=FindingStatus.VERIFIED_STATIC)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R008"

    def test_raw_does_not_match(self, engine: JudgeEngine, ledger: EventLedger) -> None:
        """Given RAW, R008 does NOT match."""
        f = _mk(status=FindingStatus.RAW, file_path="src/app.py")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.matched_rule_id != "R008"


# ═══════════════════════════════════════════════════════════════
# Priority ordering
# ═══════════════════════════════════════════════════════════════


class TestPriorityOrdering:
    """Lower-numbered rules take precedence."""

    def test_r001_beats_r004(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given a finding matching R001 (prio 1) and R004 (prio 4), R001 wins."""
        # Empty file_path triggers R001; VERIFIED_STATIC + evidence triggers R004
        f = _mk(
            file_path="",
            status=FindingStatus.VERIFIED_STATIC,
            evidence=[{"type": "test"}],
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"

    def test_higher_priority_blocks_lower(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Given a finding matching R005 (prio 5), it only applies if no higher match."""
        # R005 needs llm_analysis + empty evidence. Also give it a vendor file path
        # to see R002 (prio 2) win instead.
        f = _mk(
            file_path="vendor/lib/dep.py",
            llm_analysis="Some analysis text",
            evidence=[],
            status=FindingStatus.RAW,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        # R002 (prio 2) should match before R005 (prio 5)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R002"

    def test_r005_only_matches_when_no_higher_rule(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """When nothing higher matches, R005 applies."""
        f = _mk(
            file_path="src/app.py",
            llm_analysis="Potential issue found — need more data.",
            evidence=[],
            status=FindingStatus.RAW,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.INCONCLUSIVE
        assert result.matched_rule_id == "R005"


# ═══════════════════════════════════════════════════════════════
# No rule matches (R999 fallthrough)
# ═══════════════════════════════════════════════════════════════


class TestR999Fallthrough:
    """When no rule matches, R999 marks the finding INCONCLUSIVE."""

    def test_no_rule_matches_becomes_inconclusive(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """A finding that matches no rule → INCONCLUSIVE with R999."""
        f = _mk(
            file_path="src/app.py",
            status=FindingStatus.RAW,
            llm_analysis=None,
            evidence=[],
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.INCONCLUSIVE
        assert result.matched_rule_id == "R999"

    def test_ruling_reason_mentions_no_rule_matched(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Fallthrough ruling_reason contains 'No judge rule matched'."""
        f = _mk(
            file_path="src/valid.py",
            status=FindingStatus.RAW,
        )
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.ruling_reason is not None
        assert "No judge rule matched" in result.ruling_reason


# ═══════════════════════════════════════════════════════════════
# Terminal findings
# ═══════════════════════════════════════════════════════════════


class TestTerminalFindings:
    """Findings already in a terminal state are returned unchanged."""

    def test_rejected_static_is_unchanged(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """A REJECTED_STATIC finding is returned as-is."""
        f = _mk(status=FindingStatus.REJECTED_STATIC, file_path="")
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result is f

    def test_dynamic_not_implemented_is_unchanged(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """A DYNAMIC_NOT_IMPLEMENTED finding is returned as-is."""
        f = _mk(status=FindingStatus.DYNAMIC_NOT_IMPLEMENTED)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.DYNAMIC_NOT_IMPLEMENTED
        assert result is f

    def test_inconclusive_is_unchanged(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """An INCONCLUSIVE finding is returned as-is."""
        f = _mk(status=FindingStatus.INCONCLUSIVE)
        result = engine.judge(f, events=[], ledger=ledger)
        assert result.status == FindingStatus.INCONCLUSIVE
        assert result is f


# ═══════════════════════════════════════════════════════════════
# Integration — state machine transitions + event ledger
# ═══════════════════════════════════════════════════════════════


class TestIntegration:
    """End-to-end: judge → state machine transition → event in ledger."""

    def test_judge_emits_event_and_sets_metadata(
        self, engine: JudgeEngine, ledger: EventLedger, sm: FindingStateMachine
    ) -> None:
        """After judging, the ledger contains the promoted event and finding has metadata."""
        # 1. Create a RAW finding and emit it to the ledger
        f = _mk(
            finding_id="F-aaaa00000001",
            task_id="integration-task",
            source_tool="gitleaks",
            file_path="src/secrets.py",
            status=FindingStatus.RAW,
        )
        emit_raw_finding(ledger, f)

        # 2. Transition RAW → CANDIDATE → VERIFIED_STATIC via state machine
        #    (so the finding exists in the ledger for emit_finding_promoted)
        f.status = FindingStatus.RAW
        sm.transition(f, FindingStatus.CANDIDATE, "promoted to candidate", ledger, agent_id="test")
        sm.transition(f, FindingStatus.VERIFIED_STATIC, "static verified", ledger, agent_id="test")

        # 3. Judge — R006 should match (gitleaks + VERIFIED_STATIC → PENDING_DYNAMIC_VALIDATION)
        result = engine.judge(f, events=[], ledger=ledger, state_machine=sm)

        # 4. Assertions on the finding
        assert result.matched_rule_id == "R006"
        assert result.ruling == FindingStatus.PENDING_DYNAMIC_VALIDATION.value
        assert result.ruling_reason is not None
        assert result.status == FindingStatus.PENDING_DYNAMIC_VALIDATION

        # 5. Assertions on the ledger — should have a promoted event from the judge
        events = ledger.get_finding_events("F-aaaa00000001")
        promoted_events = [
            e for e in events if e.event_type == EVENT_FINDING_PROMOTED
        ]
        # At least: RAW→CANDIDATE, CANDIDATE→VERIFIED_STATIC, VERIFIED_STATIC→PENDING
        assert len(promoted_events) >= 3
        last_promoted = promoted_events[-1]
        assert last_promoted.payload["from_status"] == "verified_static"
        assert last_promoted.payload["to_status"] == "pending_dynamic_validation"
        assert last_promoted.payload["agent_id"] == "judge_engine"

    def test_r007_confirmatory_does_not_emit_event(
        self, engine: JudgeEngine, ledger: EventLedger, sm: FindingStateMachine
    ) -> None:
        """R007 is confirmatory (status unchanged) — no transition event emitted."""
        f = _mk(
            finding_id="F-bbbb00000002",
            task_id="integration-task-2",
            status=FindingStatus.VERIFIED_STATIC,
            llm_analysis="Semgrep and LLM agree — this is a valid finding.",
            file_path="src/eval.py",
            line_start=10,
        )
        emit_raw_finding(ledger, f)

        # Get count of promoted events before judging
        promoted_before = len([
            e for e in ledger.get_finding_events("F-bbbb00000002")
            if e.event_type == EVENT_FINDING_PROMOTED
        ])

        result = engine.judge(f, events=[], ledger=ledger, state_machine=sm)

        # R007 matched but status unchanged
        assert result.matched_rule_id == "R007"
        assert result.status == FindingStatus.VERIFIED_STATIC

        # No new promoted event because status didn't change
        promoted_after = len([
            e for e in ledger.get_finding_events("F-bbbb00000002")
            if e.event_type == EVENT_FINDING_PROMOTED
        ])
        assert promoted_after == promoted_before

    def test_judge_without_state_machine_directly_sets_status(
        self, engine: JudgeEngine, ledger: EventLedger
    ) -> None:
        """Without a state machine, the verdict is applied directly to the finding."""
        f = _mk(
            file_path="",
            status=FindingStatus.RAW,
        )
        result = engine.judge(f, events=[], ledger=ledger, state_machine=None)
        assert result.status == FindingStatus.REJECTED_STATIC
        assert result.matched_rule_id == "R001"
        assert result.ruling == FindingStatus.REJECTED_STATIC.value
