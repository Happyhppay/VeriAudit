"""Tests for the Invariants module — pure validation functions for Findings and AuditEvents."""

from datetime import datetime, timezone

import pytest

from veriaudit.core.invariants import (
    validate_finding,
    validate_event_hash,
    validate_status_consistency,
)
from veriaudit.core.schema import AuditEvent, Finding, FindingStatus


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _make_finding(**overrides) -> Finding:
    """Create a valid Finding, optionally overriding fields."""
    defaults: dict = {
        "finding_id": "F-1234567890ab",
        "task_id": "task-001",
        "file_path": "src/main.py",
        "line_start": 10,
        "source_tool": "semgrep",
        "rule_id": "python.security.sql-injection",
        "message": "Potential SQL injection",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _make_event(**overrides) -> AuditEvent:
    """Create a valid AuditEvent with a correct hash, optionally overriding fields."""
    ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
    defaults: dict = {
        "event_id": "evt-123456789012",
        "task_id": "task-001",
        "seq": 0,
        "timestamp": ts,
        "event_type": "analysis.raw_finding_emitted",
        "payload": {"key": "value"},
        "prev_hash": "0" * 64,
        "hash": "placeholder",
    }
    defaults.update(overrides)
    event = AuditEvent(**defaults)
    if overrides.get("hash") is None and defaults["hash"] == "placeholder":
        # Only recompute if caller did not provide an explicit hash override
        pass
    if "hash" not in overrides or overrides["hash"] == "placeholder":
        event.hash = event.compute_hash()
    return event


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def valid_finding() -> Finding:
    return _make_finding(
        line_end=20,
        severity="high",
        confidence="medium",
        cwe="CWE-89",
    )


@pytest.fixture
def valid_event() -> AuditEvent:
    return _make_event()


# ═══════════════════════════════════════════════════════════════
# validate_finding
# ═══════════════════════════════════════════════════════════════

class TestValidateFindingValid:
    """1. VALID finding passes."""

    def test_valid_finding_passes(self, valid_finding: Finding) -> None:
        ok, errors = validate_finding(valid_finding)
        assert ok is True
        assert errors == []


class TestValidateFindingIdPattern:
    """2. finding_id pattern validation."""

    def test_missing_f_prefix_fails(self) -> None:
        f = _make_finding(finding_id="A-1234567890ab")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("finding_id" in e for e in errors)

    def test_too_short_fails(self) -> None:
        f = _make_finding(finding_id="F-abcd")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("finding_id" in e for e in errors)

    def test_non_hex_chars_fails(self) -> None:
        # "ghijklmnopqr" — g, h, i, j, k, l, m, n, o, p, q, r are not valid hex
        f = _make_finding(finding_id="F-ghijklmnopqr")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("finding_id" in e for e in errors)

    @pytest.mark.parametrize("fid", ["F-1234567890ab", "F-fedcba987654"])
    def test_valid_hex_ids_pass(self, fid: str) -> None:
        f = _make_finding(finding_id=fid)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []


class TestValidateFindingTaskId:
    """3. task_id validation."""

    def test_empty_task_id_fails(self) -> None:
        f = _make_finding(task_id="")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("task_id" in e for e in errors)

    def test_whitespace_only_fails(self) -> None:
        f = _make_finding(task_id="   ")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("task_id" in e for e in errors)


class TestValidateFindingFilePath:
    """4. file_path validation."""

    def test_empty_file_path_fails(self) -> None:
        f = _make_finding(file_path="")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("file_path" in e for e in errors)

    def test_normal_path_passes(self) -> None:
        f = _make_finding(file_path="src/utils/helper.py")
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []


class TestValidateFindingLineStart:
    """5. line_start validation (needs model_construct to bypass Pydantic ge=1)."""

    def test_zero_fails(self) -> None:
        f = Finding.model_construct(
            finding_id="F-1234567890ab", task_id="task-001", file_path="f.py",
            line_start=0, source_tool="semgrep", rule_id="r1", message="m",
            status="raw", severity="high", confidence="medium",
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("line_start" in e for e in errors)

    def test_negative_fails(self) -> None:
        f = Finding.model_construct(
            finding_id="F-1234567890ab", task_id="task-001", file_path="f.py",
            line_start=-5, source_tool="semgrep", rule_id="r1", message="m",
            status="raw", severity="high", confidence="medium",
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("line_start" in e for e in errors)

    @pytest.mark.parametrize("val", [1, 42, 9999])
    def test_one_or_greater_passes(self, val: int) -> None:
        f = _make_finding(line_start=val)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []


class TestValidateFindingLineEnd:
    """6. line_end validation (cross-field: line_end >= line_start)."""

    def test_less_than_line_start_fails(self) -> None:
        f = _make_finding(line_start=20, line_end=10)
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("line_end" in e for e in errors)

    def test_equal_to_line_start_passes(self) -> None:
        f = _make_finding(line_start=15, line_end=15)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_greater_than_line_start_passes(self) -> None:
        f = _make_finding(line_start=10, line_end=30)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_none_passes(self) -> None:
        f = _make_finding(line_start=10, line_end=None)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []


class TestValidateFindingSourceTool:
    """7. source_tool validation (uses model_construct to bypass Pydantic validator)."""

    @pytest.mark.parametrize("tool", ["semgrep", "bandit", "gitleaks", "manual"])
    def test_allowed_tools_pass(self, tool: str) -> None:
        f = _make_finding(source_tool=tool)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_random_tool_fails(self) -> None:
        f = Finding.model_construct(
            finding_id="F-1234567890ab", task_id="task-001", file_path="f.py",
            line_start=1, source_tool="random_tool", rule_id="r1", message="m",
            status="raw", severity="high", confidence="medium",
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("source_tool" in e for e in errors)


class TestValidateFindingSeverity:
    """8. severity validation (uses model_construct to bypass Pydantic validator)."""

    @pytest.mark.parametrize("sev", ["critical", "high", "medium", "low", "info"])
    def test_allowed_severities_pass(self, sev: str) -> None:
        f = _make_finding(severity=sev)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_fatal_fails(self) -> None:
        f = Finding.model_construct(
            finding_id="F-1234567890ab", task_id="task-001", file_path="f.py",
            line_start=1, source_tool="semgrep", rule_id="r1", message="m",
            status="raw", severity="fatal", confidence="medium",
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("severity" in e for e in errors)


class TestValidateFindingConfidence:
    """9. confidence validation (uses model_construct to bypass Pydantic validator)."""

    @pytest.mark.parametrize("conf", ["high", "medium", "low"])
    def test_allowed_confidences_pass(self, conf: str) -> None:
        f = _make_finding(confidence=conf)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_unknown_fails(self) -> None:
        f = Finding.model_construct(
            finding_id="F-1234567890ab", task_id="task-001", file_path="f.py",
            line_start=1, source_tool="semgrep", rule_id="r1", message="m",
            status="raw", severity="high", confidence="unknown",
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("confidence" in e for e in errors)


class TestValidateFindingPostVerificationEvidence:
    """10. Post-verification evidence/llm_analysis requirement."""

    def test_verified_static_no_evidence_no_analysis_fails(self) -> None:
        f = _make_finding(
            status=FindingStatus.VERIFIED_STATIC,
            evidence=[],
            llm_analysis=None,
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("evidence" in e or "llm_analysis" in e for e in errors)

    def test_verified_static_has_evidence_passes(self) -> None:
        f = _make_finding(
            status=FindingStatus.VERIFIED_STATIC,
            evidence=[{"type": "screenshot", "file": "vuln1.png"}],
            llm_analysis=None,
        )
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_verified_static_has_llm_analysis_passes(self) -> None:
        f = _make_finding(
            status=FindingStatus.VERIFIED_STATIC,
            evidence=[],
            llm_analysis="This is a true positive because...",
        )
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_raw_no_evidence_passes(self) -> None:
        """RAW status is not a post-verification state, so evidence not required."""
        f = _make_finding(
            status=FindingStatus.RAW,
            evidence=[],
            llm_analysis=None,
        )
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_pending_dynamic_validation_no_evidence_fails(self) -> None:
        f = _make_finding(
            status=FindingStatus.PENDING_DYNAMIC_VALIDATION,
            evidence=[],
            llm_analysis=None,
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("evidence" in e or "llm_analysis" in e for e in errors)

    def test_dynamic_not_implemented_no_evidence_fails(self) -> None:
        f = _make_finding(
            status=FindingStatus.DYNAMIC_NOT_IMPLEMENTED,
            evidence=[],
            llm_analysis=None,
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("evidence" in e or "llm_analysis" in e for e in errors)


class TestValidateFindingCwe:
    """11. CWE pattern validation."""

    @pytest.mark.parametrize("cwe", ["CWE-89", "CWE-999"])
    def test_valid_cwe_passes(self, cwe: str) -> None:
        f = _make_finding(cwe=cwe)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []

    def test_missing_dash_fails(self) -> None:
        f = _make_finding(cwe="CWE89")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("cwe" in e for e in errors)

    def test_lowercase_fails(self) -> None:
        f = _make_finding(cwe="cwe-89")
        ok, errors = validate_finding(f)
        assert ok is False
        assert any("cwe" in e for e in errors)

    def test_none_passes(self) -> None:
        f = _make_finding(cwe=None)
        ok, errors = validate_finding(f)
        assert ok is True
        assert errors == []


class TestValidateFindingMultipleErrors:
    """12. Multiple errors are all collected."""

    def test_three_errors_returned(self) -> None:
        f = Finding.model_construct(
            finding_id="F-ghijklmnopqr",   # non-hex → error
            task_id="   ",                 # whitespace only → error
            file_path="src/main.py",
            line_start=1,
            source_tool="invalid_tool",    # invalid tool → error
            rule_id="r1",
            message="m",
            status="raw",
            severity="high",
            confidence="medium",
        )
        ok, errors = validate_finding(f)
        assert ok is False
        assert len(errors) == 3, f"Expected 3 errors, got {len(errors)}: {errors}"


# ═══════════════════════════════════════════════════════════════
# validate_event_hash
# ═══════════════════════════════════════════════════════════════

class TestValidateEventHash:
    """13. AuditEvent hash integrity and mandatory fields."""

    def test_valid_event_passes(self, valid_event: AuditEvent) -> None:
        ok, msg = validate_event_hash(valid_event)
        assert ok is True
        assert msg == "valid"

    def test_empty_event_id_fails(self) -> None:
        event = _make_event(event_id="")
        ok, msg = validate_event_hash(event)
        assert ok is False
        assert "event_id" in msg

    def test_empty_task_id_fails(self) -> None:
        event = _make_event(task_id="")
        ok, msg = validate_event_hash(event)
        assert ok is False
        assert "task_id" in msg

    def test_negative_seq_fails(self) -> None:
        event = AuditEvent.model_construct(
            event_id="evt-123456789012", task_id="task-001",
            seq=-1, event_type="test", prev_hash="0" * 64, hash="0" * 64,
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            payload={},
        )
        ok, msg = validate_event_hash(event)
        assert ok is False
        assert "seq" in msg

    def test_tampered_hash_fails(self) -> None:
        event = _make_event()
        # Tamper with the hash
        event.hash = "0" * 64  # all-zeros is incorrect
        ok, msg = validate_event_hash(event)
        assert ok is False
        assert "hash mismatch" in msg


# ═══════════════════════════════════════════════════════════════
# validate_status_consistency
# ═══════════════════════════════════════════════════════════════

class TestValidateStatusConsistency:
    """14. Cross-finding consistency checks."""

    def test_empty_list_returns_valid(self) -> None:
        ok, errors = validate_status_consistency([])
        assert ok is True
        assert errors == []

    def test_single_finding_returns_valid(self, valid_finding: Finding) -> None:
        ok, errors = validate_status_consistency([valid_finding])
        assert ok is True
        assert errors == []

    def test_different_finding_ids_returns_valid(self) -> None:
        f1 = _make_finding(finding_id="F-aaaaaaaaaaaa")
        f2 = _make_finding(finding_id="F-bbbbbbbbbbbb")
        ok, errors = validate_status_consistency([f1, f2])
        assert ok is True
        assert errors == []

    def test_duplicate_finding_id_returns_invalid(self) -> None:
        f1 = _make_finding(finding_id="F-aaaaaaaaaaaa")
        f2 = _make_finding(finding_id="F-aaaaaaaaaaaa")
        ok, errors = validate_status_consistency([f1, f2])
        assert ok is False
        assert any("duplicate finding_id" in e for e in errors)

    def test_different_task_ids_returns_warning(self) -> None:
        f1 = _make_finding(finding_id="F-aaaaaaaaaaaa", task_id="task-alpha")
        f2 = _make_finding(finding_id="F-bbbbbbbbbbbb", task_id="task-beta")
        ok, errors = validate_status_consistency([f1, f2])
        assert ok is False
        assert any("multiple task_ids" in e for e in errors)
