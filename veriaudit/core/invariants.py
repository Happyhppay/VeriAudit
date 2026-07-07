"""Invariants module — pure validation functions for Findings and AuditEvents.

Implements cross-field consistency checks beyond what Pydantic field validators enforce.
All functions are pure: no side effects, no I/O.
"""

import re
from typing import List, Tuple

from veriaudit.core.schema import AuditEvent, Finding, FindingStatus

# Patterns compiled once at module level.
_FINDING_ID_RE = re.compile(r"^F-[0-9a-f]{12}$")
_CWE_RE = re.compile(r"^CWE-\d+$")

# States at or beyond static verification requiring evidence or analysis.
# Values are strings because Pydantic Config.use_enum_values = True.
_POST_VERIFICATION_STATES: set[str] = {
    FindingStatus.VERIFIED_STATIC.value,
    FindingStatus.PENDING_DYNAMIC_VALIDATION.value,
    FindingStatus.DYNAMIC_NOT_IMPLEMENTED.value,
}

ALLOWED_SOURCE_TOOLS: set[str] = {"semgrep", "bandit", "gitleaks", "manual"}
ALLOWED_SEVERITIES: set[str] = {"critical", "high", "medium", "low", "info"}
ALLOWED_CONFIDENCES: set[str] = {"high", "medium", "low"}


def validate_finding(finding: Finding) -> Tuple[bool, List[str]]:
    """Validate a single Finding against all invariants.

    Returns (is_valid, error_messages).  All violations are collected and
    returned — the caller decides whether to reject or warn.
    """
    errors: List[str] = []

    # 1. finding_id pattern
    if not _FINDING_ID_RE.match(finding.finding_id):
        errors.append(f"finding_id '{finding.finding_id}' does not match F-<12-hex>")

    # 2. task_id not empty
    if not finding.task_id.strip():
        errors.append("task_id must not be empty")

    # 3. file_path not empty
    if not finding.file_path.strip():
        errors.append("file_path must not be empty")

    # 4. line_start >= 1
    if finding.line_start < 1:
        errors.append(f"line_start must be >= 1, got {finding.line_start}")

    # 5. line_end (if set) >= line_start
    if finding.line_end is not None and finding.line_end < finding.line_start:
        errors.append(
            f"line_end ({finding.line_end}) must be >= line_start ({finding.line_start})"
        )

    # 6. source_tool
    if finding.source_tool not in ALLOWED_SOURCE_TOOLS:
        errors.append(
            f"source_tool '{finding.source_tool}' not in {sorted(ALLOWED_SOURCE_TOOLS)}"
        )

    # 7. severity
    if finding.severity not in ALLOWED_SEVERITIES:
        errors.append(
            f"severity '{finding.severity}' not in {sorted(ALLOWED_SEVERITIES)}"
        )

    # 8. confidence
    if finding.confidence not in ALLOWED_CONFIDENCES:
        errors.append(
            f"confidence '{finding.confidence}' not in {sorted(ALLOWED_CONFIDENCES)}"
        )

    # 9. VERIFIED_STATIC or above → must have evidence or llm_analysis
    if finding.status in _POST_VERIFICATION_STATES:
        has_evidence = len(finding.evidence) > 0
        has_analysis = bool(finding.llm_analysis and finding.llm_analysis.strip())
        if not has_evidence and not has_analysis:
            errors.append(
                f"status '{finding.status}' requires evidence or llm_analysis, "
                "but neither is present"
            )

    # 10. CWE pattern
    if finding.cwe is not None and not _CWE_RE.match(finding.cwe):
        errors.append(f"cwe '{finding.cwe}' does not match CWE-<digits>")

    return (len(errors) == 0, errors)


def validate_event_hash(event: AuditEvent) -> Tuple[bool, str]:
    """Validate an AuditEvent's hash and mandatory fields.

    Returns (is_valid, message).
    """
    # event_id not empty
    if not event.event_id.strip():
        return (False, "event_id must not be empty")

    # task_id not empty
    if not event.task_id.strip():
        return (False, "task_id must not be empty")

    # seq >= 0
    if event.seq < 0:
        return (False, f"seq must be >= 0, got {event.seq}")

    # hash integrity
    recomputed = event.compute_hash()
    if recomputed != event.hash:
        return (
            False,
            f"hash mismatch: stored={event.hash[:16]}..., computed={recomputed[:16]}...",
        )

    return (True, "valid")


def validate_status_consistency(findings: List[Finding]) -> Tuple[bool, List[str]]:
    """Validate cross-finding consistency across a batch.

    Checks: no duplicate finding_ids; all findings share the same task_id.
    """
    errors: List[str] = []

    if not findings:
        return (True, errors)

    seen_ids: set[str] = set()
    task_ids: set[str] = set()

    for finding in findings:
        if finding.finding_id in seen_ids:
            errors.append(f"duplicate finding_id: {finding.finding_id}")
        seen_ids.add(finding.finding_id)
        task_ids.add(finding.task_id)

    if len(task_ids) > 1:
        errors.append(
            f"findings span multiple task_ids: {sorted(task_ids)}"
        )

    return (len(errors) == 0, errors)
