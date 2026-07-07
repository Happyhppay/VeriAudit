"""VeriAudit core — schema, event ledger, state machine, judge engine."""

from veriaudit.core.schema import (
    Finding,
    FindingStatus,
    AuditEvent,
    ProjectProfile,
    AuditReport,
    JudgeRule,
    DEFAULT_RULES,
)
from veriaudit.core.event_ledger import EventLedger
from veriaudit.core.finding_state_machine import FindingStateMachine
from veriaudit.core.judge_engine import JudgeEngine
from veriaudit.core.invariants import validate_finding, validate_event_hash
from veriaudit.core.exceptions import (
    LedgerWriteError,
    InvalidStateTransition,
    TerminalStateModification,
    RepoCloneError,
    InvalidRepoError,
    SASTToolError,
    LLMAPIError,
    ReportGenerationError,
)

__all__ = [
    "Finding",
    "FindingStatus",
    "AuditEvent",
    "ProjectProfile",
    "AuditReport",
    "JudgeRule",
    "DEFAULT_RULES",
    "EventLedger",
    "FindingStateMachine",
    "JudgeEngine",
    "validate_finding",
    "validate_event_hash",
    "LedgerWriteError",
    "InvalidStateTransition",
    "TerminalStateModification",
    "RepoCloneError",
    "InvalidRepoError",
    "SASTToolError",
    "LLMAPIError",
    "ReportGenerationError",
]
