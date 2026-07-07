# VeriAudit - Core exceptions
from __future__ import annotations


class VeriAuditError(Exception):
    """Base exception for all VeriAudit errors."""
    pass


# --- Event Ledger ---

class LedgerWriteError(VeriAuditError):
    """Failed to write to the event ledger."""
    pass


class LedgerIntegrityError(VeriAuditError):
    """SHA-256 hash chain verification failed."""
    pass


# --- Finding State Machine ---

class InvalidStateTransition(VeriAuditError):
    """Attempted an invalid status transition."""

    def __init__(self, from_status: str, to_status: str):
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(f"Invalid transition: {from_status} -> {to_status}")


class TerminalStateModification(VeriAuditError):
    """Attempted to modify a finding in terminal state."""

    def __init__(self, finding_id: str, current_status: str):
        self.finding_id = finding_id
        self.current_status = current_status
        super().__init__(f"Finding {finding_id} is in terminal state {current_status}")


# --- Invariants ---

class InvariantViolation(VeriAuditError):
    """A core invariant was violated."""

    def __init__(self, invariant: str, details: str = ""):
        self.invariant = invariant
        self.details = details
        super().__init__(f"Invariant violation [{invariant}]: {details}")


class BoundaryViolation(InvariantViolation):
    """Agent called a tool outside its whitelist."""

    def __init__(self, agent_id: str, tool_name: str):
        super().__init__(
            invariant="boundary_discipline",
            details=f"Agent '{agent_id}' attempted to call '{tool_name}' outside its whitelist",
        )


class LockViolation(InvariantViolation):
    """Agent tried to modify a finding locked by another agent."""

    def __init__(self, finding_id: str, agent_id: str, lock_owner: str):
        super().__init__(
            invariant="lock_ownership",
            details=f"Agent '{agent_id}' tried to modify finding '{finding_id}' locked by '{lock_owner}'",
        )


# --- Repo ---

class RepoCloneError(VeriAuditError):
    """Failed to clone repository."""
    pass


class InvalidRepoError(VeriAuditError):
    """The provided path is not a valid code repository."""
    pass


# --- SAST ---

class SASTToolError(VeriAuditError):
    """A SAST tool failed during execution."""

    def __init__(self, tool_name: str, stderr: str = ""):
        self.tool_name = tool_name
        self.stderr = stderr
        super().__init__(f"SAST tool '{tool_name}' failed: {stderr[:200]}")


# --- Adapters ---

class AdapterNotFoundError(VeriAuditError):
    """No adapter found for the requested language or build system."""

    def __init__(self, adapter_type: str, key: str):
        self.adapter_type = adapter_type
        self.key = key
        super().__init__(f"No {adapter_type} adapter found for '{key}'")


# --- LLM ---

class LLMAPIError(VeriAuditError):
    """LLM API call failed."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(f"LLM API error (status={status_code}): {message}")


# --- Report ---

class ReportGenerationError(VeriAuditError):
    """Report generation failed."""
    pass
