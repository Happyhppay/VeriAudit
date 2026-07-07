"""Custom exceptions for VeriAudit.

These are shared across all three persons (A, B, C).
"""


class VeriAuditError(Exception):
    """Base exception for all VeriAudit errors."""


class LedgerWriteError(VeriAuditError):
    """Raised when Event Ledger disk write fails."""


class InvalidStateTransition(VeriAuditError):
    """Raised when a finding state transition is not allowed."""


class TerminalStateModification(VeriAuditError):
    """Raised when attempting to modify a finding in terminal state."""


class RepoCloneError(VeriAuditError):
    """Raised when git clone fails."""


class InvalidRepoError(VeriAuditError):
    """Raised when the input path is not a valid code repository."""


class SASTToolError(VeriAuditError):
    """Raised when a SAST tool execution fails."""


class LLMAPIError(VeriAuditError):
    """Raised when an LLM API call fails."""


class ReportGenerationError(VeriAuditError):
    """Raised when report generation fails."""
