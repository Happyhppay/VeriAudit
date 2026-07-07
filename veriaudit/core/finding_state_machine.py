# VeriAudit - Finding State Machine
# Encapsulates all finding status transitions.
# This is the ONLY way to change a Finding's status.
from __future__ import annotations

from .event_ledger import EventLedger
from .exceptions import InvalidStateTransition, TerminalStateModification
from .schema import AuditEvent, EventType, Finding, FindingStatus


class FindingStateMachine:
    """
    Finding status state machine.
    Enforces legal transitions and terminal state immutability.
    """

    def transition(self, finding: Finding, to_status: FindingStatus,
                   reason: str, ledger: EventLedger,
                   agent_id: str = "system") -> Finding:
        """
        Execute a status transition.

        1. Validate from_status -> to_status is legal
        2. Validate finding is not in a terminal state
        3. Update finding.status and finding.updated_at
        4. Write an analysis.finding_promoted event to the ledger
        5. Return the updated finding
        """
        from_status = finding.status

        # Check if already terminal
        if FindingStatus.is_terminal(from_status):
            raise TerminalStateModification(finding.finding_id, from_status.value)

        # Check transition validity
        if not FindingStatus.can_transition(from_status, to_status):
            raise InvalidStateTransition(from_status.value, to_status.value)

        # Update finding
        finding.status = to_status
        from datetime import datetime, timezone
        finding.updated_at = datetime.now(timezone.utc)

        # Write event
        event = AuditEvent(
            correlation_id=finding.correlation_id,
            task_id=getattr(finding, 'task_id', None),
            finding_id=finding.finding_id,
            event_type=EventType.ANALYSIS_FINDING_PROMOTED,
            agent_id=agent_id,
            payload={
                "finding_id": finding.finding_id,
                "from_status": from_status.value,
                "to_status": to_status.value,
                "reason": reason,
                "agent_id": agent_id,
            },
        )
        ledger.append(event)

        return finding

    def reject(self, finding: Finding, reason: str,
               ledger: EventLedger, agent_id: str = "system") -> Finding:
        """Shortcut for rejecting a finding."""
        from datetime import datetime, timezone

        finding.status = FindingStatus.REJECTED
        finding.updated_at = datetime.now(timezone.utc)

        event = AuditEvent(
            correlation_id=finding.correlation_id,
            task_id=getattr(finding, 'task_id', None),
            finding_id=finding.finding_id,
            event_type=EventType.ANALYSIS_FINDING_REJECTED,
            agent_id=agent_id,
            payload={
                "finding_id": finding.finding_id,
                "reason": reason,
                "agent_id": agent_id,
            },
        )
        ledger.append(event)

        return finding

    def mark_inconclusive(self, finding: Finding, reason: str,
                           ledger: EventLedger,
                           agent_id: str = "system") -> Finding:
        """Shortcut for inconclusive."""
        return self.transition(finding, FindingStatus.INCONCLUSIVE, reason,
                                ledger, agent_id)

    def mark_reachable(self, finding: Finding, reason: str,
                        ledger: EventLedger,
                        agent_id: str = "system") -> Finding:
        return self.transition(finding, FindingStatus.REACHABLE, reason,
                                ledger, agent_id)

    def mark_exploitable(self, finding: Finding, reason: str,
                          ledger: EventLedger,
                          agent_id: str = "system") -> Finding:
        return self.transition(finding, FindingStatus.EXPLOITABLE, reason,
                                ledger, agent_id)

    def mark_confirmed(self, finding: Finding, reason: str,
                        ledger: EventLedger,
                        agent_id: str = "system") -> Finding:
        return self.transition(finding, FindingStatus.CONFIRMED_EXPLOITED,
                                reason, ledger, agent_id)

    def mark_candidate(self, finding: Finding, reason: str,
                        ledger: EventLedger,
                        agent_id: str = "system") -> Finding:
        return self.transition(finding, FindingStatus.CANDIDATE, reason,
                                ledger, agent_id)

    # Queries
    def is_terminal(self, status: FindingStatus) -> bool:
        return FindingStatus.is_terminal(status)

    def get_allowed_transitions(self, status: FindingStatus) -> list[FindingStatus]:
        return FindingStatus.get_allowed(status)
