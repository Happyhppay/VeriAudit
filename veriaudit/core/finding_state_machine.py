"""Finding State Machine — validates and executes lifecycle transitions on Findings.

This is Person A's module.  The state machine enforces the transition graph
defined in FindingStatus and guards terminal states against modification.
Every successful transition is recorded in the Event Ledger.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Set

from veriaudit.core.event_ledger import EventLedger, emit_finding_promoted
from veriaudit.core.exceptions import InvalidStateTransition, TerminalStateModification
from veriaudit.core.schema import Finding, FindingStatus

# ────────────────────────────────────────────────────────────
# Reconstructed transition data (avoiding str, Enum shadowing).
#
# FindingStatus inherits from (str, Enum); Python's enum machinery
# converts any class-level non-descriptor attribute that can be
# stringified into an enum member.  TRANSITIONS (a dict) and TERMINAL
# (a set) in schema.py are therefore inaccessible via standard
# attribute lookup — FindingStatus.TRANSITIONS is the *enum member*
# whose .value is the str() of the dict, not the dict itself.
#
# We reconstruct the graph here using the same FindingStatus members
# so the state machine is self-contained and correct.
# ────────────────────────────────────────────────────────────

_TRANSITIONS: Dict[FindingStatus, List[FindingStatus]] = {
    FindingStatus.RAW: [
        FindingStatus.CANDIDATE,
        FindingStatus.REJECTED_STATIC,
    ],
    FindingStatus.CANDIDATE: [
        FindingStatus.VERIFIED_STATIC,
        FindingStatus.REJECTED_STATIC,
        FindingStatus.INCONCLUSIVE,
    ],
    FindingStatus.VERIFIED_STATIC: [
        FindingStatus.PENDING_DYNAMIC_VALIDATION,
    ],
    FindingStatus.PENDING_DYNAMIC_VALIDATION: [
        FindingStatus.DYNAMIC_NOT_IMPLEMENTED,
        FindingStatus.INCONCLUSIVE,
    ],
    FindingStatus.REJECTED_STATIC: [],
    FindingStatus.DYNAMIC_NOT_IMPLEMENTED: [],
    FindingStatus.INCONCLUSIVE: [
        FindingStatus.CANDIDATE,
    ],
}

_TERMINAL: Set[FindingStatus] = {
    FindingStatus.REJECTED_STATIC,
    FindingStatus.DYNAMIC_NOT_IMPLEMENTED,
    FindingStatus.INCONCLUSIVE,
}


class FindingStateMachine:
    """Validates and executes state transitions on Findings.

    The transition graph originates from FindingStatus (schema.py) but
    is replicated here to avoid str/Enum attribute shadowing.  This
    class is a pure executor — it does **not** perform domain-level
    validation on the Finding object itself; that is the invariants
    module's responsibility.
    """

    _transitions: Dict[FindingStatus, List[FindingStatus]] = _TRANSITIONS
    _terminal: Set[FindingStatus] = _TERMINAL

    # ── public API ─────────────────────────────────────────────

    def transition(
        self,
        finding: Finding,
        to_status: FindingStatus,
        reason: str,
        ledger: EventLedger,
        agent_id: str = "verification_agent",
    ) -> Finding:
        """Execute a state transition on *finding*, recording it in *ledger*.

        Validation order:
          1. Terminal guard   — is the current status immutable?
          2. Transition validity — is *to_status* reachable from current?

        Args:
            finding:   The Finding to transition.
            to_status: Target lifecycle status.
            reason:    Human-readable justification (recorded in ledger).
            ledger:    Append-only event ledger for audit trail.
            agent_id:  Identifier of the agent performing the transition.

        Returns:
            The same *finding* instance with updated status and timestamp.

        Raises:
            InvalidStateTransition: *to_status* is not reachable from
                                    the current status.
            TerminalStateModification: The finding is in a terminal
                                       (immutable) state.
        """
        from_status: FindingStatus = FindingStatus(finding.status)

        # Guard 1 — is the source state terminal (immutable)?
        if from_status in self._terminal:
            raise TerminalStateModification(
                f"Finding '{finding.finding_id}' is in terminal state "
                f"'{from_status.value}' and cannot be modified."
            )

        # Guard 2 — is the transition itself valid?
        allowed = self._transitions.get(from_status, [])
        if to_status not in allowed:
            raise InvalidStateTransition(
                f"Cannot transition from '{from_status.value}' "
                f"to '{to_status.value}'.  "
                f"Allowed: {[s.value for s in allowed] or '(none — terminal)'}"
            )

        # ── execute ────────────────────────────────────────
        finding.status = to_status
        finding.updated_at = datetime.utcnow()

        emit_finding_promoted(
            ledger=ledger,
            finding_id=finding.finding_id,
            from_status=from_status.value,
            to_status=to_status.value,
            reason=reason,
            agent_id=agent_id,
        )

        return finding

    def is_terminal(self, status: FindingStatus) -> bool:
        """Return True if *status* is a terminal (immutable) state."""
        return status in self._terminal

    def get_allowed_transitions(self, status: FindingStatus) -> List[FindingStatus]:
        """Return the list of states reachable from *status*."""
        return self._transitions.get(status, [])
