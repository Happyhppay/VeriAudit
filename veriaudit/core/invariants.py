# VeriAudit - 6 Core Invariants
# Hardcoded in the core engine. All agents and MCP calls must pass these checks.
from __future__ import annotations

from typing import Dict, List

from .schema import AuditEvent, EventType, FindingStatus, MCPToolCall


class InvariantEngine:
    """Enforces the six core invariants on every agent action."""

    # ========== Invariant 1: claim-before-work ==========

    def check_claim_before_work(self, agent_id: str,
                                 tool_call: MCPToolCall,
                                 events: List[AuditEvent]) -> bool:
        """
        Agent MUST write an agent.tool_call event BEFORE invoking any MCP tool.
        Checks: last event from this agent for this call_id is a TOOL_CALL intent.
        Returns True if claim exists.
        """
        for e in reversed(events):
            if (e.event_type == EventType.AGENT_TOOL_CALL
                    and e.agent_id == agent_id
                    and e.payload.get("call_id") == tool_call.call_id):
                return True
        return False

    # ========== Invariant 2: complete-after-work ==========

    def check_complete_after_work(self, call_id: str,
                                   events: List[AuditEvent],
                                   timeout_seconds: int = 30) -> bool:
        """
        Tool MUST write a completion event within timeout_seconds.
        Returns True if completion exists.
        """
        from datetime import datetime, timezone, timedelta

        # Find the tool_call event
        call_event = None
        for e in events:
            if (e.event_type == EventType.AGENT_TOOL_CALL
                    and e.payload.get("call_id") == call_id):
                call_event = e
                break

        if not call_event:
            return False

        # Find a matching result event
        for e in reversed(events):
            if (e.event_type == EventType.AGENT_TOOL_RESULT
                    and e.payload.get("call_id") == call_id):
                delta = e.timestamp - call_event.timestamp
                return delta.total_seconds() <= timeout_seconds

        return False

    # ========== Invariant 3: prior-status consistency ==========

    def check_status_transition(self, from_status: FindingStatus,
                                 to_status: FindingStatus) -> bool:
        """
        Finding status transitions MUST follow the state machine.
        Returns True if transition is legal.
        """
        return FindingStatus.can_transition(from_status, to_status)

    # ========== Invariant 4: lock ownership ==========

    def check_lock_ownership(self, finding_id: str,
                              agent_id: str,
                              locks: Dict[str, str]) -> bool:
        """
        A finding locked by one agent cannot be modified by another.
        Returns True if agent_id owns the lock or no lock exists.
        """
        if finding_id not in locks:
            return True  # No lock, anyone can acquire
        return locks[finding_id] == agent_id

    # ========== Invariant 5: boundary discipline ==========

    def check_boundary(self, agent_id: str,
                        tool_name: str,
                        whitelist: Dict[str, List[str]]) -> bool:
        """
        Agent can ONLY call tools in its whitelist.
        Supports glob patterns: "sast_mcp.*", "cpg_mcp.query_*"
        Returns True if tool is allowed.
        """
        if agent_id not in whitelist:
            return False

        allowed_patterns = whitelist[agent_id]
        for pattern in allowed_patterns:
            if self._match_pattern(tool_name, pattern):
                return True
        return False

    def _match_pattern(self, tool_name: str, pattern: str) -> bool:
        """Simple glob matching: * matches any sequence."""
        import re
        regex = "^" + pattern.replace(".", "\\.").replace("*", ".*") + "$"
        return bool(re.match(regex, tool_name))

    # ========== Invariant 6: done immutability ==========

    def check_done_immutability(self, finding_id: str,
                                 events: List[AuditEvent]) -> bool:
        """
        Findings in terminal state cannot be modified.
        Returns True if finding is NOT terminal (can be modified).
        """
        # Get current status from events
        status = FindingStatus.RAW
        for e in sorted(events, key=lambda e: e.sequence):
            if e.finding_id == finding_id or e.payload.get("finding_id") == finding_id:
                if e.event_type == EventType.ANALYSIS_FINDING_PROMOTED:
                    to_s = e.payload.get("to_status") or e.payload.get("to")
                    if to_s:
                        try:
                            status = FindingStatus(to_s)
                        except ValueError:
                            pass
                elif e.event_type == EventType.JUDGE_RULING_MADE:
                    ruling = e.payload.get("ruling")
                    if ruling:
                        try:
                            status = FindingStatus(ruling)
                        except ValueError:
                            pass

        return not FindingStatus.is_terminal(status)

    # ========== Batch check ==========

    def check_all_before_tool_call(self, agent_id: str,
                                    tool_call: MCPToolCall,
                                    whitelist: Dict[str, List[str]],
                                    events: List[AuditEvent]) -> None:
        """Run all relevant checks before a tool call. Raises on violation."""

        from .exceptions import BoundaryViolation

        # Boundary check (5) - fails fast
        if not self.check_boundary(agent_id, tool_call.tool_name, whitelist):
            raise BoundaryViolation(agent_id, tool_call.tool_name)

        # Claim check (1) - must have written intent
        if not self.check_claim_before_work(agent_id, tool_call, events):
            from .exceptions import InvariantViolation
            raise InvariantViolation(
                "claim_before_work",
                f"Agent '{agent_id}' must write AGENT_TOOL_CALL event before calling '{tool_call.tool_name}'"
            )
