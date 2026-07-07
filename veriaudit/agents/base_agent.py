# VeriAudit - Base Agent (ReAct loop)
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from veriaudit.core.event_ledger import EventLedger
from veriaudit.core.invariants import InvariantEngine
from veriaudit.core.schema import (
    AgentMessage,
    AgentIntent,
    AuditEvent,
    EventType,
    MCPToolCall,
    MCPToolResult,
    gen_id,
)


class BaseAgent(ABC):
    """
    Base class for all agents.
    Implements the ReAct (Reasoning + Acting) loop.
    """

    def __init__(self,
                 agent_id: str,
                 allowed_tools: List[str],
                 ledger: EventLedger,
                 invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None,
                 max_iterations: int = 15,
                 timeout_seconds: int = 1800):
        self.agent_id = agent_id
        self.allowed_tools = allowed_tools
        self.ledger = ledger
        self.invariants = invariants
        self.llm_config = llm_config or {}
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds

        self._locks: Dict[str, str] = {}  # finding_id -> agent_id
        self._current_correlation_id: str = ""

    # ========== Subclass must implement ==========

    @abstractmethod
    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        """Return the system prompt for this agent's LLM call."""
        ...

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """
        Return OpenAI-compatible tool definitions for this agent.
        Subclasses should override to provide their own tool schemas.
        Default: empty (no tools available).
        """
        return []

    # ========== ReAct Loop ==========

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the ReAct loop.

        Args:
            task: {"task_type": "...", "profile": ..., "correlation_id": "...", ...}

        Returns:
            {"status": "completed"/"failed"/"timeout", "result": {...}, "iterations": int}
        """
        self._current_correlation_id = task.get("correlation_id", "")
        start_time = time.time()
        iterations = 0

        # Build initial context
        system_prompt = self.get_system_prompt(task)
        tool_defs = self.get_tool_definitions()

        context: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(task, default=str, ensure_ascii=False)},
        ]

        try:
            while iterations < self.max_iterations:
                if time.time() - start_time > self.timeout_seconds:
                    return {"status": "timeout", "result": None, "iterations": iterations}

                iterations += 1

                # Call LLM — if no LLM configured, return task directly
                if not self.llm_config.get("api_key"):
                    return self._handle_no_llm(task)

                response = self._call_llm(context, tool_defs)

                if response.get("is_tool_call"):
                    # Extract tool call
                    tool_name = response.get("tool_name", "")
                    tool_params = response.get("tool_params", {})

                    # Invariant 5: boundary discipline
                    if not self.invariants.check_boundary(
                        self.agent_id, tool_name,
                        {self.agent_id: self.allowed_tools},
                    ):
                        context.append({
                            "role": "tool",
                            "content": f"ERROR: Tool '{tool_name}' is not in your whitelist.",
                        })
                        continue

                    # Invariant 1: claim-before-work
                    call = MCPToolCall(
                        tool_name=tool_name,
                        params=tool_params,
                        caller_agent=self.agent_id,
                        correlation_id=self._current_correlation_id,
                    )
                    self._write_llm_call_event(tool_name, tool_params)

                    # Execute tool
                    result: MCPToolResult = self._dispatch_tool(call)

                    context.append({
                        "role": "assistant",
                        "content": response.get("thought", f"Calling {tool_name}"),
                    })
                    context.append({
                        "role": "tool",
                        "content": json.dumps({
                            "success": result.success,
                            "data": result.data,
                            "error": result.error,
                        }, default=str),
                    })

                elif response.get("is_final"):
                    return {
                        "status": "completed",
                        "result": response.get("content", {}),
                        "iterations": iterations,
                    }
                else:
                    # Continue reasoning
                    context.append({
                        "role": "assistant",
                        "content": response.get("content", ""),
                    })

        except Exception as e:
            self._write_error_event(str(e))
            return {"status": "failed", "result": str(e), "iterations": iterations}

        return {"status": "timeout", "result": None, "iterations": iterations}

    # ========== Internal ==========

    def _call_llm(self, context: List[Dict[str, Any]],
                   tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Call the LLM API.
        Returns: {"is_tool_call": bool, "is_final": bool, "content": ..., "tool_name": ..., "tool_params": ...}
        """
        import httpx
        import re

        config = self.llm_config
        try:
            resp = httpx.post(
                f"{config['base_url']}/chat/completions",
                headers={
                    "Authorization": f"Bearer {config['api_key']}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": config.get("model", "deepseek-chat"),
                    "messages": [{"role": m["role"], "content": m["content"]} for m in context],
                    "temperature": config.get("temperature", 0.1),
                    "max_tokens": config.get("max_tokens", 8000),
                    "tools": tools if tools else None,
                },
                timeout=60,
            )
            data = resp.json()

            message = data.get("choices", [{}])[0].get("message", {})
            content = message.get("content", "")
            tool_calls = message.get("tool_calls", [])

            if tool_calls:
                tc = tool_calls[0]
                fn = tc.get("function", {})
                return {
                    "is_tool_call": True,
                    "is_final": False,
                    "thought": content,
                    "tool_name": fn.get("name", ""),
                    "tool_params": json.loads(fn.get("arguments", "{}")),
                }

            # Try to parse structured JSON from content
            if content.strip().startswith("{"):
                try:
                    parsed = json.loads(content.strip())
                    if "tool_name" in parsed:
                        return {
                            "is_tool_call": True,
                            "is_final": False,
                            "thought": parsed.get("thought", ""),
                            "tool_name": parsed["tool_name"],
                            "tool_params": parsed.get("tool_params", {}),
                        }
                except json.JSONDecodeError:
                    pass

            return {"is_tool_call": False, "is_final": True, "content": content}

        except Exception as e:
            return {"is_tool_call": False, "is_final": True,
                    "content": json.dumps({"error": str(e)})}

    def _handle_no_llm(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback when no LLM is configured — return task as-is."""
        return {"status": "completed", "result": task, "iterations": 0,
                "note": "No LLM configured — returning task without processing"}

    def _dispatch_tool(self, call: MCPToolCall) -> MCPToolResult:
        """Dispatch tool call to the appropriate MCP server."""
        from veriaudit.mcp_servers.repo_mcp import RepoMCP
        from veriaudit.mcp_servers.build_mcp import BuildMCP
        from veriaudit.mcp_servers.sast_mcp import SASTMCP
        from veriaudit.mcp_servers.cpg_mcp import CPGMCP
        from veriaudit.mcp_servers.fuzz_mcp import FuzzMCP
        from veriaudit.mcp_servers.exploit_mcp import ExploitMCP
        from veriaudit.mcp_servers.evidence_mcp import EvidenceMCP
        from veriaudit.mcp_servers.report_mcp import ReportMCP

        server_map = {
            "repo_mcp": RepoMCP,
            "build_mcp": BuildMCP,
            "sast_mcp": SASTMCP,
            "cpg_mcp": CPGMCP,
            "fuzz_mcp": FuzzMCP,
            "exploit_mcp": ExploitMCP,
            "evidence_mcp": EvidenceMCP,
            "report_mcp": ReportMCP,
        }

        server_name = call.tool_name.split(".")[0]
        server_cls = server_map.get(server_name)

        if server_cls:
            server = server_cls()
            return server.handle_call(call)
        else:
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                success=False,
                error=f"No MCP server found for '{server_name}'",
            )

    def _write_llm_call_event(self, tool_name: str, params: Dict[str, Any]):
        """Write an agent.tool_call event to the ledger."""
        event = AuditEvent(
            correlation_id=self._current_correlation_id,
            event_type=EventType.AGENT_TOOL_CALL,
            agent_id=self.agent_id,
            payload={"tool_name": tool_name, "params": params},
        )
        self.ledger.append(event)

    def _write_error_event(self, error_msg: str):
        """Write an error.occurred event."""
        event = AuditEvent(
            correlation_id=self._current_correlation_id,
            event_type=EventType.ERROR_OCCURRED,
            agent_id=self.agent_id,
            payload={"error_message": error_msg},
        )
        self.ledger.append(event)

    def acquire_lock(self, finding_id: str) -> bool:
        """Try to acquire a lock on a finding."""
        if finding_id not in self._locks:
            self._locks[finding_id] = self.agent_id
            return True
        return self._locks[finding_id] == self.agent_id

    def release_lock(self, finding_id: str):
        self._locks.pop(finding_id, None)
