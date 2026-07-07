# VeriAudit - Base MCP Server
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from veriaudit.core.schema import MCPToolCall, MCPToolResult


class BaseMCP(ABC):
    """Base class for all MCP servers."""

    @property
    @abstractmethod
    def server_name(self) -> str:
        """e.g. "sast_mcp", "fuzz_mcp" """
        ...

    def handle_call(self, call: MCPToolCall) -> MCPToolResult:
        """
        Dispatch a tool call to the appropriate method.

        Args:
            call: MCPToolCall from an agent.
                  call.tool_name format: "server_name.method_name"

        Returns:
            MCPToolResult
        """
        start = time.time()

        # Extract method name
        tool_name = call.tool_name
        prefix = f"{self.server_name}."
        if tool_name.startswith(prefix):
            method_name = tool_name[len(prefix):]
        else:
            method_name = tool_name

        # Find and call the method
        method = getattr(self, method_name, None)

        if method is None:
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=tool_name,
                success=False,
                error=f"Unknown tool: {tool_name}",
                duration_ms=0,
            )

        try:
            data = method(**call.params)
            duration_ms = int((time.time() - start) * 1000)
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=tool_name,
                success=True,
                data=data if isinstance(data, dict) else {"result": data},
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.time() - start) * 1000)
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=tool_name,
                success=False,
                error=str(e),
                duration_ms=duration_ms,
            )

    @abstractmethod
    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        """
        Return OpenAI-compatible tool definitions for LLM use.
        Each tool dict has: name, description, parameters (JSON Schema).
        """
        ...
