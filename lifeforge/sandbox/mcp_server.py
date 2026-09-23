"""MCP Server -- exposes the LIFE FORGE sandbox as a Model Context Protocol server.

This allows any MCP-compatible client (Claude Desktop, Cursor, LangGraph agents,
custom MCP clients) to connect to the sandbox and interact with the simulated
enterprise environment through standard JSON-RPC tool calls.

The server:
  - Publishes all sandbox tools as MCP tools
  - Maintains a stateful WorldState across tool calls
  - Injects adversarial mutations on-the-fly via configured mutators
  - Records a complete simulation trace for post-hoc analysis
  - Supports stdio and SSE transports

Usage (CLI):
    lifeforge mcp-serve --transport stdio
    lifeforge mcp-serve --transport sse --port 8080

Usage (programmatic):
    from lifeforge.sandbox.mcp_server import LifeForgeMCPServer
    server = LifeForgeMCPServer()
    server.run_stdio()
"""
from __future__ import annotations

import copy
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .mock_tools import ToolRegistry, ToolResult
from .world_state import WorldState

logger = logging.getLogger(__name__)


def _check_mcp() -> Any:
    """Lazy-import the MCP SDK with a clear error if missing."""
    try:
        import mcp.server
        import mcp.types
        return mcp
    except ImportError:
        raise ImportError(
            "The MCP SDK is required for the LIFE FORGE MCP server. Install it with:\n"
            "  pip install 'lifeforge[mcp]'\n"
            "  # or: pip install mcp"
        )


# ---------------------------------------------------------------------------
# Lightweight standalone server (no MCP SDK dependency)
# ---------------------------------------------------------------------------

@dataclass
class MCPToolCall:
    """Represents a single tool call received from an MCP client."""
    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""


@dataclass
class MCPServerConfig:
    """Configuration for the LIFE FORGE MCP server."""
    server_name: str = "lifeforge-sandbox"
    server_version: str = "0.1.0"
    enable_mutations: bool = False
    mutation_probability: float = 0.3
    max_steps: int = 50


class LifeForgeMCPServer:
    """LIFE FORGE sandbox exposed as an MCP-compatible tool server.

    This is the core server implementation. It handles:
    1. Tool listing -- publishes all registered sandbox tools
    2. Tool execution -- dispatches calls against the sandbox WorldState
    3. State management -- maintains deterministic state across calls
    4. Trace recording -- logs every call for post-hoc analysis
    5. Optional mutation -- can inject adversarial perturbations mid-session

    The server can be used standalone (via the JSON-RPC handler methods)
    or wrapped with the MCP SDK's stdio/SSE transports.
    """

    def __init__(
        self,
        config: MCPServerConfig | None = None,
        tool_registry: ToolRegistry | None = None,
        initial_state: WorldState | None = None,
        mutators: list[Any] | None = None,
    ) -> None:
        self.config = config or MCPServerConfig()
        self.tool_registry = tool_registry or ToolRegistry.default_purchasing_registry()
        self.state = initial_state or WorldState.default_purchasing_world()
        self._initial_state = self.state.snapshot()
        self._mutators = mutators or []
        self._trace: list[dict[str, Any]] = []
        self._step_count = 0
        self._rng: Any = None  # Lazy import random

    # -----------------------------------------------------------------
    # MCP Protocol Methods
    # -----------------------------------------------------------------

    def handle_initialize(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Handle MCP initialize request."""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.config.server_name,
                "version": self.config.server_version,
            },
        }

    def handle_list_tools(self) -> list[dict[str, Any]]:
        """Return tool definitions in MCP format."""
        tools = []
        for tool in self.tool_registry.list_tools():
            tools.append({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.parameters_schema,
            })
        return tools

    def handle_call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a tool call against the sandbox state."""
        self._step_count += 1
        self.state.step_count = self._step_count
        args = arguments or {}

        # Optionally apply mutations before executing
        if self.config.enable_mutations and self._mutators:
            self._maybe_apply_mutation()

        # Dispatch tool
        result = self.tool_registry.dispatch(tool_name, self.state, args)

        # Record trace
        trace_entry = {
            "step": self._step_count,
            "tool_name": tool_name,
            "arguments": copy.deepcopy(args),
            "result": {
                "success": result.success,
                "output": copy.deepcopy(result.output),
                "error": result.error,
                "cost": result.cost,
            },
        }
        self._trace.append(trace_entry)

        # Format as MCP tool result
        if result.success:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result.output, indent=2, default=str),
                    }
                ],
                "isError": False,
            }
        else:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Error: {result.error}",
                    }
                ],
                "isError": True,
            }

    def _maybe_apply_mutation(self) -> None:
        """Probabilistically apply an adversarial mutation to the world state."""
        import random as _random
        if self._rng is None:
            self._rng = _random.Random(42)

        if self._rng.random() < self.config.mutation_probability:
            mutator = self._rng.choice(self._mutators)
            self.state = mutator.mutate(self.state, self._rng)
            logger.info("Applied mutation: %s at step %d", mutator.name, self._step_count)

    # -----------------------------------------------------------------
    # JSON-RPC Handler
    # -----------------------------------------------------------------

    def handle_jsonrpc(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle a raw JSON-RPC 2.0 request and return the response."""
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id")

        try:
            if method == "initialize":
                result = self.handle_initialize(params)
            elif method == "tools/list":
                result = {"tools": self.handle_list_tools()}
            elif method == "tools/call":
                result = self.handle_call_tool(
                    tool_name=params.get("name", ""),
                    arguments=params.get("arguments"),
                )
            elif method == "notifications/initialized":
                # Client acknowledgement -- no response needed
                return {}
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}",
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }

        except Exception as exc:
            logger.exception("Error handling MCP request: %s", method)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": str(exc),
                },
            }

    # -----------------------------------------------------------------
    # Transport: stdio
    # -----------------------------------------------------------------

    def run_stdio(self) -> None:
        """Run the server on stdio (line-delimited JSON-RPC).

        Reads JSON-RPC requests from stdin and writes responses to stdout.
        This is the standard MCP stdio transport.
        """
        import sys

        logger.info("LIFE FORGE MCP Server starting on stdio...")

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                sys.stdout.write(json.dumps(error_response) + "\n")
                sys.stdout.flush()
                continue

            response = self.handle_jsonrpc(request)
            if response:  # Notifications return empty dict
                sys.stdout.write(json.dumps(response, default=str) + "\n")
                sys.stdout.flush()

    # -----------------------------------------------------------------
    # State Management
    # -----------------------------------------------------------------

    def reset(self) -> None:
        """Reset the server to its initial state."""
        self.state = self._initial_state.snapshot()
        self._trace = []
        self._step_count = 0

    def get_trace(self) -> list[dict[str, Any]]:
        """Return the complete recorded trace."""
        return copy.deepcopy(self._trace)

    def get_state_snapshot(self) -> dict[str, Any]:
        """Return the current world state as a dictionary."""
        return self.state.to_dict()

    # -----------------------------------------------------------------
    # MCP SDK Integration (optional, for full MCP compliance)
    # -----------------------------------------------------------------

    def create_mcp_app(self) -> Any:
        """Create a full MCP Server application using the MCP SDK.

        Returns an mcp.server.Server instance configured with all
        sandbox tools. Requires the `mcp` package to be installed.

        Usage:
            server = LifeForgeMCPServer()
            app = server.create_mcp_app()
            # Then run with mcp.server.stdio.run_server(app)
        """
        mcp_mod = _check_mcp()
        from mcp.server import Server
        import mcp.types as types

        app = Server(self.config.server_name)

        @app.list_tools()
        async def list_tools() -> list[types.Tool]:
            tool_list = self.handle_list_tools()
            return [
                types.Tool(
                    name=t["name"],
                    description=t["description"],
                    inputSchema=t["inputSchema"],
                )
                for t in tool_list
            ]

        @app.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any] | None = None
        ) -> list[types.TextContent]:
            result = self.handle_call_tool(name, arguments)
            contents = result.get("content", [])
            return [
                types.TextContent(type="text", text=c.get("text", ""))
                for c in contents
            ]

        return app
