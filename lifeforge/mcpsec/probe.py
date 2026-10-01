"""Live probing of MCP servers over stdio and HTTP.

The probe speaks the MCP JSON-RPC dialect used by this repository's own server
(line-delimited JSON over stdio; JSON or SSE responses over HTTP): it performs
the ``initialize`` handshake, fetches ``tools/list``, and - never by default -
can exercise a single named tool for evidence.

A transport abstraction separates the protocol client from I/O, so the whole
probe layer is testable in-process against :class:`~lifeforge.sandbox.mcp_server.LifeForgeMCPServer`
without spawning subprocesses.
"""
from __future__ import annotations

import json
import queue
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from .manifest import McpServerManifest, McpToolDefinition, tools_from_wire

#: Default timeout for one protocol round-trip, in seconds.
DEFAULT_TIMEOUT = 15.0


class McpProbeError(RuntimeError):
    """Raised when a live probe cannot complete (handshake, transport, protocol)."""


class McpTransport(ABC):
    """Request/response framing for one MCP connection."""

    @abstractmethod
    def send(self, payload: dict[str, Any]) -> None:
        """Send one JSON-RPC message (request or notification)."""
        raise NotImplementedError

    @abstractmethod
    def receive(self, timeout: float) -> dict[str, Any]:
        """Receive the next JSON-RPC message, or raise on timeout."""
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - default no-op
        """Release the connection."""
        return None


class InProcessMcpTransport(McpTransport):
    """Transport that delegates to a server object's ``handle_jsonrpc``.

    Used by tests and by scans of a server object the caller already holds.
    Notifications produce no response, matching the stdio contract.
    """

    def __init__(self, server: Any) -> None:
        self.server = server

    def send(self, payload: dict[str, Any]) -> None:
        return None

    def receive(self, timeout: float) -> dict[str, Any]:
        raise McpProbeError(
            "InProcessMcpTransport is driven through request(); call client.request_* methods."
        )

    def request(self, payload: dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
        """Execute one message synchronously and return the server's response.

        ``timeout`` is accepted for interface parity with the HTTP transport
        and is inherently satisfied: the in-process call is synchronous.
        """
        response = self.server.handle_jsonrpc(payload)
        return response or None


class StdioMcpTransport(McpTransport):
    """Line-delimited JSON-RPC over a subprocess (the MCP stdio transport)."""

    def __init__(self, command: str | list[str]) -> None:
        argv = shlex.split(command) if isinstance(command, str) else list(command)
        try:
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise McpProbeError(f"Cannot launch MCP server {argv!r}: {exc}") from exc
        self._responses: queue.Queue = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        """Continuously read server output lines into the response queue."""
        assert self.process.stdout is not None
        for line in self.process.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._responses.put(json.loads(line))
            except json.JSONDecodeError:
                continue
        self._responses.put(None)

    def send(self, payload: dict[str, Any]) -> None:
        """Write one JSON line to the server's stdin."""
        assert self.process.stdin is not None
        try:
            self.process.stdin.write(json.dumps(payload) + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise McpProbeError(f"MCP server closed stdin: {exc}") from exc

    def receive(self, timeout: float) -> dict[str, Any]:
        """Pull the next response, or raise McpProbeError on timeout/exit."""
        try:
            item = self._responses.get(timeout=timeout)
        except queue.Empty as exc:
            raise McpProbeError(f"MCP server did not respond within {timeout:.0f}s") from exc
        if item is None:
            raise McpProbeError("MCP server exited before the scan completed")
        return item

    def close(self) -> None:
        """Terminate the subprocess."""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - stubborn server
                self.process.kill()


class HttpMcpTransport(McpTransport):
    """JSON-RPC over HTTP (the MCP Streamable HTTP transport, request/response mode).

    Sends each message as a POST; accepts either a JSON body or a
    ``text/event-stream`` body with ``data:`` lines, and carries the server's
    ``Mcp-Session-Id`` on subsequent requests.
    """

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.session_id: str | None = None
        self.extra_headers = dict(headers or {})

    def _headers(self) -> dict[str, str]:
        request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.extra_headers,
        }
        if self.session_id:
            request_headers["Mcp-Session-Id"] = self.session_id
        return request_headers

    def _post(self, payload: dict[str, Any], timeout: float) -> tuple[int, str, dict[str, str]]:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read().decode("utf-8"), dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers or {})
        except (urllib.error.URLError, OSError) as exc:
            raise McpProbeError(f"MCP HTTP endpoint unreachable: {exc}") from exc

    @staticmethod
    def _parse_body(status: int, body: str, content_type: str) -> dict[str, Any] | None:
        """Extract one JSON-RPC response from a JSON or SSE body."""
        if status == 202 or not body.strip():
            return None
        if "text/event-stream" in content_type:
            for line in body.splitlines():
                if line.startswith("data:"):
                    data = line[len("data:"):].strip()
                    if data and data != "[DONE]":
                        return json.loads(data)
            return None
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise McpProbeError(f"MCP HTTP endpoint returned non-JSON body: {body[:120]!r}") from exc
        return parsed if isinstance(parsed, dict) else None

    def send(self, payload: dict[str, Any]) -> None:
        return None

    def receive(self, timeout: float) -> dict[str, Any]:
        raise McpProbeError("HttpMcpTransport is driven through request().")

    def request(self, payload: dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
        """POST one message and return the parsed response (None for 202/empty)."""
        status, body, headers = self._post(payload, timeout)
        session = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
        if session:
            self.session_id = session
        return self._parse_body(status, body, headers.get("Content-Type", ""))


class McpClient:
    """Minimal MCP client: handshake, tool listing, optional single tool call.

    The client never executes tools unless explicitly asked - a scanner that
    fires destructive calls while looking for dangerous tools would be the
    vulnerability it claims to find.
    """

    def __init__(self, transport: Any, *, client_name: str = "lifeforge-mcpsec", timeout: float = DEFAULT_TIMEOUT) -> None:
        self.transport = transport
        self.client_name = client_name
        self.timeout = timeout
        self._next_id = 0
        self.server_info: dict[str, Any] = {}
        self.protocol_version = ""

    # ------------------------------------------------------------------
    # Framing
    # ------------------------------------------------------------------

    def _next_request_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request = {
            "jsonrpc": "2.0",
            "id": self._next_request_id(),
            "method": method,
            "params": params or {},
        }
        if isinstance(self.transport, (InProcessMcpTransport, HttpMcpTransport)):
            response = self.transport.request(request, timeout=self.timeout)
        else:
            self.transport.send(request)
            response = self.transport.receive(self.timeout)

        if response is None:
            raise McpProbeError(f"MCP server returned no response to '{method}'")
        if "error" in response:
            error = response["error"]
            raise McpProbeError(
                f"MCP server error on '{method}': {error.get('message', error)} (code {error.get('code')})"
            )
        return response.get("result") or {}

    def _send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        notification = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if isinstance(self.transport, (InProcessMcpTransport, HttpMcpTransport)):
            self.transport.request(notification, timeout=self.timeout)
        else:
            self.transport.send(notification)

    # ------------------------------------------------------------------
    # Protocol
    # ------------------------------------------------------------------

    def initialize(self) -> dict[str, Any]:
        """Perform the MCP handshake and record the server's identity."""
        result = self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": self.client_name, "version": "1.0.0"},
            },
        )
        self.server_info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
        self.protocol_version = str(result.get("protocolVersion", ""))
        self._send_notification("notifications/initialized")
        return result

    def list_tools(self) -> list[McpToolDefinition]:
        """Fetch and normalize the server's tool definitions."""
        result = self._send_request("tools/list")
        raw_tools = result.get("tools") if isinstance(result.get("tools"), list) else []
        server_name = str(self.server_info.get("name", "server")) if self.server_info else "server"
        return tools_from_wire(raw_tools, server=server_name)

    def ping(self) -> bool:
        """Protocol-level liveness check (never executes a tool)."""
        try:
            self._send_request("ping")
            return True
        except McpProbeError:
            return False

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Exercise one named tool. Opt-in only; the caller owns the blast radius."""
        result = self._send_request("tools/call", {"name": tool_name, "arguments": arguments})
        return result

    def close(self) -> None:
        """Release the transport."""
        self.transport.close()


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


def probe_server_manifest(
    transport: Any,
    *,
    client_name: str = "lifeforge-mcpsec",
    timeout: float = DEFAULT_TIMEOUT,
    drift_delay_seconds: float = 0.0,
) -> tuple[McpServerManifest, list[McpToolDefinition]]:
    """Connect, handshake, fetch tools twice, and return (manifest, drift diff).

    The second fetch exists for rug-pull detection: a server that mutates its
    definitions between approval-time and use-time will differ across the two
    observations even without a stored baseline. Pass
    ``drift_delay_seconds`` to widen the observation window.
    """
    client = McpClient(transport, client_name=client_name, timeout=timeout)
    try:
        client.initialize()
        tools = client.list_tools()
        if drift_delay_seconds > 0:
            time.sleep(drift_delay_seconds)
        tools_again = client.list_tools()
    finally:
        client.close()

    manifest = McpServerManifest(
        tools=tools,
        server_info=client.server_info,
        source=f"live:{getattr(transport, 'url', getattr(transport, 'command', 'in-process'))}",
        protocol_version=client.protocol_version,
    )
    return manifest, tools_again
