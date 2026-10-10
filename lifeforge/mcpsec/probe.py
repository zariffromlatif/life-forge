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
import logging
import os
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

logger = logging.getLogger(__name__)

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


#: Largest single JSON-RPC message accepted from a server (stdio line or HTTP
#: body). A hostile server streaming an endless line cannot exhaust memory.
MAX_MESSAGE_BYTES = 16 * 1024 * 1024

#: Upper bound on ``tools/list`` pages followed via ``nextCursor``.
MAX_TOOL_PAGES = 100


def split_command(command: str) -> list[str]:
    """Split a command line into argv, preserving Windows backslash paths.

    POSIX ``shlex`` treats backslashes as escapes, turning
    ``C:\\tools\\srv.exe`` into ``C:toolssrv.exe``. On Windows the non-POSIX
    mode is used and surrounding quotes are stripped from each token.
    """
    if os.name != "nt":
        return shlex.split(command)
    tokens = shlex.split(command, posix=False)
    cleaned: list[str] = []
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
        cleaned.append(token)
    return cleaned


def _ids_match(candidate_id: Any, request_id: Any) -> bool:
    """JSON-RPC id equality, tolerating servers that echo ints as strings."""
    if candidate_id is None:
        return False
    return candidate_id == request_id or str(candidate_id) == str(request_id)


class StdioMcpTransport(McpTransport):
    """Line-delimited JSON-RPC over a subprocess (the MCP stdio transport)."""

    def __init__(self, command: str | list[str]) -> None:
        argv = split_command(command) if isinstance(command, str) else list(command)
        self.command = command
        popen_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True
        try:
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                **popen_kwargs,
            )
        except OSError as exc:
            raise McpProbeError(f"Cannot launch MCP server {argv!r}: {exc}") from exc
        self._responses: queue.Queue = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        """Continuously read server output lines into the response queue.

        Lines are read in bounded chunks: a line longer than
        :data:`MAX_MESSAGE_BYTES` is discarded rather than buffered whole.
        Non-object JSON (arrays, scalars) is dropped here so the client only
        ever sees dict messages.
        """
        assert self.process.stdout is not None
        stream = self.process.stdout
        try:
            while True:
                line = stream.readline(MAX_MESSAGE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_MESSAGE_BYTES and not line.endswith(b"\n"):
                    # Oversized: skip the remainder of this line.
                    while True:
                        rest = stream.readline(MAX_MESSAGE_BYTES)
                        if not rest or rest.endswith(b"\n"):
                            break
                    logger.debug("Discarded oversized MCP stdio message")
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue
                if isinstance(message, dict):
                    self._responses.put(message)
                elif isinstance(message, list):
                    # JSON-RPC batch: enqueue its object members.
                    for item in message:
                        if isinstance(item, dict):
                            self._responses.put(item)
        except (OSError, ValueError):
            pass
        self._responses.put(None)

    def send(self, payload: dict[str, Any]) -> None:
        """Write one JSON line to the server's stdin."""
        assert self.process.stdin is not None
        try:
            self.process.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
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
        """Terminate the server and every process it spawned.

        Launchers such as ``npx``/``uvx`` (and the ``.cmd`` shims on Windows)
        start the real server as a grandchild; terminating only the direct
        child leaves it running. The whole tree/process group is killed.
        """
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
        except (OSError, ValueError):
            pass
        if self.process.poll() is not None:
            return
        _kill_process_tree(self.process)


def _kill_process_tree(process: subprocess.Popen) -> None:
    """Terminate a process and its descendants, escalating to kill."""
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        import signal

        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - stubborn server
        if os.name != "nt":
            import signal

            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


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

    @staticmethod
    def _select_message(candidates: list[Any], request_id: Any) -> dict[str, Any] | None:
        """Return the JSON-RPC message answering ``request_id`` (None if absent).

        Server-initiated notifications and requests that precede the
        response on the same stream are skipped - taking the first message
        blindly let a server hand the scanner an empty result.
        """
        for candidate in candidates:
            if isinstance(candidate, list):
                found = HttpMcpTransport._select_message(candidate, request_id)
                if found is not None:
                    return found
            elif isinstance(candidate, dict):
                if request_id is None:
                    return candidate
                if _ids_match(candidate.get("id"), request_id) and ("result" in candidate or "error" in candidate):
                    return candidate
        return None

    @staticmethod
    def _parse_body(status: int, body: str, content_type: str, request_id: Any = None) -> dict[str, Any] | None:
        """Extract the JSON-RPC response for ``request_id`` from a JSON or SSE body."""
        if status == 202 or not body.strip():
            return None
        if "text/event-stream" in content_type:
            messages: list[Any] = []
            for event_data in _sse_events(body.splitlines()):
                try:
                    messages.append(json.loads(event_data))
                except json.JSONDecodeError:
                    continue
            return HttpMcpTransport._select_message(messages, request_id)
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise McpProbeError(f"MCP HTTP endpoint returned non-JSON body: {body[:120]!r}") from exc
        return HttpMcpTransport._select_message([parsed], request_id)

    def send(self, payload: dict[str, Any]) -> None:
        return None

    def receive(self, timeout: float) -> dict[str, Any]:
        raise McpProbeError("HttpMcpTransport is driven through request().")

    def request(self, payload: dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
        """POST one message and return its response (None for notifications/202).

        ``timeout`` bounds the WHOLE exchange, not each socket read: an SSE
        stream kept open with keepalive comments is abandoned at the deadline,
        and the body is capped at :data:`MAX_MESSAGE_BYTES`.
        """
        request_id = payload.get("id")
        is_notification = "id" not in payload
        deadline = time.monotonic() + timeout
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read(MAX_MESSAGE_BYTES).decode("utf-8", errors="replace")
            self._remember_session(dict(exc.headers or {}))
            if is_notification:
                return None
            return self._parse_body(exc.code, body, (exc.headers or {}).get("Content-Type", ""), request_id)
        except (urllib.error.URLError, OSError) as exc:
            raise McpProbeError(f"MCP HTTP endpoint unreachable: {exc}") from exc

        try:
            headers = dict(response.headers)
            self._remember_session(headers)
            content_type = response.headers.get("Content-Type", "") or ""
            if is_notification or response.status == 202:
                return None
            if "text/event-stream" in content_type:
                return self._read_sse_until_response(response, request_id, deadline)
            body = _read_bounded(response, deadline)
            return self._parse_body(response.status, body, content_type, request_id)
        finally:
            try:
                response.close()
            except OSError:
                pass

    def _remember_session(self, headers: dict[str, str]) -> None:
        session = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
        if session:
            self.session_id = session

    def _read_sse_until_response(self, response: Any, request_id: Any, deadline: float) -> dict[str, Any] | None:
        """Consume an SSE stream until the matching response, EOF, or the deadline."""
        lines: queue.Queue = queue.Queue()

        def pump() -> None:
            total = 0
            try:
                while True:
                    raw = response.readline(MAX_MESSAGE_BYTES + 1)
                    if not raw:
                        break
                    total += len(raw)
                    if total > MAX_MESSAGE_BYTES:
                        lines.put(McpProbeError("MCP HTTP response exceeded the size limit"))
                        return
                    lines.put(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
            except Exception as exc:  # closed at deadline: any read error ends the pump
                lines.put(exc)
                return
            lines.put(None)

        threading.Thread(target=pump, daemon=True).start()
        data_lines: list[str] = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpProbeError("MCP HTTP SSE stream produced no matching response before the timeout")
            try:
                item = lines.get(timeout=remaining)
            except queue.Empty as exc:
                raise McpProbeError("MCP HTTP SSE stream produced no matching response before the timeout") from exc
            if isinstance(item, McpProbeError):
                raise item
            if isinstance(item, Exception) or item is None:
                item = ""  # flush any pending event, then stop
                eof = True
            else:
                eof = False
            if item == "":
                if data_lines:
                    data = "\n".join(data_lines)
                    data_lines = []
                    try:
                        message = json.loads(data)
                    except json.JSONDecodeError:
                        message = None
                    found = self._select_message([message], request_id) if message is not None else None
                    if found is not None:
                        return found
                if eof:
                    return None
                continue
            if item.startswith("data:"):
                value = item[len("data:"):]
                data_lines.append(value[1:] if value.startswith(" ") else value)


def _sse_events(lines: list[str]):
    """Yield the joined ``data:`` payload of each SSE event in ``lines``."""
    data_lines: list[str] = []
    for line in list(lines) + [""]:
        if line == "":
            if data_lines:
                data = "\n".join(data_lines)
                data_lines = []
                if data.strip() and data.strip() != "[DONE]":
                    yield data
            continue
        if line.startswith("data:"):
            value = line[len("data:"):]
            data_lines.append(value[1:] if value.startswith(" ") else value)


def _read_bounded(response: Any, deadline: float) -> str:
    """Read a non-streaming body with a total deadline and a size cap."""
    result: queue.Queue = queue.Queue()

    def pump() -> None:
        try:
            result.put(response.read(MAX_MESSAGE_BYTES + 1))
        except Exception as exc:  # closed at deadline: any read error ends the pump
            result.put(exc)

    threading.Thread(target=pump, daemon=True).start()
    try:
        body = result.get(timeout=max(0.0, deadline - time.monotonic()))
    except queue.Empty as exc:
        raise McpProbeError("MCP HTTP response body not received before the timeout") from exc
    if isinstance(body, Exception):
        raise McpProbeError(f"MCP HTTP response could not be read: {body}") from body
    if len(body) > MAX_MESSAGE_BYTES:
        raise McpProbeError("MCP HTTP response exceeded the size limit")
    return body.decode("utf-8", errors="replace")


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
        request_id = self._next_request_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        if isinstance(self.transport, (InProcessMcpTransport, HttpMcpTransport)):
            response = self.transport.request(request, timeout=self.timeout)
        else:
            self.transport.send(request)
            # Some servers emit a reply to the notifications/initialized
            # notification, or stale messages land in the queue; only a
            # response carrying THIS request's id is acceptable. Anything else
            # is discarded and the read continues.
            response = None
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise McpProbeError(f"MCP server did not respond to '{method}' within {self.timeout:.0f}s")
                candidate = self.transport.receive(remaining)
                # A server-initiated request may reuse the same id number, so
                # only a message carrying result/error counts as the reply.
                if (
                    isinstance(candidate, dict)
                    and _ids_match(candidate.get("id"), request_id)
                    and ("result" in candidate or "error" in candidate)
                ):
                    response = candidate
                    break
                logger.debug("Discarding non-matching message while awaiting '%s': %s", method, str(candidate)[:120])

        if response is None:
            raise McpProbeError(f"MCP server returned no response to '{method}'")
        if not isinstance(response, dict):
            raise McpProbeError(f"MCP server sent a non-object response to '{method}'")
        if "error" in response:
            error = response["error"]
            if isinstance(error, dict):
                raise McpProbeError(
                    f"MCP server error on '{method}': {error.get('message', error)} (code {error.get('code')})"
                )
            raise McpProbeError(f"MCP server error on '{method}': {str(error)[:200]}")
        result = response.get("result")
        return result if isinstance(result, dict) else {}

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
        """Fetch and normalize the server's tool definitions, following pagination.

        ``tools/list`` is paginated via ``nextCursor``; reading only the first
        page let a server hide tools (and their poisoned descriptions) on
        later pages. Pages are followed up to :data:`MAX_TOOL_PAGES`, and a
        repeated cursor ends the walk.
        """
        raw_tools: list[Any] = []
        cursor: Any = None
        seen_cursors: set[str] = set()
        for _ in range(MAX_TOOL_PAGES):
            result = self._send_request("tools/list", {"cursor": cursor} if cursor is not None else None)
            page = result.get("tools")
            if isinstance(page, list):
                raw_tools.extend(page)
            cursor = result.get("nextCursor")
            if cursor in (None, "") or str(cursor) in seen_cursors:
                break
            seen_cursors.add(str(cursor))
        else:
            raise McpProbeError(f"MCP server paginated tools/list beyond {MAX_TOOL_PAGES} pages")
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
    probe_tool: str | None = None,
    probe_arguments: dict[str, Any] | None = None,
) -> tuple[McpServerManifest, list[McpToolDefinition]]:
    """Connect, handshake, fetch tools twice, and return (manifest, drift diff).

    The second fetch exists for rug-pull detection: a server that mutates its
    definitions between approval-time and use-time will differ across the two
    observations even without a stored baseline. Pass
    ``drift_delay_seconds`` to widen the observation window.

    When ``probe_tool`` is named, that single tool is executed on the target
    after the scan fetches and its response recorded as evidence. This is
    strictly opt-in - the caller owns the blast radius of executing a tool on
    a live server.
    """
    client = McpClient(transport, client_name=client_name, timeout=timeout)
    try:
        client.initialize()
        tools = client.list_tools()
        if drift_delay_seconds > 0:
            time.sleep(drift_delay_seconds)
        tools_again = client.list_tools()

        probe_result: dict[str, Any] | None = None
        if probe_tool:
            started = time.monotonic()
            try:
                response = client.call_tool(probe_tool, dict(probe_arguments or {}))
                probe_result = {
                    "tool": probe_tool,
                    "arguments": dict(probe_arguments or {}),
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "response": response,
                    "error": None,
                }
            except McpProbeError as exc:
                probe_result = {
                    "tool": probe_tool,
                    "arguments": dict(probe_arguments or {}),
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "response": None,
                    "error": str(exc),
                }
    finally:
        client.close()

    manifest = McpServerManifest(
        tools=tools,
        server_info=client.server_info,
        source=f"live:{getattr(transport, 'url', getattr(transport, 'command', 'in-process'))}",
        protocol_version=client.protocol_version,
        probe_result=probe_result,
    )
    return manifest, tools_again
