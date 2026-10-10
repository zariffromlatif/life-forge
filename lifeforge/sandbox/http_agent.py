"""HTTP webhook adapter for evaluating external agents running as microservices."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from lifeforge.sandbox.agent import AgentAction, AgentInterface


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only within the same scheme and host.

    Custom headers (often an Authorization token) are attached to every
    request; following a redirect to another host would hand them to it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise urllib.error.HTTPError(
                req.full_url, code, f"refusing cross-host redirect to {new.netloc}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirectHandler)


class HTTPAgentAdapter(AgentInterface):
    """
    Adapts any external agent exposed via an HTTP REST endpoint into an AgentInterface.

    Enables testing agents written in any language (Python, TypeScript, Go, Java)
    running in local Docker containers or remote test clusters.
    """

    def __init__(
        self,
        endpoint: str,
        reset_endpoint: str | None = None,
        name: str = "HTTPAgent",
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.reset_endpoint = reset_endpoint
        self.name = name
        self.timeout = timeout
        self.headers = headers or {}
        self.step_count = 0

    def reset(self) -> None:
        """Signal episode reset to remote agent if reset endpoint is configured."""
        self.step_count = 0
        if not self.reset_endpoint:
            return

        try:
            req_headers = {"Content-Type": "application/json", **self.headers}
            req = urllib.request.Request(
                self.reset_endpoint,
                data=b"{}",
                headers=req_headers,
                method="POST",
            )
            with _OPENER.open(req, timeout=self.timeout) as resp:
                pass
        except Exception:
            # Non-fatal if remote agent does not maintain external episode state
            pass

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        """Post current observation to remote webhook and convert response to AgentAction."""
        self.step_count += 1
        payload = {
            "observation": observation,
            "history": history,
            "step": self.step_count,
        }

        data_bytes = json.dumps(payload, default=str).encode("utf-8")
        req_headers = {
            "Content-Type": "application/json",
            "User-Agent": "LIFE-FORGE-Agent-Evaluator/0.4",
            **self.headers,
        }

        req = urllib.request.Request(
            self.endpoint,
            data=data_bytes,
            headers=req_headers,
            method="POST",
        )

        try:
            with _OPENER.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                res_data = json.loads(body)
                return self._parse_action_response(res_data)
        # Transport failures are reported as "error", never "finish": a dead or
        # misconfigured endpoint has not demonstrated safe behaviour, and
        # scoring it as a clean stop would rank a broken agent as resilient.
        except urllib.error.HTTPError as http_err:
            return AgentAction(
                action_type="error",
                thought=f"Remote agent HTTP Error {http_err.code}: {http_err.reason}",
                message=f"HTTP Webhook failure: {http_err.code} {http_err.reason}",
            )
        except Exception as exc:
            return AgentAction(
                action_type="error",
                thought=f"Remote agent communication error: {exc}",
                message=f"Webhook connection failure: {exc}",
            )

    def _parse_action_response(self, data: dict[str, Any]) -> AgentAction:
        """Normalize varied JSON action schemas from external agents into AgentAction."""
        if not isinstance(data, dict):
            return AgentAction(
                action_type="error",
                thought="Remote agent returned a non-object JSON payload.",
                message="Remote agent returned a non-object JSON payload.",
            )

        # 1. Determine action type
        action_type = data.get("action_type") or data.get("action") or data.get("type", "tool_call")
        if action_type in ("finish", "complete", "stop"):
            action_type = "finish"
        elif action_type in ("message", "chat"):
            action_type = "message"
        else:
            action_type = "tool_call"

        # 2. Extract tool name
        tool_name = data.get("tool_name") or data.get("tool") or data.get("name")

        # 3. Extract arguments
        arguments = data.get("arguments") or data.get("args") or data.get("parameters") or {}
        if not isinstance(arguments, dict):
            arguments = {}

        # 4. Extract thought / reasoning
        thought = data.get("thought") or data.get("rationale") or data.get("reasoning")

        # 5. Extract message
        message = data.get("message") or data.get("content") or data.get("output")

        return AgentAction(
            action_type=action_type,
            tool_name=tool_name,
            arguments=arguments,
            thought=thought,
            message=message,
        )
