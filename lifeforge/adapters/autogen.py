"""AutoGen adapter for LIFE FORGE.

Wraps a Microsoft AutoGen conversational agent (``ConversableAgent`` or any
duck-typed object exposing ``generate_reply``) as a standard AgentInterface so
it can be evaluated inside the sandbox step loop.

AutoGen is NOT imported at module level; the adapter works with any object
that exposes the reply interface, so LIFE FORGE stays importable without
autogen installed.

Typical usage
-------------
    import autogen  # your existing configuration

    assistant = autogen.AssistantAgent(name="procurement", llm_config=...)
    user_proxy = autogen.UserProxyAgent(name="user", human_input_mode="NEVER")

    from lifeforge.adapters import AutoGenAdapter
    adapter = AutoGenAdapter(agent=assistant, name="autogen-procurement")
    # adapter can now be passed to SandboxRunner or EvolutionEngine

Step semantics
--------------
AutoGen agents are step-drivable: each ``generate_reply`` call produces one
reply - either text (parsed against the shared ACTION_PROTOCOL) or a dict
carrying ``tool_calls`` in AutoGen's native shape, which is mapped directly to
a tool_call action. The adapter maintains the conversation history across
``act`` calls and clears it on ``reset``.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from lifeforge.sandbox.agent import AgentAction, AgentInterface

from ._parsing import ACTION_PROTOCOL, extract_json_payload, parse_action_payload, result_to_text

logger = logging.getLogger(__name__)


def _format_observation(observation: dict[str, Any]) -> str:
    """Serialize a sandbox observation into readable message text."""
    parts: list[str] = []

    inbox: list[dict[str, Any]] = observation.get("inbox") or []
    if inbox:
        parts.append("=== INBOX ===")
        for message in inbox:
            parts.append(f"From: {message.get('from', 'unknown')} | Subject: {message.get('subject', '')}")
            parts.append(str(message.get("body", "")))

    last_result = observation.get("last_tool_result")
    if last_result is not None:
        parts.append("=== LAST TOOL RESULT ===")
        parts.append(json.dumps(last_result, indent=2, default=str))

    if not parts:
        parts.append("No new information. Decide the next action or finish.")

    parts.append(ACTION_PROTOCOL)
    return "\n".join(parts)


class AutoGenAdapter(AgentInterface):
    """Wraps an AutoGen agent as a LIFE FORGE agent.

    Parameters
    ----------
    agent:
        An AutoGen agent (``ConversableAgent``/``AssistantAgent``) or any
        object exposing ``generate_reply(messages=..., sender=...)``. When
        ``generate_reply`` raises ``TypeError`` for the ``sender`` keyword,
        the adapter retries without it.
    name:
        Identifier shown in traces and reports.
    """

    def __init__(self, agent: Any, name: str = "AutoGenAdapter") -> None:
        if agent is None:
            raise ValueError("AutoGenAdapter requires an agent object with a generate_reply method.")
        if not hasattr(agent, "generate_reply"):
            raise ValueError(
                "AutoGenAdapter wraps AutoGen agents exposing generate_reply(messages=...). "
                "For run-to-completion frameworks use the dedicated adapters instead."
            )
        self.agent = agent
        self.name = name
        self._messages: list[dict[str, str]] = []

    def reset(self) -> None:
        """Clear the per-episode conversation history."""
        self._messages = []

    def act(self, observation: dict[str, Any], history: list[dict[str, Any]]) -> AgentAction:
        """Send the observation as a user message and parse the agent's reply."""
        text = _format_observation(observation)
        self._messages.append({"role": "user", "content": text})

        try:
            reply = self._generate_reply()
        except Exception as exc:
            logger.error("AutoGenAdapter generate_reply raised: %s", exc)
            return AgentAction(
                action_type="finish",
                thought=f"AutoGen agent error: {exc}",
                message=f"AutoGen agent failed: {exc}",
            )

        self._messages.append({"role": "assistant", "content": result_to_text(reply)[:8000]})

        # Native AutoGen tool-call replies arrive as dicts with tool_calls.
        if isinstance(reply, dict) and reply.get("tool_calls"):
            action = self._action_from_tool_calls(reply["tool_calls"])
            if action is not None:
                return action

        content = result_to_text(reply)
        payload = extract_json_payload(content)
        return parse_action_payload(payload, fallback_text=content)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _generate_reply(self) -> Any:
        """Call generate_reply, tolerating signature variations across versions."""
        try:
            return self.agent.generate_reply(messages=self._messages, sender=None)
        except TypeError:
            return self.agent.generate_reply(messages=self._messages)

    @staticmethod
    def _action_from_tool_calls(tool_calls: list[Any]) -> AgentAction | None:
        """Map AutoGen's tool_calls structure to a tool_call action.

        Handles both the modern OpenAI-style shape
        ``{"id": ..., "function": {"name": ..., "arguments": "..."}}`` and the
        flat ``{"name": ..., "arguments": {...}}`` shape.
        """
        if not tool_calls:
            return None
        call = tool_calls[0]
        if isinstance(call, dict):
            function = call.get("function") or {}
            tool_name = function.get("name") or call.get("name")
            raw_args = function.get("arguments", call.get("arguments"))
        else:
            function = getattr(call, "function", None)
            tool_name = getattr(function, "name", None) or getattr(call, "name", None)
            raw_args = getattr(function, "arguments", None)

        if not isinstance(tool_name, str) or not tool_name.strip():
            return None

        if isinstance(raw_args, str):
            try:
                arguments: dict[str, Any] = json.loads(raw_args)
                if not isinstance(arguments, dict):
                    arguments = {"raw": raw_args}
            except json.JSONDecodeError:
                arguments = {"raw": raw_args}
        elif isinstance(raw_args, dict):
            arguments = dict(raw_args)
        else:
            arguments = {}

        return AgentAction(
            action_type="tool_call",
            tool_name=tool_name.strip(),
            arguments=arguments,
            thought=f"AutoGen selected tool: {tool_name.strip()}",
        )
