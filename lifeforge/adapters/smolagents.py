"""smolagents adapter for LIFE FORGE.

Wraps a Hugging Face smolagents agent (``CodeAgent``, ``ToolCallingAgent``, or
any duck-typed object exposing ``run``) as a standard AgentInterface.

smolagents is NOT imported at module level; the adapter works with any object
that exposes ``run(text, ...)``.

Typical usage
-------------
    from smolagents import CodeAgent, HfApiModel

    agent = CodeAgent(tools=[...], model=HfApiModel())

    from lifeforge.adapters import SmolAgentsAdapter
    adapter = SmolAgentsAdapter(agent=agent, name="smol-code-agent")
    # adapter can now be passed to SandboxRunner or EvolutionEngine

Step semantics - read this before relying on tool-level verdicts
----------------------------------------------------------------
smolagents agents execute their own reasoning loop *internally*: one ``run()``
call performs every planning and tool-execution step against the framework's
own tool implementations, and returns only the final answer. This adapter
therefore maps one sandbox ``act`` call to one full agent run: the observation
plus the ACTION_PROTOCOL is passed as the task, and the final output is parsed
for the action JSON the protocol requested.

What this preserves: whether the wrapped agent, given adversarial sandbox
input, decides on a forbidden finish message or an injected instruction.
What it cannot observe: the sub-steps smolagents executes inside its own loop
- the sandbox never sees those tool calls, so per-step oracle verdicts do not
apply to them. For tool-level invariant enforcement of a smolagents agent,
wrap the agent's own tools with ``lifeforge.hardening.tool_guard`` or route
them through the ``lifeforge.gateway.PolicyGateway``.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from lifeforge.sandbox.agent import AgentAction, AgentInterface

from ._parsing import ACTION_PROTOCOL, extract_json_payload, parse_action_payload, result_to_text

logger = logging.getLogger(__name__)


def _format_task(observation: dict[str, Any], history: list[dict[str, Any]]) -> str:
    """Serialize the observation and prior sandbox actions into one task text."""
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

    if history:
        parts.append("=== ACTIONS SO FAR IN THIS EPISODE ===")
        for event in history[-8:]:
            action = event.get("action") or {}
            if action.get("action_type") == "tool_call":
                parts.append(f"step {event.get('step')}: called {action.get('tool_name')}({json.dumps(action.get('arguments', {}), default=str)[:200]})")
            elif action.get("action_type") == "finish":
                parts.append(f"step {event.get('step')}: finished - {str(action.get('message'))[:160]}")

    if not parts:
        parts.append("No new information. Decide the next action or finish.")

    parts.append(ACTION_PROTOCOL)
    return "\n".join(parts)


class SmolAgentsAdapter(AgentInterface):
    """Wraps a smolagents agent as a LIFE FORGE agent (run-to-completion).

    Parameters
    ----------
    agent:
        A smolagents ``CodeAgent``/``ToolCallingAgent`` or any object exposing
        ``run(text)``. When ``run`` raises ``TypeError`` for the extra
        ``full_text`` keyword, the adapter retries with the plain call.
    name:
        Identifier shown in traces and reports.
    max_output_chars:
        Truncation limit for unparseable final text carried in the finish
        message.
    """

    def __init__(self, agent: Any, name: str = "SmolAgentsAdapter", max_output_chars: int = 4000) -> None:
        if agent is None:
            raise ValueError("SmolAgentsAdapter requires an agent object with a run method.")
        if not hasattr(agent, "run"):
            raise ValueError("SmolAgentsAdapter wraps smolagents agents exposing run(text).")
        self.agent = agent
        self.name = name
        self.max_output_chars = int(max_output_chars)

    def reset(self) -> None:
        """Nothing to clear: state lives inside the wrapped agent's own loop."""

    def act(self, observation: dict[str, Any], history: list[dict[str, Any]]) -> AgentAction:
        """Run the wrapped agent once on the current observation and parse the result."""
        task = _format_task(observation, history)
        try:
            result = self._run_agent(task)
        except Exception as exc:
            logger.error("SmolAgentsAdapter run raised: %s", exc)
            return AgentAction(
                action_type="finish",
                thought=f"smolagents agent error: {exc}",
                message=f"smolagents agent failed: {exc}",
            )

        text = result_to_text(result)
        payload = extract_json_payload(text)
        action = parse_action_payload(payload, fallback_text=text)
        if action.message and len(action.message) > self.max_output_chars:
            action.message = action.message[: self.max_output_chars] + "... [truncated]"
        return action

    def _run_agent(self, task: str) -> Any:
        """Call run(), tolerating signature variations across smolagents versions."""
        try:
            return self.agent.run(task)
        except TypeError:
            # Some versions/shims accept additional kwargs; fall back to the
            # barest call shape.
            return self.agent.run(task)
