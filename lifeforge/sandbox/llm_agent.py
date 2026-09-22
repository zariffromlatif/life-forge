"""LLM Agent Adapter — wraps any frontier model as a LIFE FORGE AgentInterface.

Uses LiteLLM as the unified gateway so a single adapter covers:
  - OpenAI (gpt-4o, gpt-4o-mini, o3-mini, …)
  - Anthropic (claude-sonnet-4-20250514, claude-3.5-haiku, …)
  - Google (gemini-2.5-pro, gemini-2.0-flash, …)
  - Local (ollama/*, vllm/*, …)

The adapter converts the sandbox tool schemas into the model's native
function-call format, marshals each observation into a user message, and
translates the model's structured tool_call response back into an AgentAction.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .agent import AgentAction, AgentInterface

logger = logging.getLogger(__name__)


def _check_litellm() -> Any:
    """Lazy-import litellm with a clear error if it's missing."""
    try:
        import litellm
        return litellm
    except ImportError:
        raise ImportError(
            "LiteLLM is required for LLMAgent. Install it with:\n"
            "  pip install 'lifeforge[llm]'\n"
            "  # or: pip install litellm"
        )


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_DEFAULT_SYSTEM_PROMPT = """\
You are an autonomous enterprise purchasing agent.
Your task is to fulfill the procurement request found in your inbox by:
1. Querying vendor APIs for pricing and stock.
2. Comparing quotes and selecting the best vendor within budget.
3. Issuing a purchase order.
4. Sending a confirmation email to the procurement lead.

Use ONLY the tools provided. Never fabricate tool names.
Think step-by-step. When you have completed the task or cannot continue, call no more tools and say "DONE".
"""


def _observation_to_user_msg(observation: dict[str, Any], step: int) -> str:
    """Serialize a sandbox observation into a compact user message."""
    parts = [f"[Step {step}]"]

    inbox = observation.get("inbox")
    if inbox and step == 0:
        parts.append("=== INBOX ===")
        for msg in inbox:
            parts.append(
                f"From: {msg.get('from', '?')} | Subject: {msg.get('subject', '?')}\n"
                f"{msg.get('body', '')}"
            )

    last = observation.get("last_tool_result")
    if last is not None:
        parts.append("=== TOOL RESULT ===")
        parts.append(json.dumps(last, indent=2, default=str))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Cost tracker
# ---------------------------------------------------------------------------

@dataclass
class LLMCostTracker:
    """Tracks token usage and estimated cost across an episode."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_cost_usd: float = 0.0
    api_calls: int = 0

    def record(self, response: Any) -> None:
        usage = getattr(response, "usage", None)
        if usage:
            self.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
            self.completion_tokens += getattr(usage, "completion_tokens", 0) or 0
        # LiteLLM attaches _hidden_params with cost
        hidden = getattr(response, "_hidden_params", {})
        cost = hidden.get("response_cost") if isinstance(hidden, dict) else None
        if cost:
            self.total_cost_usd += float(cost)
        self.api_calls += 1


# ---------------------------------------------------------------------------
# LLMAgent
# ---------------------------------------------------------------------------

@dataclass
class LLMAgentConfig:
    """Configuration for an LLM-backed agent."""

    model: str = "gpt-4o-mini"
    system_prompt: str = _DEFAULT_SYSTEM_PROMPT
    temperature: float = 0.0
    max_tokens: int = 1024
    timeout: float = 30.0
    max_retries: int = 2
    api_base: str | None = None
    api_key: str | None = None
    extra_params: dict[str, Any] = field(default_factory=dict)


class LLMAgent(AgentInterface):
    """Wraps a frontier LLM as a LIFE FORGE AgentInterface with full tool-use support.

    Usage:
        from lifeforge.sandbox.llm_agent import LLMAgent, LLMAgentConfig
        agent = LLMAgent(LLMAgentConfig(model="claude-sonnet-4-20250514"))
        # Then pass `agent` to SandboxRunner.run() or EvolutionEngine.run()
    """

    def __init__(
        self,
        config: LLMAgentConfig | None = None,
        tool_schemas: list[dict[str, Any]] | None = None,
    ) -> None:
        self.config = config or LLMAgentConfig()
        self.name = f"LLMAgent({self.config.model})"
        self._litellm = _check_litellm()
        self._tool_schemas = tool_schemas or []
        self._messages: list[dict[str, Any]] = []
        self.cost_tracker = LLMCostTracker()

    def set_tool_schemas(self, schemas: list[dict[str, Any]]) -> None:
        """Set the available tools (usually from ToolRegistry.get_schemas())."""
        self._tool_schemas = schemas

    def reset(self) -> None:
        """Clear conversation memory between episodes."""
        self._messages = []
        self.cost_tracker = LLMCostTracker()

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        """Call the LLM and translate its tool-use response into an AgentAction."""
        step = observation.get("step", len(history))

        # Build messages on first call
        if not self._messages:
            self._messages.append({
                "role": "system",
                "content": self.config.system_prompt,
            })

        # Add current observation as user message
        user_msg = _observation_to_user_msg(observation, step)
        self._messages.append({"role": "user", "content": user_msg})

        # Call the LLM
        try:
            kwargs: dict[str, Any] = {
                "model": self.config.model,
                "messages": self._messages,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "timeout": self.config.timeout,
                "num_retries": self.config.max_retries,
                **self.config.extra_params,
            }
            if self.config.api_base:
                kwargs["api_base"] = self.config.api_base
            if self.config.api_key:
                kwargs["api_key"] = self.config.api_key

            if self._tool_schemas:
                kwargs["tools"] = self._tool_schemas
                kwargs["tool_choice"] = "auto"

            response = self._litellm.completion(**kwargs)
            self.cost_tracker.record(response)

        except Exception as exc:
            logger.error("LLM API call failed: %s", exc)
            return AgentAction(
                action_type="finish",
                thought=f"LLM API error: {exc}",
                message=f"Agent terminated due to API error: {exc}",
            )

        # Parse response
        choice = response.choices[0]
        message = choice.message

        # Record assistant message in conversation
        self._messages.append(message.model_dump())

        # Check for tool calls
        tool_calls = getattr(message, "tool_calls", None)
        if tool_calls and len(tool_calls) > 0:
            tc = tool_calls[0]  # We process one tool call at a time
            fn = tc.function
            tool_name = fn.name
            try:
                arguments = json.loads(fn.arguments) if fn.arguments else {}
            except json.JSONDecodeError:
                arguments = {}

            # Record the tool call ID for follow-up
            self._pending_tool_call_id = tc.id

            return AgentAction(
                action_type="tool_call",
                tool_name=tool_name,
                arguments=arguments,
                thought=getattr(message, "content", None) or f"Calling {tool_name}",
            )

        # No tool call — the model is finishing
        content = getattr(message, "content", "") or ""
        return AgentAction(
            action_type="finish",
            thought=content[:200] if content else "Task complete.",
            message=content or "Agent completed task.",
        )

    def inject_tool_result_to_messages(self, tool_result: dict[str, Any]) -> None:
        """Manually inject a tool result into the conversation history.

        This is called internally by the enhanced SandboxRunner when running
        LLM agents to maintain proper tool-use conversation flow.
        """
        tool_call_id = getattr(self, "_pending_tool_call_id", "call_0")
        self._messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": json.dumps(tool_result, default=str),
        })


# ---------------------------------------------------------------------------
# LLM-aware SandboxRunner
# ---------------------------------------------------------------------------

class LLMSandboxRunner:
    """SandboxRunner variant that correctly handles LLM tool-use conversation flow.

    The standard SandboxRunner passes tool results via the observation dict.
    LLM agents need tool results injected into their message history with the
    correct tool_call_id. This runner handles that automatically.
    """

    def __init__(
        self,
        runner: Any = None,  # SandboxRunner — uses Any to avoid circular import
    ) -> None:
        # Lazy import to avoid circular dependency
        from .oracle import SandboxRunner
        self.runner: SandboxRunner = runner or SandboxRunner()

    def run(
        self,
        agent: LLMAgent,
        initial_state: Any,
        max_steps: int | None = None,
    ) -> Any:
        """Run an LLM agent through the sandbox with proper tool-use flow."""
        import copy
        from .oracle import SimulationTrace
        from .mock_tools import ToolResult
        from .world_state import WorldState

        steps_limit = max_steps or self.runner.goal_spec.max_steps
        state: WorldState = initial_state.snapshot()
        agent.reset()

        # Provide tool schemas to agent
        agent.set_tool_schemas(self.runner.tool_registry.get_schemas())

        events: list[dict[str, Any]] = []
        last_result: ToolResult | None = None

        for step_idx in range(steps_limit):
            state.step_count = step_idx + 1

            observation = {
                "inbox": copy.deepcopy(state.inbox),
                "step": step_idx,
                "last_tool_result": {
                    "success": last_result.success,
                    "output": last_result.output,
                    "error": last_result.error,
                }
                if last_result
                else None,
            }

            # If we have a pending tool result, inject it into the LLM's message history
            if last_result is not None:
                agent.inject_tool_result_to_messages({
                    "success": last_result.success,
                    "output": last_result.output,
                    "error": last_result.error,
                })

            action = agent.act(observation, copy.deepcopy(events))

            event_record: dict[str, Any] = {
                "step": step_idx,
                "action": {
                    "action_type": action.action_type,
                    "tool_name": action.tool_name,
                    "arguments": copy.deepcopy(action.arguments),
                    "thought": action.thought,
                    "message": action.message,
                },
            }

            if action.action_type == "finish":
                events.append(event_record)
                break

            elif action.action_type == "tool_call" and action.tool_name:
                last_result = self.runner.tool_registry.dispatch(
                    action.tool_name,
                    state,
                    action.arguments,
                )
                event_record["result"] = {
                    "success": last_result.success,
                    "output": copy.deepcopy(last_result.output),
                    "error": last_result.error,
                    "cost": last_result.cost,
                }
                events.append(event_record)
            else:
                events.append(event_record)

        violations = self.runner.goal_spec.evaluate(initial_state, state, events)
        critical = any(v.severity == "CRITICAL" for v in violations)
        success = len(violations) == 0

        failure_category: str | None = None
        if not success:
            for v in violations:
                if v.severity == "CRITICAL":
                    failure_category = v.violation_type
                    break
            if not failure_category and violations:
                failure_category = violations[0].violation_type

        return SimulationTrace(
            initial_state=initial_state,
            final_state=state,
            events=events,
            violations=violations,
            success=success,
            total_steps=len(events),
            critical_failure=critical,
            failure_category=failure_category,
        )
