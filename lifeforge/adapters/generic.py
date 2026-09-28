"""Generic callable adapter for LIFE FORGE.

Wraps any Python callable as a LIFE FORGE AgentInterface.  This is the
universal fallback when neither LangChain nor LangGraph is in use.

Typical usage
-------------
    from lifeforge.adapters import CallableAdapter
    from lifeforge.sandbox.agent import AgentAction

    def my_agent(observation: dict) -> dict:
        # Inspect the observation and decide what to do
        return {"tool_name": "vendor_api", "arguments": {"vendor_id": "v1"}}

    adapter = CallableAdapter(fn=my_agent, name="my-custom-agent")
    # adapter can now be passed to SandboxRunner.run() or EvolutionEngine

If the callable already returns an AgentAction it is passed through as-is.
If it returns a dict containing both ``"tool_name"`` and ``"arguments"`` keys,
a tool_call AgentAction is constructed.  Any other return value is stringified
and returned as a finish AgentAction.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from lifeforge.sandbox.agent import AgentAction, AgentInterface

logger = logging.getLogger(__name__)


class CallableAdapter(AgentInterface):
    """Wraps any Python callable as a LIFE FORGE agent.

    The callable receives the raw ``observation`` dict and must return one of:

    - An :class:`~lifeforge.sandbox.agent.AgentAction` instance (passed through unchanged).
    - A dict with ``"tool_name"`` (str) and ``"arguments"`` (dict) keys, which
      is translated into a tool_call AgentAction.
    - Anything else, which is converted to a string and returned as a finish
      AgentAction message.

    Exceptions raised by the callable are caught and returned as a finish
    AgentAction so LIFE FORGE episodes always terminate cleanly.

    Parameters
    ----------
    fn:
        Any Python callable with the signature ``(observation: dict) -> Any``.
        The ``history`` argument from act() is NOT forwarded to the callable by
        default to keep the interface simple.  If you need history, use a
        closure or a class-based callable that captures it.
    name:
        Human-readable identifier shown in trace logs and reports.
    pass_history:
        When True the callable receives both the observation and the history
        list: ``fn(observation, history)``.  Defaults to False.

    Example
    -------
        import random
        from lifeforge.adapters import CallableAdapter

        def random_vendor_agent(obs: dict) -> dict:
            vendors = ["vendor_alphatech", "vendor_betasolutions"]
            return {
                "tool_name": "vendor_api",
                "arguments": {
                    "vendor_id": random.choice(vendors),
                    "item": "server_h100",
                },
            }

        adapter = CallableAdapter(fn=random_vendor_agent, name="random-vendor")
    """

    def __init__(
        self,
        fn: Callable[[dict[str, Any]], Any],
        name: str = "CallableAdapter",
        pass_history: bool = False,
    ) -> None:
        self.fn = fn
        self.name = name
        self.pass_history = pass_history

    # ------------------------------------------------------------------
    # AgentInterface implementation
    # ------------------------------------------------------------------

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        """Invoke the wrapped callable and parse its return value.

        Parameters
        ----------
        observation:
            Current sandbox observation produced by SandboxRunner.
        history:
            List of prior step records.  Only forwarded to the callable when
            ``pass_history=True`` was set on construction.

        Returns
        -------
        AgentAction
            Parsed from the callable's return value, or a finish action on
            any exception.
        """
        try:
            if self.pass_history:
                result: Any = self.fn(observation, history)  # type: ignore[call-arg]
            else:
                result = self.fn(observation)
        except Exception as exc:
            logger.error("CallableAdapter fn raised an exception: %s", exc)
            return AgentAction(
                action_type="finish",
                thought=f"Callable error: {exc}",
                message=f"Agent callable failed: {exc}",
            )

        return self._parse_result(result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_result(result: Any) -> AgentAction:
        """Translate the callable's return value into an AgentAction.

        Resolution order:
        1. If the result is already an AgentAction, return it unchanged.
        2. If the result is a dict with both ``"tool_name"`` and
           ``"arguments"`` keys, build a tool_call AgentAction.
        3. Otherwise stringify the result and return a finish AgentAction.
        """
        # Already an AgentAction -- pass through
        if isinstance(result, AgentAction):
            return result

        # Dict with tool_call shape
        if isinstance(result, dict):
            tool_name: str | None = result.get("tool_name")
            arguments: Any = result.get("arguments")
            if tool_name is not None and arguments is not None:
                return AgentAction(
                    action_type="tool_call",
                    tool_name=str(tool_name),
                    arguments=dict(arguments) if isinstance(arguments, dict) else {},
                    thought=result.get("thought"),  # type: ignore[arg-type]
                )

            # Dict without tool keys -- treat the whole thing as a finish message
            message_text = result.get("message") or result.get("output") or str(result)
            return AgentAction(
                action_type="finish",
                thought=result.get("thought"),  # type: ignore[arg-type]
                message=str(message_text),
            )

        # Fallback: stringify any other type
        return AgentAction(
            action_type="finish",
            thought="Callable returned a non-dict value.",
            message=str(result),
        )
