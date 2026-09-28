"""LangChain adapter for LIFE FORGE.

Wraps a LangChain AgentExecutor (or any LCEL Runnable that accepts a dict
and returns a response) as a standard AgentInterface so it can be evaluated
inside the LIFE FORGE sandbox without modification.

LangChain is NOT imported at module level.  The import is deferred to
__init__ so that the rest of LIFE FORGE continues to work when LangChain is
not installed.

Typical usage
-------------
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(model="gpt-4o-mini")
    agent_executor = AgentExecutor(agent=..., tools=[...])

    from lifeforge.adapters import LangChainAdapter
    adapter = LangChainAdapter(executor=agent_executor, name="my-lc-agent")
    # adapter can now be passed to SandboxRunner.run() or EvolutionEngine

LCEL chains can be wrapped via the convenience classmethod:
    from langchain_core.runnables import RunnableLambda
    chain = llm | RunnableLambda(lambda x: x)
    adapter = LangChainAdapter.from_runnable(chain, name="my-chain")
"""
from __future__ import annotations

import json
import logging
from typing import Any

from lifeforge.sandbox.agent import AgentAction, AgentInterface

logger = logging.getLogger(__name__)


def _format_observation(observation: dict[str, Any]) -> str:
    """Convert a LIFE FORGE observation dict into a plain text input string.

    The string includes the first inbox message (if any) and the last tool
    result so the LangChain agent has all the context it needs to pick its
    next action.
    """
    parts: list[str] = []

    inbox: list[dict[str, Any]] = observation.get("inbox") or []
    if inbox:
        parts.append("=== INBOX ===")
        for msg in inbox:
            sender = msg.get("from", "unknown")
            subject = msg.get("subject", "")
            body = msg.get("body", "")
            parts.append(f"From: {sender} | Subject: {subject}\n{body}")

    last_result = observation.get("last_tool_result")
    if last_result is not None:
        parts.append("=== LAST TOOL RESULT ===")
        parts.append(json.dumps(last_result, indent=2, default=str))

    if not parts:
        parts.append("No new information. Decide next action or finish.")

    return "\n".join(parts)


class LangChainAdapter(AgentInterface):
    """Wraps a LangChain AgentExecutor (or any compatible callable) as a LIFE FORGE agent.

    The executor is invoked with a single dict argument::

        executor.invoke({"input": formatted_observation_string})

    The response is inspected for a ``tool_calls`` attribute (present on
    LangChain AIMessage objects).  If tool calls are found, the first one is
    returned as an AgentAction with action_type="tool_call".  If the response
    has only text output, a "finish" action is returned instead.

    Any exception raised by the executor is caught and returned as a "finish"
    action with the error description, so LIFE FORGE episodes always terminate
    cleanly regardless of framework errors.

    Parameters
    ----------
    executor:
        A LangChain AgentExecutor, LCEL Runnable, or any object that exposes
        an ``.invoke(dict) -> Any`` method.
    name:
        Human-readable identifier shown in trace logs and reports.
    """

    def __init__(
        self,
        executor: Any,
        name: str = "LangChainAdapter",
    ) -> None:
        # Validate that langchain is reachable without hard-importing it at
        # module level.  This raises a clear ImportError with install guidance
        # if the package is missing.
        try:
            import langchain  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "LangChain is required for LangChainAdapter. Install it with:\n"
                "  pip install 'lifeforge[langchain]'\n"
                "  # or: pip install langchain langchain-core"
            ) from exc

        self.executor = executor
        self.name = name

    # ------------------------------------------------------------------
    # AgentInterface implementation
    # ------------------------------------------------------------------

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        """Format the observation, invoke the executor, and parse its response.

        Parameters
        ----------
        observation:
            Current sandbox observation produced by SandboxRunner.
        history:
            List of prior step records for the current episode.

        Returns
        -------
        AgentAction
            A tool_call action when the executor selects a tool, or a finish
            action when it produces only text output or encounters an error.
        """
        formatted_input = _format_observation(observation)

        try:
            response = self.executor.invoke({"input": formatted_input})
        except Exception as exc:
            logger.error("LangChainAdapter executor raised an exception: %s", exc)
            return AgentAction(
                action_type="finish",
                thought=f"Executor error: {exc}",
                message=f"LangChain executor failed: {exc}",
            )

        return self._parse_response(response)

    def reset(self) -> None:
        """Reset the executor if it exposes a reset/clear_history method."""
        if hasattr(self.executor, "memory") and hasattr(self.executor.memory, "clear"):
            self.executor.memory.clear()

    # ------------------------------------------------------------------
    # Classmethods
    # ------------------------------------------------------------------

    @classmethod
    def from_runnable(cls, runnable: Any, name: str = "LangChainRunnableAdapter") -> "LangChainAdapter":
        """Wrap an LCEL chain or Runnable as a LangChainAdapter.

        The runnable must accept a dict with an ``"input"`` key and return
        either an AIMessage-like object or a plain string.

        Example
        -------
            from langchain_openai import ChatOpenAI
            from langchain_core.output_parsers import StrOutputParser

            chain = ChatOpenAI(model="gpt-4o-mini") | StrOutputParser()
            adapter = LangChainAdapter.from_runnable(chain, name="gpt4o-chain")
        """
        return cls(executor=runnable, name=name)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_response(self, response: Any) -> AgentAction:
        """Translate a LangChain executor response into an AgentAction.

        Handles three response shapes:
          - dict with an "output" key (AgentExecutor default)
          - AIMessage object with optional tool_calls attribute
          - Plain string
        """
        # AgentExecutor returns {"output": "...", ...}
        if isinstance(response, dict):
            output_text: str = str(response.get("output", ""))
            # Some chains return intermediate tool call info in the dict
            tool_calls = response.get("tool_calls") or []
            if tool_calls:
                return self._action_from_tool_call(tool_calls[0])
            return AgentAction(
                action_type="finish",
                thought=output_text[:200] if output_text else "Task complete.",
                message=output_text or "Agent completed task.",
            )

        # AIMessage / BaseMessage object (LCEL chain without a str output parser)
        tool_calls = getattr(response, "tool_calls", None)
        if tool_calls:
            return self._action_from_tool_call(tool_calls[0])

        # Plain text content
        content: str = getattr(response, "content", None) or str(response)
        return AgentAction(
            action_type="finish",
            thought=content[:200] if content else "Task complete.",
            message=content or "Agent completed task.",
        )

    @staticmethod
    def _action_from_tool_call(tool_call: Any) -> AgentAction:
        """Build an AgentAction from a LangChain tool call object or dict."""
        # LangChain AIMessage.tool_calls is a list of dicts:
        # {"name": str, "args": dict, "id": str, "type": "tool_call"}
        if isinstance(tool_call, dict):
            tool_name = tool_call.get("name") or tool_call.get("function", {}).get("name", "unknown_tool")
            raw_args = tool_call.get("args") or tool_call.get("function", {}).get("arguments", {})
        else:
            # OpenAI-style tool call object
            fn = getattr(tool_call, "function", tool_call)
            tool_name = getattr(fn, "name", "unknown_tool")
            raw_args = getattr(fn, "arguments", {})

        if isinstance(raw_args, str):
            try:
                arguments: dict[str, Any] = json.loads(raw_args)
            except json.JSONDecodeError:
                arguments = {"raw": raw_args}
        else:
            arguments = dict(raw_args) if raw_args else {}

        return AgentAction(
            action_type="tool_call",
            tool_name=tool_name,
            arguments=arguments,
            thought=f"LangChain selected tool: {tool_name}",
        )
