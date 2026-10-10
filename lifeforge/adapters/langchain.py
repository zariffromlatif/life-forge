"""LangChain adapter for LIFE FORGE.

Wraps a LangChain AgentExecutor (or any LCEL Runnable that accepts a dict
and returns a response) as a standard AgentInterface so it can be evaluated
inside the LIFE FORGE sandbox without modification.

LangChain is NOT imported at module level.  The import is deferred to
__init__ so that the rest of LIFE FORGE continues to work when LangChain is
not installed.

.. warning::
   The sandbox only sees the action the wrapped agent *returns*. Tools bound
   to an AgentExecutor (``AgentExecutor(tools=[...])``) are executed by
   LangChain itself, inside ``invoke()``, against whatever real systems they
   touch - the sandbox cannot intercept or undo them, and their effects are
   invisible to the oracle. Evaluate an executor with NO real tools bound (or
   with stubs), and let it act on the sandbox through the ACTION PROTOCOL
   JSON reply this adapter requests.

Typical usage
-------------
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(model="gpt-4o-mini")
    agent_executor = AgentExecutor(agent=..., tools=[])

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

from ._parsing import (
    ACTION_PROTOCOL,
    describe_sandbox_tools,
    extract_json_payload,
    parse_action_payload,
    result_to_text,
)

logger = logging.getLogger(__name__)


def _format_observation(observation: dict[str, Any], sandbox_tools: Any = None) -> str:
    """Convert a LIFE FORGE observation dict into a plain text input string.

    The string carries the inbox, the last tool result, the sandbox tools the
    agent may call (when known), and the ACTION PROTOCOL describing the JSON
    reply the adapter parses.
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

    tools_text = describe_sandbox_tools(observation, sandbox_tools)
    if tools_text:
        parts.append(tools_text)
    parts.append(ACTION_PROTOCOL)
    return "\n".join(parts)


class LangChainAdapter(AgentInterface):
    """Wraps a LangChain AgentExecutor (or any compatible callable) as a LIFE FORGE agent.

    The executor is invoked with a single dict argument::

        executor.invoke({"input": formatted_observation_string})

    The input ends with the shared ACTION PROTOCOL (and the sandbox tool list
    when known). The response is parsed in this order:

    1. native ``tool_calls`` on an AIMessage-like object (or in a dict),
    2. the text output (``{"output": ...}`` from AgentExecutor, message
       content, or a plain string) parsed through the shared JSON action
       protocol - so an executor replying with a ``tool_call`` JSON object
       reaches the sandbox as a tool call,
    3. anything unparseable degrades to a ``finish`` action.

    Any exception raised by the executor is caught and returned as a "finish"
    action, so episodes always terminate cleanly. See the module warning:
    tools bound to the executor itself run for real, outside the sandbox.

    Parameters
    ----------
    executor:
        A LangChain AgentExecutor, LCEL Runnable, or any object that exposes
        an ``.invoke(dict) -> Any`` method.
    name:
        Human-readable identifier shown in trace logs and reports.
    sandbox_tools:
        Optional sandbox tool names/specs to list in every prompt. When
        omitted, an ``available_tools`` entry in the observation is used.
    """

    def __init__(
        self,
        executor: Any,
        name: str = "LangChainAdapter",
        sandbox_tools: Any = None,
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
        self.sandbox_tools = sandbox_tools
        if getattr(executor, "tools", None):
            logger.warning(
                "LangChainAdapter: the wrapped executor has its own tools bound; LangChain executes "
                "them for real inside invoke(), outside the LIFE FORGE sandbox."
            )

    # ------------------------------------------------------------------
    # AgentInterface implementation
    # ------------------------------------------------------------------

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        """Format the observation, invoke the executor, and parse its response."""
        formatted_input = _format_observation(observation, self.sandbox_tools)

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
        """
        return cls(executor=runnable, name=name)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_response(self, response: Any) -> AgentAction:
        """Translate a LangChain executor response into an AgentAction."""
        if isinstance(response, dict):
            native_calls = response.get("tool_calls")
        else:
            native_calls = getattr(response, "tool_calls", None)
        if native_calls:
            return self._action_from_tool_call(native_calls[0])

        text = result_to_text(response)
        return parse_action_payload(extract_json_payload(text), fallback_text=text or "Agent completed task.")

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
                arguments: Any = json.loads(raw_args)
            except json.JSONDecodeError:
                arguments = {"raw": raw_args}
        else:
            arguments = dict(raw_args) if raw_args else {}
        if not isinstance(arguments, dict):
            arguments = {"raw": arguments}

        return AgentAction(
            action_type="tool_call",
            tool_name=tool_name,
            arguments=arguments,
            thought=f"LangChain selected tool: {tool_name}",
        )
