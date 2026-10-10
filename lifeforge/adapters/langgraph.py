"""LangGraph adapter for LIFE FORGE.

Wraps a compiled LangGraph StateGraph application as a standard AgentInterface
so it can be evaluated inside the LIFE FORGE sandbox without any modification
to the graph itself.

LangGraph (and LangChain core) are NOT imported at module level.  The import
is deferred to the act() method so that the rest of LIFE FORGE continues to
work when LangGraph is not installed.

Typical usage
-------------
    from langgraph.graph import StateGraph, END
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage

    # Build and compile your graph (any topology)
    graph = StateGraph(...)
    ...
    app = graph.compile()

    from lifeforge.adapters import LangGraphAdapter
    adapter = LangGraphAdapter(app=app, name="my-langgraph-agent")
    # adapter can now be passed to SandboxRunner.run() or EvolutionEngine

The adapter supports both streaming and non-streaming compiled graphs.  When
the graph supports ``.stream()``, only ``.invoke()`` is used here to keep the
interface synchronous and compatible with the LIFE FORGE step loop.

.. warning::
   Graphs with their own tool nodes (e.g. ``create_react_agent(llm, tools)``)
   run those tools FOR REAL inside ``invoke()`` and loop until the model
   stops calling them. The sandbox never sees or intercepts those calls, so
   their side effects land on real systems and are invisible to the oracle.
   Evaluate graphs with no real tools bound (or stubs) and let the agent act
   on the sandbox through the ACTION PROTOCOL reply this adapter requests.
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


def _format_observation_for_langgraph(observation: dict[str, Any], sandbox_tools: Any = None) -> str:
    """Serialize a LIFE FORGE observation into a human-readable string.

    The resulting string is used as the content of a HumanMessage passed to
    the LangGraph app so the graph nodes have full context about the current
    sandbox state.
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


class LangGraphAdapter(AgentInterface):
    """Wraps a compiled LangGraph StateGraph app as a LIFE FORGE agent.

    The graph is invoked once per sandbox step with a minimal message list::

        app.invoke({"messages": [HumanMessage(content=formatted_observation)]})

    The adapter extracts the last AIMessage from the returned state dict.
    If that message carries tool_calls, the first tool call is returned as a
    tool_call AgentAction.  Otherwise the message content is returned as a
    finish AgentAction.

    Streaming graphs are fully supported because only ``.invoke()`` is used;
    the adapter never calls ``.stream()``.

    Parameters
    ----------
    app:
        A compiled LangGraph StateGraph (``graph.compile()``).  Any graph
        that accepts a ``{"messages": list}`` input and returns a dict with a
        ``"messages"`` list in its output state is compatible.
    name:
        Human-readable identifier shown in trace logs and reports.

    Example
    -------
        from langgraph.prebuilt import create_react_agent
        from langchain_openai import ChatOpenAI

        llm = ChatOpenAI(model="gpt-4o-mini")
        app = create_react_agent(llm, tools=[])

        from lifeforge.adapters import LangGraphAdapter
        adapter = LangGraphAdapter(app=app, name="react-agent")
    """

    def __init__(
        self,
        app: Any,
        name: str = "LangGraphAdapter",
        sandbox_tools: Any = None,
    ) -> None:
        self.app = app
        self.name = name
        self.sandbox_tools = sandbox_tools

    # ------------------------------------------------------------------
    # AgentInterface implementation
    # ------------------------------------------------------------------

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        """Build a message list from the observation, invoke the app, and parse the result.

        Parameters
        ----------
        observation:
            Current sandbox observation produced by SandboxRunner.
        history:
            List of prior step records for the current episode (not forwarded
            to the graph because LangGraph maintains its own message state).

        Returns
        -------
        AgentAction
            A tool_call action when the final AIMessage selects a tool, or a
            finish action for plain text output or any exception.
        """
        # Lazy import -- keeps LIFE FORGE importable without langgraph installed
        try:
            from langchain_core.messages import HumanMessage
        except ImportError as exc:
            raise ImportError(
                "langchain-core is required for LangGraphAdapter. Install it with:\n"
                "  pip install 'lifeforge[langgraph]'\n"
                "  # or: pip install langgraph langchain-core"
            ) from exc

        formatted_obs = _format_observation_for_langgraph(observation, self.sandbox_tools)

        try:
            result: Any = self.app.invoke(
                {"messages": [HumanMessage(content=formatted_obs)]}
            )
        except Exception as exc:
            logger.error("LangGraphAdapter app.invoke raised an exception: %s", exc)
            return AgentAction(
                action_type="finish",
                thought=f"LangGraph app error: {exc}",
                message=f"LangGraph app failed: {exc}",
            )

        return self._parse_result(result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_result(self, result: Any) -> AgentAction:
        """Extract the last AIMessage from the graph result and build an AgentAction.

        The graph output is expected to be a dict with a ``"messages"`` key
        whose value is a list of LangChain BaseMessage objects.  The adapter
        walks the list in reverse to find the last AIMessage.
        """
        # Lazy import for message type check
        try:
            from langchain_core.messages import AIMessage
        except ImportError:
            AIMessage = None  # type: ignore[assignment,misc]

        messages: list[Any] = []

        if isinstance(result, dict):
            messages = result.get("messages") or []
        elif isinstance(result, list):
            messages = result

        # Find the last AIMessage (or any non-human message as fallback)
        ai_message: Any = None
        for msg in reversed(messages):
            if AIMessage is not None and isinstance(msg, AIMessage):
                ai_message = msg
                break
            # Fallback: any object whose role/type is "ai" or "assistant"
            role = getattr(msg, "type", None) or getattr(msg, "role", None) or ""
            if str(role).lower() in ("ai", "assistant"):
                ai_message = msg
                break

        if ai_message is None:
            # No AI message found -- the raw result may still carry an
            # ACTION PROTOCOL reply (custom graphs returning text/dicts).
            fallback_text = result_to_text(result)
            return parse_action_payload(
                extract_json_payload(fallback_text),
                fallback_text=fallback_text or "Graph returned no output.",
            )

        # Check for tool calls on the AIMessage
        tool_calls: list[Any] = getattr(ai_message, "tool_calls", None) or []
        if tool_calls:
            return self._action_from_tool_call(tool_calls[0])

        # Text response: parse it through the shared ACTION PROTOCOL so a
        # JSON tool_call reply reaches the sandbox; plain prose -> finish.
        content = getattr(ai_message, "content", None)
        if isinstance(content, list):
            # Multi-part content blocks: join their text parts.
            content = "\n".join(
                str(block.get("text", "")) if isinstance(block, dict) else str(block) for block in content
            )
        text = content if isinstance(content, str) and content else str(ai_message)
        return parse_action_payload(extract_json_payload(text), fallback_text=text or "Agent completed task.")

    @staticmethod
    def _action_from_tool_call(tool_call: Any) -> AgentAction:
        """Build an AgentAction from a LangGraph/LangChain tool call entry.

        LangChain AIMessage.tool_calls is a list of dicts with the shape::

            {"name": str, "args": dict, "id": str, "type": "tool_call"}
        """
        if isinstance(tool_call, dict):
            tool_name: str = tool_call.get("name") or "unknown_tool"
            raw_args: Any = tool_call.get("args") or {}
        else:
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
            thought=f"LangGraph selected tool: {tool_name}",
        )
