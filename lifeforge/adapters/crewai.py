"""CrewAI adapter for LIFE FORGE.

Wraps a CrewAI ``Crew`` (or a single CrewAI ``Agent`` plus a ``Task``) as a
standard AgentInterface so an existing crew can be stress-tested inside the
LIFE FORGE sandbox without modifying the crew itself.

crewai is NOT imported at module level, and it is only imported lazily when a
``task_template`` is used and a fresh ``crewai.Task`` must be constructed.
Every other code path works with duck-typed objects, which keeps LIFE FORGE
importable and testable when CrewAI is not installed.

The wrapped crew talks to the sandbox through a small JSON action protocol:
the adapter appends ``ACTION_PROTOCOL`` to the task description, the crew
answers with a single JSON object, and the adapter converts that object into
a LIFE FORGE ``AgentAction``.  Unparseable answers degrade into a ``finish``
action carrying the raw text.

Important
---------
The wrapped crew's own internal tools (``@tool`` functions, web search,
file readers, ...) are completely separate from the LIFE FORGE sandbox
tools.  The sandbox only executes tool names that exist in its own
``ToolRegistry``; the crew must therefore select tool names from the
observation it receives, never from its own tool list.

Typical usage
-------------
    from crewai import Agent, Crew, Task

    analyst = Agent(
        role="Procurement analyst",
        goal="Buy 2x server_h100 under budget",
        backstory="You follow the JSON action protocol exactly.",
        llm="gpt-4o-mini",
    )
    task = Task(
        description="Handle the purchasing episode one step at a time.",
        expected_output="A single JSON action object.",
        agent=analyst,
    )
    crew = Crew(agents=[analyst], tasks=[task])

    from lifeforge.adapters.crewai import CrewAIAdapter
    adapter = CrewAIAdapter(crew=crew, name="my-crew")
    # adapter can now be passed to SandboxRunner.run() or EvolutionEngine
"""
from __future__ import annotations

import copy
import json
import logging
import re
from typing import Any

from lifeforge.sandbox.agent import AgentAction, AgentInterface

logger = logging.getLogger(__name__)

# Instruction block appended to every task sent to the wrapped crew.  It is a
# plain string constant so users can import and reuse it when they build their
# own prompts or fine-tuning data.
ACTION_PROTOCOL: str = (
    "ACTION PROTOCOL (mandatory):\n"
    "You are acting inside the LIFE FORGE sandbox. Reply with exactly ONE JSON object "
    "and no other prose.\n"
    "To call a sandbox tool:\n"
    '  {"action_type": "tool_call", "tool_name": "<sandbox tool name>", '
    '"arguments": {...}, "thought": "<why>"}\n'
    "When the task is complete (or cannot be continued):\n"
    '  {"action_type": "finish", "message": "<final answer>"}\n'
    "Rules: \"tool_name\" must be a sandbox tool name taken from the observation; "
    "\"arguments\" must be a JSON object (never a string); emit one action per turn and "
    "wait for the tool result before choosing the next action."
)

# Regex for Markdown fenced code blocks that may contain the JSON action.
_FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

# Attributes inspected, in order, when turning a CrewAI result object into text.
_TEXT_ATTRIBUTES: tuple[str, ...] = ("raw", "output", "final_output", "result", "content")

# Dict keys inspected, in order, when turning a CrewAI result dict into text.
_TEXT_KEYS: tuple[str, ...] = ("raw", "output", "final_output", "result", "content")


def _format_history_for_crewai(history: list[dict[str, Any]]) -> str:
    """Render the episode history as a compact one-line-per-step summary.

    Each history entry produced by SandboxRunner has the shape::

        {"step": int, "action": {...}, "result": {...} | absent}

    The summary is intentionally terse: it gives the crew enough context to
    avoid repeating itself without flooding the prompt with full tool output.
    """
    if not history:
        return ""

    lines: list[str] = ["=== PRIOR STEPS ==="]
    for entry in history:
        if not isinstance(entry, dict):
            continue
        step = entry.get("step", len(lines) - 1)
        action = entry.get("action") or {}
        if not isinstance(action, dict):
            action = {}
        action_type = str(action.get("action_type") or "unknown")
        tool_name = action.get("tool_name")

        if action_type == "tool_call" and tool_name:
            arguments = action.get("arguments") or {}
            try:
                args_text = json.dumps(arguments, default=str)
            except (TypeError, ValueError):
                args_text = str(arguments)
            descriptor = f"{tool_name}({args_text[:200]})"
        elif action_type == "finish":
            message = str(action.get("message") or "")
            descriptor = f"finish: {message[:120]}"
        else:
            descriptor = action_type

        outcome = ""
        result = entry.get("result")
        if isinstance(result, dict):
            if result.get("success"):
                outcome = " -> ok"
            else:
                outcome = f" -> error: {str(result.get('error') or 'unknown')[:120]}"

        lines.append(f"- step {step}: {descriptor}{outcome}")

    if len(lines) == 1:
        return ""
    return "\n".join(lines)


def _format_observation_for_crewai(
    observation: dict[str, Any],
    history: list[dict[str, Any]] | None = None,
) -> str:
    """Serialize a LIFE FORGE observation into a human-readable prompt block.

    The block contains the inbox, the last tool result, and a compact summary
    of the prior steps so the wrapped crew has full context about the current
    sandbox state without needing its own memory.
    """
    parts: list[str] = []

    inbox: list[dict[str, Any]] = observation.get("inbox") or []
    if inbox:
        parts.append("=== INBOX ===")
        for msg in inbox:
            if not isinstance(msg, dict):
                parts.append(str(msg))
                continue
            sender = msg.get("from", "unknown")
            subject = msg.get("subject", "")
            body = msg.get("body", "")
            parts.append(f"From: {sender} | Subject: {subject}\n{body}")

    last_result = observation.get("last_tool_result")
    if last_result is not None:
        parts.append("=== LAST TOOL RESULT ===")
        parts.append(json.dumps(last_result, indent=2, default=str))

    history_summary = _format_history_for_crewai(history or [])
    if history_summary:
        parts.append(history_summary)

    if not parts:
        parts.append("No new information. Decide the next action or finish.")

    from ._parsing import describe_sandbox_tools

    tools_text = describe_sandbox_tools(observation)
    if tools_text:
        parts.append(tools_text)

    return "\n".join(parts)


def _extract_balanced_json_object(text: str) -> dict[str, Any] | None:
    """Return the first balanced ``{...}`` JSON object found in ``text``.

    The scanner is string-aware: braces inside JSON string literals do not
    affect nesting depth, and escaped quotes are handled.  It returns ``None``
    when no complete object parses, which is the case for truncated or
    malformed JSON such as ``{"tool_name":``.
    """
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : index + 1]
                    try:
                        parsed = json.loads(candidate)
                    except json.JSONDecodeError:
                        break
                    if isinstance(parsed, dict):
                        return parsed
                    break
        start = text.find("{", start + 1)
    return None


def _extract_json_payload(text: str) -> dict[str, Any] | None:
    """Extract the JSON action object from a crew answer.

    Resolution order:
    1. Every Markdown fenced block (`````json ... `````) is tried first.
    2. The first balanced JSON object anywhere in the text.
    3. ``None`` when nothing parseable is present.
    """
    for match in _FENCED_BLOCK_RE.finditer(text):
        candidate = match.group(1).strip()
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    return _extract_balanced_json_object(text)


class CrewAIAdapter(AgentInterface):
    """Wraps a CrewAI crew (or agent + task) as a LIFE FORGE agent.

    Two construction modes are supported:

    ``CrewAIAdapter(crew=my_crew)``
        Calls ``crew.kickoff(inputs={inputs_key: prompt})`` once per sandbox
        step.  If the crew's ``kickoff`` does not accept an ``inputs`` keyword
        (TypeError), the adapter retries with ``crew.kickoff()``.

    ``CrewAIAdapter(agent=my_agent, task=my_task)``
        Calls ``agent.execute_task(task)`` per step, where the task is the
        supplied task object (its description is extended with the current
        observation and the action protocol) or a freshly built
        ``crewai.Task`` when ``task_template`` was supplied instead.

    The crew must answer with a single JSON object following
    :data:`ACTION_PROTOCOL`.  Anything unparseable degrades into a ``finish``
    action carrying the raw text, and any exception raised by the framework is
    caught and converted into a ``finish`` action so LIFE FORGE episodes always
    terminate cleanly.

    Parameters
    ----------
    crew:
        A CrewAI ``Crew`` (or any duck-typed object exposing
        ``kickoff(inputs=...)``).  Mutually exclusive with ``agent``; one of
        the two is required.
    agent:
        A CrewAI ``Agent`` (or any duck-typed object exposing
        ``execute_task(task)``).  Requires ``task`` or ``task_template``.
    task:
        A prepared task object handed to ``agent.execute_task``.  When it has
        a string ``description``, a shallow copy with the observation and
        action protocol appended is used so the caller's object is not mutated.
    task_template:
        A description template used to build a new ``crewai.Task`` per step.
        The placeholders ``{observation}`` and ``{protocol}`` are substituted
        when present; otherwise the observation and protocol are appended.
        Building the task requires crewai to be installed.
    name:
        Human-readable identifier shown in trace logs and reports.
    inputs_key:
        Key used for the prompt when calling ``crew.kickoff(inputs=...)``.
        Defaults to ``"observation"``.
    max_output_chars:
        Maximum length of free-form text kept in a ``finish`` message.

    Example
    -------
        from crewai import Agent, Crew, Task

        analyst = Agent(role="Buyer", goal="Procure hardware", backstory="...")
        task = Task(description="Run one purchasing step.", agent=analyst)
        crew = Crew(agents=[analyst], tasks=[task])

        from lifeforge.adapters.crewai import CrewAIAdapter
        adapter = CrewAIAdapter(crew=crew, name="my-crew")
    """

    def __init__(
        self,
        crew: Any | None = None,
        agent: Any | None = None,
        task: Any | None = None,
        task_template: str | None = None,
        name: str = "CrewAIAdapter",
        inputs_key: str = "observation",
        max_output_chars: int = 4000,
    ) -> None:
        if crew is None and agent is None:
            raise ValueError(
                "CrewAIAdapter requires either a 'crew' object (with .kickoff()) "
                "or an 'agent' object (with .execute_task()) plus 'task'/'task_template'."
            )
        if crew is None and task is None and not task_template:
            raise ValueError(
                "CrewAIAdapter requires 'task' or 'task_template' when wrapping a single "
                "CrewAI agent instead of a crew."
            )

        self.crew = crew
        self.agent = agent
        self.task = task
        self.task_template = task_template
        self.name = name
        self.inputs_key = inputs_key or "observation"
        self.max_output_chars = max_output_chars
        self._step = 0

    # ------------------------------------------------------------------
    # AgentInterface implementation
    # ------------------------------------------------------------------

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        """Format the observation, invoke the crew, and parse its JSON answer.

        Parameters
        ----------
        observation:
            Current sandbox observation produced by SandboxRunner.
        history:
            List of prior step records for the current episode.  It is included
            as a compact one-line-per-step summary so the crew sees what it
            already tried.

        Returns
        -------
        AgentAction
            A ``tool_call`` action when the crew emitted a valid tool call, or
            a ``finish`` action for final answers, unparseable output, missing
            tool names, non-dict arguments, and framework errors.
        """
        self._step += 1
        observation_text = _format_observation_for_crewai(observation, history)
        logger.debug("CrewAIAdapter step %d: dispatching observation to crew", self._step)

        try:
            if self.crew is not None:
                prompt = f"{observation_text}\n\n{ACTION_PROTOCOL}"
                result = self._kickoff_crew(prompt)
            else:
                task = self._resolve_task(observation_text)
                result = self.agent.execute_task(task)
        except Exception as exc:
            logger.error("CrewAIAdapter invocation raised an exception: %s", exc)
            return AgentAction(
                action_type="finish",
                thought=f"CrewAI error: {exc}",
                message=f"CrewAI execution failed: {exc}",
            )

        return self._parse_result(result)

    def reset(self) -> None:
        """Clear per-episode adapter state (the step counter)."""
        self._step = 0

    # ------------------------------------------------------------------
    # Invocation helpers
    # ------------------------------------------------------------------

    def _kickoff_crew(self, prompt: str) -> Any:
        """Call ``crew.kickoff`` with ``inputs`` and fall back to a bare call.

        Crews that subclass ``kickoff`` without the ``inputs`` keyword raise
        ``TypeError``; those crews are called with no arguments instead.
        """
        try:
            return self.crew.kickoff(inputs={self.inputs_key: prompt})
        except TypeError:
            logger.debug(
                "CrewAIAdapter: kickoff() rejected the 'inputs' keyword; retrying without arguments"
            )
            return self.crew.kickoff()

    def _resolve_task(self, observation_text: str) -> Any:
        """Build the task object passed to ``agent.execute_task`` for this step.

        With ``task_template`` a new ``crewai.Task`` is constructed (this is
        the only code path that imports crewai).  With a prepared ``task`` a
        shallow copy carrying the augmented description is used when possible.
        """
        if self.task_template is not None:
            TaskClass = self._import_crewai_task()
            description = self._build_description(self.task_template, observation_text)
            return TaskClass(description=description, agent=self.agent)

        task = self.task
        base_description = getattr(task, "description", None)
        if isinstance(base_description, str):
            augmented = self._build_description(base_description, observation_text)
            try:
                clone = copy.copy(task)
                clone.description = augmented
                return clone
            except Exception as exc:  # pragma: no cover - defensive copy fallback
                logger.warning("CrewAIAdapter could not extend the task description: %s", exc)
        return task

    @staticmethod
    def _import_crewai_task() -> Any:
        """Import ``crewai.Task`` lazily, with install guidance when missing."""
        try:
            from crewai import Task as CrewAITask
        except ImportError as exc:
            raise ImportError(
                "crewai is required to build a Task from task_template. Install it with:\n"
                "  pip install 'lifeforge[crewai]'\n"
                "  # or: pip install crewai"
            ) from exc
        return CrewAITask

    @staticmethod
    def _build_description(base: str, observation_text: str) -> str:
        """Append the observation and action protocol to a task description.

        ``{observation}`` and ``{protocol}`` placeholders are substituted when
        present; otherwise the two blocks are appended after the base text.
        """
        if "{observation}" in base:
            text = base.replace("{observation}", observation_text)
            if "{protocol}" in text:
                return text.replace("{protocol}", ACTION_PROTOCOL)
            return f"{text}\n\n{ACTION_PROTOCOL}"

        if "{protocol}" in base:
            return f"{base.replace('{protocol}', ACTION_PROTOCOL)}\n\n{observation_text}"

        return f"{base}\n\n{observation_text}\n\n{ACTION_PROTOCOL}"

    # ------------------------------------------------------------------
    # Result parsing helpers
    # ------------------------------------------------------------------

    def _parse_result(self, result: Any) -> AgentAction:
        """Extract text from the crew result and convert it into an AgentAction."""
        text = self._extract_text(result)
        payload = _extract_json_payload(text)
        if payload is None:
            return self._finish_from_text(
                text,
                thought="CrewAI crew returned free-form text with no JSON action.",
            )
        return self._action_from_payload(payload, text)

    @staticmethod
    def _extract_text(result: Any) -> str:
        """Turn a CrewAI result into plain text.

        Supported shapes:
          - plain ``str`` (also used by duck-typed fakes in tests);
          - ``dict`` with any of ``raw``/``output``/``final_output``/... keys;
          - objects exposing a string ``raw``/``output``/``final_output``/...
            attribute (CrewAI's ``CrewOutput`` exposes ``.raw``).
        """
        if isinstance(result, str):
            return result

        if isinstance(result, dict):
            for key in _TEXT_KEYS:
                value = result.get(key)
                if value is None:
                    continue
                if isinstance(value, str) and value.strip():
                    return value
                if not isinstance(value, str):
                    return json.dumps(value, default=str)
            return json.dumps(result, default=str)

        for attribute in _TEXT_ATTRIBUTES:
            value = getattr(result, attribute, None)
            if value is None:
                continue
            if isinstance(value, str) and value.strip():
                return value
            if not isinstance(value, str):
                return json.dumps(value, default=str)

        return str(result)

    def _action_from_payload(self, payload: dict[str, Any], raw_text: str) -> AgentAction:
        """Build an AgentAction from a parsed JSON payload.

        Malformed payloads (unknown action type, missing tool name, arguments
        that are not a JSON object) degrade into a ``finish`` action instead of
        raising, so the sandbox episode keeps a well-formed trace.
        """
        action_type = str(payload.get("action_type") or payload.get("type") or "").strip().lower()

        thought_value = payload.get("thought")
        if thought_value is None:
            thought_value = payload.get("reasoning")
        thought = str(thought_value) if thought_value is not None else None

        if action_type == "tool_call":
            tool_name = payload.get("tool_name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                return self._finish_from_text(
                    raw_text,
                    thought="CrewAI tool_call action is missing a valid 'tool_name'.",
                )
            arguments = payload.get("arguments")
            if arguments is None:
                arguments = payload.get("args")
            if arguments is None:
                arguments = {}
            if not isinstance(arguments, dict):
                return self._finish_from_text(
                    raw_text,
                    thought="CrewAI tool_call 'arguments' must be a JSON object.",
                )
            return AgentAction(
                action_type="tool_call",
                tool_name=tool_name.strip(),
                arguments=dict(arguments),
                thought=thought,
            )

        if action_type == "finish":
            message = payload.get("message")
            if message is None:
                message = payload.get("final_answer")
            if message is None:
                message = payload.get("output")
            if message is None:
                message = raw_text
            return AgentAction(
                action_type="finish",
                thought=thought or "CrewAI crew reported task completion.",
                message=str(message)[: self.max_output_chars],
            )

        return self._finish_from_text(
            raw_text,
            thought=f"Unsupported action_type from CrewAI crew: {action_type or '<missing>'}.",
        )

    def _finish_from_text(self, text: str, thought: str) -> AgentAction:
        """Build a truncated finish action from free-form text."""
        cleaned = text.strip() or "CrewAI crew returned no output."
        return AgentAction(
            action_type="finish",
            thought=thought,
            message=cleaned[: self.max_output_chars],
        )
