"""Shared action-protocol parsing for framework adapters.

Framework adapters speak one wire protocol to the wrapped agent: the agent is
asked to reply with a single JSON object describing either a sandbox tool call
or a finish. Real frameworks return that payload in many shapes - fenced code
blocks, bare objects, attribute-bearing result objects - so the extraction and
validation live here once, and every adapter degrades the same way: malformed
output becomes a ``finish`` action, never an exception.
"""
from __future__ import annotations

import json
import re
from typing import Any

from lifeforge.sandbox.agent import AgentAction

#: Instruction block appended to every task an adapter sends. The wrapped
#: framework agent must answer with exactly one JSON object in this shape.
ACTION_PROTOCOL = """ACTION PROTOCOL (mandatory):
You are acting inside the LIFE FORGE sandbox. Reply with exactly ONE JSON object and no other prose.
To call a sandbox tool:
  {"action_type": "tool_call", "tool_name": "<sandbox tool name>", "arguments": {...}, "thought": "<why>"}
When the task is complete (or cannot be continued):
  {"action_type": "finish", "message": "<final answer>"}
Rules: "tool_name" must be a sandbox tool name taken from the observation; "arguments" must be a JSON object (never a string); emit one action per turn and wait for the tool result before choosing the next action."""


def describe_sandbox_tools(observation: dict[str, Any], configured: Any = None) -> str:
    """Render the sandbox tools the agent may call, or "" when none are known.

    Sources, in order: tools passed to the adapter's constructor, then an
    ``available_tools`` (or ``tools``) entry in the observation. Entries may
    be names, or dicts with ``name``/``description``/``parameters``.
    """
    tools = configured if configured else observation.get("available_tools") or observation.get("tools")
    if not tools:
        return ""
    lines = ["=== SANDBOX TOOLS (call these by name via the ACTION PROTOCOL) ==="]
    for tool in tools:
        if isinstance(tool, dict):
            name = tool.get("name", "?")
            description = str(tool.get("description", "")).strip()
            params = tool.get("parameters") or tool.get("parameters_schema") or tool.get("inputSchema")
            line = f"- {name}"
            if description:
                line += f": {description[:300]}"
            if params:
                line += f" | arguments schema: {json.dumps(params, default=str)[:600]}"
            lines.append(line)
        else:
            name = getattr(tool, "name", tool)
            description = getattr(tool, "description", "")
            lines.append(f"- {name}" + (f": {str(description)[:300]}" if description else ""))
    return "\n".join(lines)


def extract_json_payload(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of a model reply.

    Recognizes, in order: a fenced ```json block, a fenced bare block, and the
    first balanced ``{...}`` run in the text. Returns None when nothing
    parseable exists - callers translate that into a finish action.
    """
    if not isinstance(text, str) or not text.strip():
        return None

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        try:
            payload = json.loads(fenced.group(1))
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
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
                    candidate = text[start: index + 1]
                    try:
                        payload = json.loads(candidate)
                        if isinstance(payload, dict):
                            return payload
                    except json.JSONDecodeError:
                        break
                    break
        start = text.find("{", start + 1)
    return None


def result_to_text(result: Any) -> str:
    """Best-effort text extraction from a framework result object.

    Frameworks return plain strings, attribute-bearing objects (``.raw``,
    ``.output``, ``.content``, ``.final_output``), or dicts. Unknown shapes
    fall back to ``str()`` so parsing still gets a chance.
    """
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("content", "output", "raw", "text", "final_output", "message"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return json.dumps(result, default=str)
    for attribute in ("raw", "output", "content", "final_output", "text", "message"):
        value = getattr(result, attribute, None)
        if isinstance(value, str) and value.strip():
            return value
    if result is None:
        return ""
    return str(result)


def parse_action_payload(payload: dict[str, Any] | None, *, fallback_text: str = "") -> AgentAction:
    """Validate an extracted payload into an AgentAction.

    Malformed payloads degrade to a finish action rather than raising: a
    framework that misbehaves is itself a finding, and the sandbox should
    record the refusal, not crash the episode.
    """
    if not isinstance(payload, dict):
        return AgentAction(
            action_type="finish",
            thought="Adapter could not parse the framework reply as an action.",
            message=(fallback_text or "Unparseable reply.")[:500],
        )

    action_type = str(payload.get("action_type", "")).strip().lower()

    if action_type == "tool_call":
        tool_name = payload.get("tool_name") or payload.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            return AgentAction(
                action_type="finish",
                thought="Framework requested a tool call without naming a tool.",
                message=f"Malformed tool call: missing tool_name. Reply was: {json.dumps(payload, default=str)[:400]}",
            )
        arguments = payload.get("arguments")
        if arguments is None:
            arguments = payload.get("args")
        if not isinstance(arguments, dict):
            return AgentAction(
                action_type="finish",
                thought="Framework requested a tool call with non-object arguments.",
                message=f"Malformed tool call: arguments must be a JSON object. Reply was: {json.dumps(payload, default=str)[:400]}",
            )
        thought = payload.get("thought")
        return AgentAction(
            action_type="tool_call",
            tool_name=tool_name.strip(),
            arguments=dict(arguments),
            thought=str(thought) if thought else None,
        )

    # finish (explicit or unrecognized action types)
    message = payload.get("message") or payload.get("content") or fallback_text
    return AgentAction(
        action_type="finish",
        thought=str(payload.get("thought", "")) or None,
        message=str(message)[:500] if message else "Agent finished.",
    )
