"""Static tool-definition extraction from MCP server source code.

Live probing is the gold standard, but many popular MCP servers refuse to
launch without API credentials. For those, this module extracts tool
definitions directly from source: TypeScript servers using the SDK's
``server.tool(...)`` / ``registerTool(...)`` / ``addTool(...)`` registration
patterns with zod schemas, and Python servers using the FastMCP
``@mcp.tool`` decorator.

Extraction is best-effort by design and states its coverage honestly: a
definition that does not match a known registration pattern is skipped, and
the caller records how many definitions each method recovered. The scanner
then runs on exactly what was extracted - the same ruleset as a live probe.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from .manifest import McpToolDefinition


class ExtractionStats:
    """Per-run counters so callers can state extraction coverage honestly."""

    def __init__(self) -> None:
        self.files_scanned = 0
        self.pattern_hits = 0
        self.pattern_misses = 0

    def to_dict(self) -> dict[str, int]:
        """Serialize the counters."""
        return {
            "files_scanned": self.files_scanned,
            "pattern_hits": self.pattern_hits,
            "pattern_misses": self.pattern_misses,
        }


# ---------------------------------------------------------------------------
# TypeScript extraction
# ---------------------------------------------------------------------------

_TS_TOOL_CALL = re.compile(
    r"""(?:server|\.|mcp)\s*\.\s*(?:tool|registerTool|addTool)\s*\(""",
)
_TS_STRING = r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`'


def _skip_string(src: str, start: int) -> int:
    """Return the index just past the string/regex token starting at ``start``."""
    quote = src[start]
    index = start + 1
    while index < len(src):
        char = src[index]
        if char == "\\":
            index += 2
            continue
        if quote == "/" and char == "\n":  # regex literal hit a newline: not a regex
            return start + 1
        if char == quote:
            return index + 1
        index += 1
    return start + 1


def _balanced_braces(src: str, open_index: int) -> int:
    """Return the index of the brace closing the one at ``open_index``.

    Tracks nesting inside strings, template literals, and comments so zod
    chains containing braces in describe() text do not truncate the object.
    """
    depth = 0
    index = open_index
    length = len(src)
    while index < length:
        char = src[index]
        if char in "\"'`/":
            index = _skip_string(src, index)
            continue
        if src.startswith("//", index):
            end = src.find("\n", index)
            index = length if end == -1 else end + 1
            continue
        if src.startswith("/*", index):
            end = src.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _balanced_parens(src: str, open_index: int) -> int:
    """Return the index of the paren closing the one at ``open_index``.

    Strings, template literals, comments, and brace/bracket nesting are all
    tracked; only the paren depth decides the match, so object literals and
    arrow-function bodies inside the argument list cannot terminate the scan
    early.
    """
    depth = 0
    index = open_index
    length = len(src)
    while index < length:
        char = src[index]
        if char in "\"'`/":
            index = _skip_string(src, index)
            continue
        if src.startswith("//", index):
            end = src.find("\n", index)
            index = length if end == -1 else end + 1
            continue
        if src.startswith("/*", index):
            end = src.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _split_top_level(body: str) -> list[str]:
    """Split a brace body on top-level commas, respecting strings and nesting."""
    parts: list[str] = []
    depth = 0
    in_string = False
    quote = ""
    escape = False
    current: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if in_string:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                in_string = False
            index += 1
            continue
        if char in "\"'`":
            in_string = True
            quote = char
            current.append(char)
            index += 1
            continue
        if char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


_ZOD_PRIMITIVES = {
    "string": "string",
    "number": "number",
    "boolean": "boolean",
    "bigint": "integer",
    "date": "string",
    "any": "string",
    "unknown": "string",
}


def _zod_to_schema(expr: str) -> dict[str, Any]:
    """Convert a zod expression to a JSON-schema fragment (best effort).

    Covers the property-level constructs that dominate real servers: primitive
    types, enums, arrays, optional/default (required-ness), describe, min/max.
    Unrecognized constructs degrade to an untyped property rather than failing.
    """
    schema: dict[str, Any] = {"type": "string"}
    text = expr.strip()

    # Strip chained modifiers from the end while collecting their effects.
    optional = False
    description: str | None = None
    for _ in range(8):
        matched = False
        if text.endswith(".optional()"):
            optional = True
            text = text[: -len(".optional()")]
            matched = True
        elif text.endswith(".nullable()"):
            optional = True
            text = text[: -len(".nullable()")]
            matched = True
        else:
            describe_match = re.search(r"\.describe\(\s*(" + _TS_STRING + r")\s*\)$", text)
            if describe_match:
                description = describe_match.group(1)[1:-1]
                text = text[: describe_match.start()]
                matched = True
        if not matched:
            break

    core = text.strip()
    enum_match = re.match(r"z\.enum\(\[(.*)\]\)", core, re.DOTALL)
    array_match = re.match(r"z\.array\(\s*(.*)\s*\)$", core, re.DOTALL)

    if enum_match:
        schema = {"type": "string", "enum": [item.strip().strip("\"'") for item in enum_match.group(1).split(",") if item.strip()]}
    elif array_match:
        inner = _zod_to_schema(array_match.group(1))
        schema = {"type": "array", "items": inner}
    else:
        type_match = re.match(r"z\.(\w+)", core)
        if type_match and type_match.group(1) in _ZOD_PRIMITIVES:
            schema = {"type": _ZOD_PRIMITIVES[type_match.group(1)]}
        elif type_match and type_match.group(1) == "object":
            schema = {"type": "object"}
        else:
            # z.string().email() etc. or custom validators: keep type when the
            # base primitive is recognizable, else leave untyped.
            base = type_match.group(1) if type_match else ""
            schema = {"type": _ZOD_PRIMITIVES.get(base, "string")}

    min_match = re.search(r"\.min\(\s*(\d+)", core)
    max_match = re.search(r"\.max\(\s*(\d+)", core)
    if min_match and schema.get("type") in ("string", "array"):
        schema["minLength" if schema["type"] == "string" else "minItems"] = int(min_match.group(1))
    if max_match and schema.get("type") in ("string", "array"):
        schema["maxLength" if schema["type"] == "string" else "maxItems"] = int(max_match.group(1))
    if description:
        schema["description"] = description

    schema["_optional"] = optional
    return schema


def _props_body_to_schema(body: str) -> dict[str, Any]:
    """Convert a zod properties object body into a JSON-schema properties map."""
    properties: dict[str, Any] = {}
    for part in _split_top_level(body):
        if not part or ":" not in part:
            continue
        name, expr = part.split(":", 1)
        name = name.strip().strip("\"'")
        if not re.match(r"^\w+$", name):
            continue
        prop = _zod_to_schema(expr)
        optional = prop.pop("_optional", False)
        prop["required"] = not optional
        properties[name] = prop
    return properties


def _register_call_schema(args_body: str) -> tuple[str, str, dict[str, Any]] | None:
    """Parse registerTool/addTool-style calls.

    Supported shapes: ``(name, config-object)``, ``(name, desc, schema)``, and
    the fastmcp single-object form ``addTool({ name, description, parameters })``.
    """
    parts = _split_top_level(args_body)
    if not parts:
        return None

    # Single-object form: addTool({ name: "...", description: "...", parameters: ... })
    if parts[0].strip().startswith("{"):
        config = parts[0].strip()
        name_match = re.search(r"\bname\s*:\s*(" + _TS_STRING + r")", config)
        if not name_match:
            return None
        name = name_match.group(1)[1:-1]
        description_match = re.search(r"description\s*:\s*(" + _TS_STRING + r")", config, re.DOTALL)
        description = description_match.group(1)[1:-1] if description_match else ""
        schema_props: dict[str, Any] = {}

        parameters_match = re.search(r"parameters\s*:\s*", config)
        if parameters_match:
            open_brace = _first_opening_brace(config, parameters_match.end())
            if open_brace != -1:
                close_brace = _balanced_braces(config, open_brace)
                if close_brace != -1:
                    body = config[open_brace + 1: close_brace]
                    if re.match(r"\s*z\s*\.\s*object\b", body):
                        body = _zod_object_body(body)
                    schema_props = _props_body_to_schema(body)

        return name, description, schema_props

    name_match = re.match(r"^(?:\"([^\"]+)\"|'([^']+)'|`([^`]+)`)$", parts[0].strip())
    if not name_match:
        return None
    name = next(group for group in name_match.groups() if group is not None)

    if len(parts) >= 2 and parts[1].strip().startswith("{"):
        config = parts[1].strip()
        description = ""
        schema_props: dict[str, Any] = {}

        description_match = re.search(r"description\s*:\s*(" + _TS_STRING + r")", config, re.DOTALL)
        if description_match:
            description = description_match.group(1)[1:-1]

        input_schema_match = re.search(r"inputSchema\s*:\s*\{", config)
        if input_schema_match:
            open_index = config.index("{", input_schema_match.end() - 1)
            close_index = _balanced_braces(config, open_index)
            if close_index != -1:
                schema_props = _props_body_to_schema(config[open_index + 1: close_index])

        return name, description, schema_props

    if len(parts) >= 3 and parts[2].strip().startswith("{"):
        description = parts[1].strip().strip("\"'`")
        open_index = parts[2].index("{")
        close_index = _balanced_braces(parts[2], open_index)
        schema_props = _props_body_to_schema(parts[2][open_index + 1: close_index]) if close_index != -1 else {}
        return name, description, schema_props

    return None


def _first_opening_brace(src: str, start: int) -> int:
    """Index of the first ``{`` at or after ``start`` (top-level of the value)."""
    return src.find("{", start)


def _zod_object_body(expr: str) -> str:
    """Reduce ``z.object({ ... })`` (with chained modifiers) to the props body."""
    open_index = expr.find("{")
    close_index = _balanced_braces(expr, open_index)
    if open_index == -1 or close_index == -1:
        return expr
    return expr[open_index + 1: close_index]


# ---------------------------------------------------------------------------
# Legacy SDK pattern: setRequestHandler(ListToolsRequestSchema, ...)
# ---------------------------------------------------------------------------

_TS_ZOD_OBJECT = re.compile(
    r"(?:export\s+)?(?:const|var)\s+(\w+)\s*(?::[^=]+)?=\s*z\s*\.\s*object\s*\(",
)
_TS_IMPORT_STAR = re.compile(
    r"import\s+\*\s+as\s+(\w+)\s+from\s+[\"']([^\"']+)[\"']",
)


def _resolve_ts_import(file_path: Path, relative: str) -> Path | None:
    """Resolve a relative TS import specifier to a sibling source file."""
    base = file_path.parent / relative
    for candidate in (base, base.with_suffix(".ts"), base.with_suffix(".tsx")):
        if candidate.is_file():
            return candidate
    plain = str(base)
    for suffix in (".js", ".mjs"):
        if plain.endswith(suffix):
            candidate = Path(plain[: -len(suffix)] + ".ts")
            if candidate.is_file():
                return candidate
    return None


def _unquote(text: str) -> str:
    """Strip one layer of matching quotes from a string literal."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`":
        return text[1:-1]
    return text


def collect_zod_objects(source: str) -> dict[str, str]:
    """Map exported ``z.object`` constant names to their property bodies."""
    objects: dict[str, str] = {}
    for match in _TS_ZOD_OBJECT.finditer(source):
        name = match.group(1)
        open_index = source.index("(", match.end() - 1)
        close_index = _balanced_parens(source, open_index)
        if close_index == -1:
            continue
        body = source[open_index + 1: close_index]
        inner_open = body.find("{")
        if inner_open != -1:
            inner_close = _balanced_braces(body, inner_open)
            if inner_close != -1:
                body = body[inner_open + 1: inner_close]
        objects.setdefault(name, body)
    return objects


def collect_object_consts(source: str) -> dict[str, str]:
    """Map ``const NAME[: Type] = { ... }`` or ``= [ ... ]`` bodies.

    Some servers declare their tools as typed object constants (or a single
    array constant of them) and return identifiers from the ListTools
    handler. Bodies are captured raw; callers parse the tool fields they
    need.
    """
    consts: dict[str, str] = {}
    pattern = re.compile(r"(?:export\s+)?const\s+(\w+)\s*(?::\s*[A-Za-z_][\w.<>[\]]*)?\s*=\s*([\{\[])")
    for match in pattern.finditer(source):
        open_char = match.group(2)
        close_char = "}" if open_char == "{" else "]"
        open_index = source.index(open_char, match.end() - 1)
        depth = 0
        close_index = -1
        for index in range(open_index, len(source)):
            if source[index] == open_char:
                depth += 1
            elif source[index] == close_char:
                depth -= 1
                if depth == 0:
                    close_index = index
                    break
        if close_index == -1:
            continue
        consts.setdefault(match.group(1), source[open_index + 1: close_index])
    return consts


def _json_schema_from_inputschema(body: str) -> dict[str, Any]:
    """Parse a plain JSON-schema ``inputSchema`` literal into a schema fragment.

    Used for servers that declare tools as typed constants with hand-written
    JSON schemas (``type``/``properties``/``required``), as opposed to zod.
    The inputSchema object is split at its own top level first, so the
    ``properties`` entry is the schema's own - never a nested or quoted
    occurrence elsewhere in the tool constant.
    """
    schema_match = re.search(r"inputSchema\s*:\s*\{", body)
    if not schema_match:
        return {}
    schema_open = body.index("{", schema_match.end() - 1)
    schema_close = _balanced_braces(body, schema_open)
    if schema_close == -1:
        return {}
    schema_body = body[schema_open + 1: schema_close]

    props_body: str | None = None
    required: list[str] = []
    for entry in _split_top_level(schema_body):
        key, _, rest = entry.partition(":")
        key = key.strip().strip("\"'")
        if key == "properties":
            candidate = rest.strip()
            if candidate.startswith("{"):
                open_index = candidate.find("{")
                close_index = _balanced_braces(candidate, open_index)
                if close_index != -1:
                    props_body = candidate[open_index + 1: close_index]
        elif key == "required":
            required_match = re.search(r"\[([^\]]*)\]", rest, re.DOTALL)
            if required_match:
                required = [item.strip().strip("\"'") for item in required_match.group(1).split(",") if item.strip()]

    properties: dict[str, Any] = {}
    if props_body is not None:
        for part in _split_top_level(props_body):
            if ":" not in part:
                continue
            name, rest = part.split(":", 1)
            name = name.strip().strip("\"'")
            if not re.match(r"^\w+$", name):
                continue
            prop: dict[str, Any] = {}
            type_match = re.search(r"\btype\s*:\s*[\"'](\w+)[\"']", rest)
            if type_match:
                prop["type"] = type_match.group(1)
            description_match = re.search(r"description\s*:\s*(" + _TS_STRING + r")", rest, re.DOTALL)
            if description_match:
                prop["description"] = _unquote(description_match.group(1))
            enum_match = re.search(r"\benum\s*:\s*\[([^\]]*)\]", rest, re.DOTALL)
            if enum_match:
                prop["enum"] = [item.strip().strip("\"'") for item in enum_match.group(1).split(",") if item.strip()]
            properties[name] = prop

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def extract_listtools_tools(
    source: str,
    file_path: Path,
    zod_objects: dict[Path, dict[str, str]],
    *,
    server: str = "default",
    stats: ExtractionStats | None = None,
) -> list[McpToolDefinition]:
    """Extract tools from a ``setRequestHandler(ListToolsRequestSchema, ...)`` handler.

    The handler returns a literal ``tools: [...]`` array whose entries carry
    inline ``inputSchema`` objects or ``zodToJsonSchema(Alias.Schema)``
    references. References resolve against ``zod_objects`` - parsed TS files
    mapped to their exported ``z.object`` bodies - via the file's
    ``import * as`` aliases.
    """
    stats = stats or ExtractionStats()

    handler_match = re.search(r"setRequestHandler\s*\(\s*ListToolsRequestSchema", source)
    if not handler_match:
        return []
    # The call's opening paren sits before the schema constant; searching
    # forward would find the arrow function's parameter list instead.
    call_open = source.index("(", handler_match.start())
    call_close = _balanced_parens(source, call_open)
    if call_close == -1:
        return []

    handler_body = source[call_open: call_close]

    object_consts = collect_object_consts(source)

    tools_array = re.search(r"tools\s*:\s*", handler_body)
    if not tools_array:
        return []
    value_start = tools_array.end()
    if handler_body[value_start: value_start + 1] == "[":
        array_open = value_start
    else:
        # The array is held in an identifier (e.g. ``tools: MAPS_TOOLS``):
        # resolve it through the file's object constants.
        identifier_match = re.match(r"(\w+)", handler_body[value_start:])
        if not identifier_match:
            return []
        referred = object_consts.get(identifier_match.group(1))
        if referred is None:
            return []
        # Re-express the array body in the same coordinates as a literal.
        handler_body = "[" + referred + "]"
        array_open = 0
    depth = 0
    array_close = -1
    for index in range(array_open, len(handler_body)):
        if handler_body[index] == "[":
            depth += 1
        elif handler_body[index] == "]":
            depth -= 1
            if depth == 0:
                array_close = index
                break
    if array_close == -1:
        return []

    aliases: dict[str, Path] = {}
    for alias_match in _TS_IMPORT_STAR.finditer(source):
        resolved = _resolve_ts_import(file_path, alias_match.group(2))
        if resolved is not None:
            aliases[alias_match.group(1)] = resolved

    # Tool objects referenced by identifier from the tools array (some servers
    # declare them as typed consts rather than inline literals).
    object_consts = collect_object_consts(source)

    tools: list[McpToolDefinition] = []
    for entry in _split_top_level(handler_body[array_open + 1: array_close]):
        entry = entry.strip().rstrip(",")
        if not entry:
            continue
        if entry.startswith("{"):
            body = entry
        else:
            identifier = entry.strip()
            if not re.match(r"^\w+$", identifier):
                stats.pattern_misses += 1
                continue
            body = object_consts.get(identifier)
            if body is None:
                stats.pattern_misses += 1
                continue

        name_match = re.search(r"\bname\s*:\s*[\"']([^\"']+)[\"']", body)
        if not name_match:
            stats.pattern_misses += 1
            continue
        name = name_match.group(1)

        description = ""
        description_match = re.search(r"description\s*:\s*(" + _TS_STRING + r")", body, re.DOTALL)
        if description_match:
            description = _unquote(description_match.group(1))

        schema_props: dict[str, Any] = {}
        zod_ref = re.search(r"zodToJsonSchema\s*\(\s*(\w+)\s*\.\s*(\w+)\s*\)", body)
        input_schema = re.search(r"inputSchema\s*:\s*\{", body)
        if zod_ref:
            module_path = aliases.get(zod_ref.group(1))
            zod_body = (zod_objects.get(module_path) or {}).get(zod_ref.group(2))
            if zod_body is not None:
                schema_props = _props_body_to_schema(zod_body)
        elif input_schema:
            schema_props = _json_schema_from_inputschema(body)
            if not schema_props.get("properties"):
                # Not a plain JSON schema (e.g. a zod expression inline):
                # fall back to the zod properties parse over the schema object.
                open_index = body.index("{", input_schema.end() - 1)
                close_index = _balanced_braces(body, open_index)
                if close_index != -1:
                    schema_props = _props_body_to_schema(body[open_index + 1: close_index])

        # Defensive: a props entry that survived parsing as a non-dict (deeply
        # nested or string-embedded schema fragment) is dropped rather than
        # crashing the scan; the dropped count stays visible in the stats.
        malformed = [key for key, spec in schema_props.items() if not isinstance(spec, dict)]
        for key in malformed:
            del schema_props[key]
        stats.pattern_misses += len(malformed)

        required = sorted(
            prop
            for prop, spec in schema_props.items()
            if isinstance(spec, dict) and spec.pop("required", True)
        )
        schema: dict[str, Any] = {"type": "object", "properties": schema_props}
        if required:
            schema["required"] = required

        tools.append(
            McpToolDefinition(name=name, description=description, input_schema=schema, server=server)
        )
        stats.pattern_hits += 1

    return tools


def extract_tools_typescript(source: str, *, server: str = "default", stats: ExtractionStats | None = None) -> list[McpToolDefinition]:
    """Extract tool definitions from TypeScript MCP server source."""
    stats = stats or ExtractionStats()
    tools: list[McpToolDefinition] = []
    seen_spans: list[tuple[int, int]] = []

    for match in _TS_TOOL_CALL.finditer(source):
        call_open = source.index("(", match.end() - 1)
        call_close = _balanced_parens(source, call_open)
        if call_close == -1:
            continue
        span = (match.start(), call_close)
        if any(span[0] < other[1] and other[0] < span[1] for other in seen_spans):
            continue  # inner registration already captured

        args_body = source[call_open + 1: call_close]
        parsed = _register_call_schema(args_body)
        if parsed is None:
            stats.pattern_misses += 1
            continue
        name, description, properties = parsed
        if not properties:
            stats.pattern_misses += 1
            continue

        required = sorted(prop_name for prop_name, spec in properties.items() if spec.pop("required", True))
        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required

        tools.append(
            McpToolDefinition(
                name=name,
                description=description,
                input_schema=schema,
                server=server,
            )
        )
        stats.pattern_hits += 1
        seen_spans.append(span)

    return tools


# ---------------------------------------------------------------------------
# Python (FastMCP) extraction
# ---------------------------------------------------------------------------

_PY_ANNOTATIONS = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
    "List": "array",
    "Dict": "object",
}


def _annotation_to_schema(annotation: ast.expr | None) -> dict[str, Any]:
    """Map a Python annotation to a JSON-schema fragment (best effort)."""
    if annotation is None:
        return {"type": "string"}
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return {"type": "string"}
    if isinstance(annotation, ast.Name):
        return {"type": _PY_ANNOTATIONS.get(annotation.id, "string")}
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return {"type": _PY_ANNOTATIONS.get(annotation.value, "string")}
    if isinstance(annotation, ast.Subscript):
        origin = annotation.value
        origin_name = getattr(origin, "id", getattr(origin, "attr", ""))
        if origin_name in ("list", "List"):
            return {"type": "array", "items": _annotation_to_schema(annotation.slice)}
        if origin_name in ("dict", "Dict"):
            return {"type": "object"}
        if origin_name in ("Optional", "Union"):
            inner = _annotation_to_schema(annotation.slice)
            inner["_optional"] = True
            return inner
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        left = _annotation_to_schema(annotation.left)
        right = annotation.right
        if isinstance(right, ast.Constant) and right.value is None:
            left["_optional"] = True
            return left
        return left
    return {"type": "string"}


def _is_tool_decorator(decorator: ast.expr) -> bool:
    """Match @mcp.tool / @app.tool / @tool / @mcp.tool(...) decorators."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute):
        return target.attr == "tool"
    if isinstance(target, ast.Name):
        return target.id == "tool"
    return False


def extract_tools_python(source: str, *, server: str = "default", stats: ExtractionStats | None = None) -> list[McpToolDefinition]:
    """Extract tool definitions from Python FastMCP-style source."""
    stats = stats or ExtractionStats()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    tools: list[McpToolDefinition] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_tool_decorator(decorator) for decorator in node.decorator_list):
            continue

        description = (ast.get_docstring(node) or "").strip()
        if not description:
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    for keyword in decorator.keywords:
                        if keyword.arg == "description" and isinstance(keyword.value, ast.Constant):
                            description = str(keyword.value.value)

        properties: dict[str, Any] = {}
        required: list[str] = []
        positional = list(node.args.args)
        pos_defaults = list(node.args.defaults or [])
        offset = len(positional) - len(pos_defaults)
        default_map: dict[str, bool] = {
            arg.arg: index >= offset for index, arg in enumerate(positional)
        }
        for kwarg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            default_map[kwarg.arg] = default is not None

        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg in ("self", "cls", "ctx", "context"):
                continue
            spec = _annotation_to_schema(arg.annotation)
            optional = spec.pop("_optional", False) or default_map.get(arg.arg, False)
            spec["required"] = not optional
            properties[arg.arg] = spec
            if not optional:
                required.append(arg.arg)

        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required

        tools.append(
            McpToolDefinition(
                name=node.name,
                description=description,
                input_schema=schema,
                server=server,
            )
        )
        stats.pattern_hits += 1

    return tools


# ---------------------------------------------------------------------------
# Filesystem entry points
# ---------------------------------------------------------------------------

_TS_EXTENSIONS = {".ts", ".tsx", ".mts", ".js", ".mjs"}
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".venv", "__pycache__"}


def extract_from_directory(
    repo_dir: Path,
    *,
    subdir: str = "",
    language: str | None = None,
    max_files: int = 400,
) -> tuple[list[McpToolDefinition], ExtractionStats]:
    """Walk a repo (or repo subdirectory) and extract tool definitions.

    ``language`` forces ``"typescript"`` or ``"python"``; by default both
    extractors run over their respective file types and the results merge.
    TypeScript extraction covers both the registration-call patterns
    (``server.tool`` / ``registerTool`` / ``addTool``) and the legacy
    ``ListToolsRequestSchema`` handler, resolving ``zodToJsonSchema`` module
    references across files.
    """
    root = Path(repo_dir) / subdir if subdir else Path(repo_dir)
    stats = ExtractionStats()
    tools: list[McpToolDefinition] = []

    paths = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not (set(path.parts) & _SKIP_DIRS)
        and (
            (language in (None, "typescript") and path.suffix in _TS_EXTENSIONS)
            or (language in (None, "python") and path.suffix == ".py")
        )
    )[:max_files]

    ts_sources: dict[Path, str] = {}
    for path in paths:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        stats.files_scanned += 1
        if path.suffix == ".py":
            tools.extend(extract_tools_python(source, server=root.name, stats=stats))
        else:
            ts_sources[path] = source
            tools.extend(extract_tools_typescript(source, server=root.name, stats=stats))

    # Second TS pass: the legacy ListToolsRequestSchema handler, with zod
    # object bodies indexed across every scanned file so cross-module
    # zodToJsonSchema references resolve.
    if ts_sources:
        zod_index = {path: collect_zod_objects(source) for path, source in ts_sources.items()}
        for path, source in ts_sources.items():
            tools.extend(
                extract_listtools_tools(source, path, zod_index, server=root.name, stats=stats)
            )

    # Deduplicate across files (same tool name registered once, defined once).
    unique: dict[str, McpToolDefinition] = {}
    for tool in tools:
        unique.setdefault(tool.name, tool)
    return list(unique.values()), stats
