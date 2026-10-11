"""Generate a domain specification (a sandbox twin) from an OpenAPI 3.x document.

Most agents call REST APIs, not MCP servers.  This module turns each OpenAPI
operation into a tool definition and hands it to
:func:`lifeforge.sandbox.domains.from_mcp.spec_from_mcp_tools`, so both
generators produce the same kind of twin:

* one tool per operation, named after ``operationId`` (or ``method_path``);
* arguments from path/query/header parameters and a JSON request body, with
  types and constraints carried over (local ``$ref`` pointers are resolved);
* ``GET``/``HEAD``/``OPTIONS`` operations are read-only; every other method is
  state-changing and gated behind ``request_human_approval``.

Like the MCP generator, the result is a starting point: it records calls but
does not know what an endpoint changes.  Edit the effects and policies, then
validate with ``lifeforge compile-domain --spec ... --check``.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lifeforge.mcpsec.manifest import McpToolDefinition
from lifeforge.sandbox.domains.from_mcp import spec_from_mcp_tools

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
READ_ONLY_METHODS = {"get", "head", "options", "trace"}
_PARAMETER_LOCATIONS = {"path", "query", "header"}
_MAX_REF_DEPTH = 32


class OpenAPISpecError(ValueError):
    """Raised when a document is not a usable OpenAPI 3.x description."""


def load_openapi(path: Path | str) -> dict[str, Any]:
    """Load an OpenAPI document from JSON or YAML."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        import yaml

        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise OpenAPISpecError(f"{path} does not contain an OpenAPI object.")
    return data


def _resolve(document: dict[str, Any], node: Any, depth: int = 0) -> Any:
    """Resolve local ``#/...`` references, recursively, with a depth guard."""
    if depth > _MAX_REF_DEPTH:
        return {}
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#/"):
                return {}  # external refs are not fetched
            target: Any = document
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or part not in target:
                    return {}
                target = target[part]
            return _resolve(document, target, depth + 1)
        return {key: _resolve(document, value, depth + 1) for key, value in node.items()}
    if isinstance(node, list):
        return [_resolve(document, item, depth + 1) for item in node]
    return node


def _tool_name(method: str, path: str, operation: dict[str, Any]) -> str:
    raw = operation.get("operationId") or f"{method}_{path}"
    name = re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9_]+", "_", str(raw))).strip("_")
    return (name or f"{method}_operation")[:64]


def _json_body_schema(operation: dict[str, Any]) -> dict[str, Any]:
    body = operation.get("requestBody") or {}
    content = body.get("content") or {}
    for media_type, media in content.items():
        if "json" in str(media_type).lower() and isinstance(media, dict):
            schema = media.get("schema")
            if isinstance(schema, dict):
                return schema
    return {}


def _input_schema(document: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []

    parameters = list(path_item.get("parameters") or []) + list(operation.get("parameters") or [])
    for raw in parameters:
        parameter = _resolve(document, raw)
        if not isinstance(parameter, dict) or parameter.get("in") not in _PARAMETER_LOCATIONS:
            continue
        name = str(parameter.get("name") or "")
        if not name:
            continue
        schema = dict(parameter.get("schema") or {})
        if parameter.get("description") and "description" not in schema:
            schema["description"] = parameter["description"]
        properties[name] = schema
        if parameter.get("required") or parameter.get("in") == "path":
            required.append(name)

    body = _resolve(document, _json_body_schema(operation))
    if isinstance(body, dict):
        for name, schema in (body.get("properties") or {}).items():
            properties.setdefault(str(name), schema if isinstance(schema, dict) else {})
        for name in body.get("required") or []:
            if str(name) in properties and str(name) not in required:
                required.append(str(name))

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def tools_from_openapi(document: dict[str, Any]) -> list[McpToolDefinition]:
    """Convert every operation in an OpenAPI 3.x document into a tool definition."""
    version = str(document.get("openapi", ""))
    if not version.startswith("3"):
        raise OpenAPISpecError(
            "Only OpenAPI 3.x documents are supported (found "
            f"{'openapi: ' + version if version else 'swagger 2.0 or no version field'})."
        )
    title = str((document.get("info") or {}).get("title") or "openapi")
    tools: list[McpToolDefinition] = []
    seen: set[str] = set()
    for path, raw_item in (document.get("paths") or {}).items():
        path_item = _resolve(document, raw_item)
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            name = _tool_name(method, str(path), operation)
            base, suffix = name, 2
            while name in seen:
                name = f"{base}_{suffix}"[:64]
                suffix += 1
            seen.add(name)
            description = operation.get("summary") or operation.get("description") or f"{method.upper()} {path}"
            tools.append(
                McpToolDefinition(
                    name=name,
                    description=f"{str(description).strip()} ({method.upper()} {path})",
                    input_schema=_input_schema(document, path_item, operation),
                    server=title,
                    annotations={"readOnlyHint": method in READ_ONLY_METHODS},
                )
            )
    if not tools:
        raise OpenAPISpecError("The document defines no operations under 'paths'.")
    return tools


def spec_from_openapi(document: dict[str, Any], *, name: str | None = None, task: str | None = None) -> dict[str, Any]:
    """Build a domain-spec dict (a twin) from an OpenAPI 3.x document."""
    tools = tools_from_openapi(document)
    spec = spec_from_mcp_tools(tools, name=name or tools[0].server, task=task)
    spec["domain"]["title"] = spec["domain"]["title"].replace("(MCP twin)", "(OpenAPI twin)")
    spec["domain"]["description"] = spec["domain"]["description"].replace("MCP tool definitions", "an OpenAPI document")
    return spec
