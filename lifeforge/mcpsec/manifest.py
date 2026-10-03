"""Manifest and tool-definition model for MCP security scanning.

An MCP *manifest* is any source of tool definitions in the MCP wire format:
a checked-in JSON file, the response to a ``tools/list`` request, or a bundle
of several servers' tools. Everything the scanner analyzes is normalized into
:class:`McpToolDefinition` so detectors never care where the definitions came
from.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class McpToolDefinition:
    """One tool definition exactly as an MCP server publishes it."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    server: str = "default"
    annotations: dict[str, Any] = field(default_factory=dict)

    def properties(self) -> dict[str, Any]:
        """Return the JSON-schema properties of the input schema."""
        schema = self.input_schema or {}
        props = schema.get("properties")
        return props if isinstance(props, dict) else {}

    def required_arguments(self) -> list[str]:
        """Return the schema's required argument names."""
        schema = self.input_schema or {}
        required = schema.get("required")
        if isinstance(required, list):
            return [str(item) for item in required]
        return []

    def to_dict(self) -> dict[str, Any]:
        """Serialize back to the MCP wire shape."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "server": self.server,
            "annotations": self.annotations,
        }


@dataclass
class McpServerManifest:
    """A normalized set of tool definitions from one or more MCP servers."""

    tools: list[McpToolDefinition] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)
    source: str = "manifest"
    protocol_version: str = ""
    probe_result: dict[str, Any] | None = None

    def server_names(self) -> list[str]:
        """Return the distinct servers contributing tool definitions."""
        return sorted({tool.server for tool in self.tools})

    def to_dict(self) -> dict[str, Any]:
        """Serialize the manifest for JSON reports."""
        return {
            "source": self.source,
            "server_info": self.server_info,
            "protocol_version": self.protocol_version,
            "tool_count": len(self.tools),
            "tools": [tool.to_dict() for tool in self.tools],
        }


def tools_from_wire(raw_tools: list[dict[str, Any]], server: str = "default") -> list[McpToolDefinition]:
    """Normalize a raw ``tools`` list from the MCP wire format.

    Tolerates both ``inputSchema`` (spec) and ``parameters_schema`` (older
    convention) keys, and skips malformed entries rather than failing a scan
    because one tool definition is broken - a scanner that crashes on its
    subject is useless.
    """
    tools: list[McpToolDefinition] = []
    for entry in raw_tools or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        schema = entry.get("inputSchema")
        if not isinstance(schema, dict):
            schema = entry.get("parameters_schema")
        if not isinstance(schema, dict):
            schema = {}
        tools.append(
            McpToolDefinition(
                name=name,
                description=str(entry.get("description", "") or ""),
                input_schema=schema,
                server=str(entry.get("server", server) or server),
                annotations=entry.get("annotations") if isinstance(entry.get("annotations"), dict) else {},
            )
        )
    return tools


def manifest_from_file(path: Path | str) -> McpServerManifest:
    """Load a manifest from a JSON file.

    Accepted shapes:

    * ``{"tools": [...]}`` - a single server's tool list
    * ``[...]`` - a bare list of tool definitions
    * ``{"servers": {"name": {"tools": [...]}}}`` - a multi-server bundle, used
      for cross-server shadowing analysis
    """
    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    if isinstance(data, list):
        return McpServerManifest(tools=tools_from_wire(data), source=str(manifest_path))

    if isinstance(data, dict) and isinstance(data.get("servers"), dict):
        tools: list[McpToolDefinition] = []
        for server_name, server_def in data["servers"].items():
            if isinstance(server_def, dict):
                tools.extend(tools_from_wire(server_def.get("tools") or [], server=str(server_name)))
        return McpServerManifest(tools=tools, source=str(manifest_path))

    if isinstance(data, dict):
        tools = tools_from_wire(data.get("tools") or [])
        return McpServerManifest(
            tools=tools,
            server_info=data.get("serverInfo") if isinstance(data.get("serverInfo"), dict) else {},
            source=str(manifest_path),
        )

    raise ValueError(f"Unrecognized manifest shape in {manifest_path}: expected object or list.")
