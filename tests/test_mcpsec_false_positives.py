"""Regression tests for the mcpsec 1.2.0 destructive-rule and extraction fixes.

Each case comes from a real definition that ruleset 1.1.0 misjudged in the
October 2026 ecosystem scan (Desktop Commander, firecrawl, server-filesystem).
"""
from __future__ import annotations

from pathlib import Path

from lifeforge.mcpsec import scan_tool_definitions
from lifeforge.mcpsec.detectors import detect_unconstrained_destructive
from lifeforge.mcpsec.extract import (
    _balanced_braces,
    _split_top_level,
    collect_zod_objects,
    extract_from_directory,
)
from lifeforge.mcpsec.manifest import McpToolDefinition

SCHEMA = {"type": "object", "properties": {"id": {"type": "string", "maxLength": 9}}, "required": ["id"]}


def _tool(name: str, description: str, annotations: dict | None = None) -> McpToolDefinition:
    return McpToolDefinition(name=name, description=description, input_schema=SCHEMA, annotations=annotations or {})


# ---------------------------------------------------------------------------
# Destructive rule
# ---------------------------------------------------------------------------


def test_read_only_hint_is_not_destructive():
    tool = _tool("start_search", "Start a search that can run in the background.", {"readOnlyHint": True})
    assert detect_unconstrained_destructive(tool) == []


def test_read_named_tool_judged_by_name_not_description():
    tool = _tool("firecrawl_search", "Search the web. A scrape with an alexandria body executes a capability.")
    assert detect_unconstrained_destructive(tool) == []


def test_past_participles_are_adjectives_not_actions():
    tool = _tool("firecrawl_credit_usage", "Report credits. Extra purchased or granted credits raise the balance.")
    assert detect_unconstrained_destructive(tool) == []
    tool = _tool("developer_lookup", "Index of merged pull requests.")
    assert detect_unconstrained_destructive(tool) == []


def test_only_the_lead_sentence_describes_the_capability():
    tool = _tool("firecrawl_parse", "Parse one document into markdown. Do not send both fields together.")
    assert detect_unconstrained_destructive(tool) == []
    tool = _tool("firecrawl_interact", "Open a browser session to click controls or run browser code.")
    assert [f.severity for f in detect_unconstrained_destructive(tool)] == ["HIGH"]


def test_destructive_hint_alone_is_medium_with_server_side_advice():
    tool = _tool("write_file", "Create or overwrite a file.", {"readOnlyHint": False, "destructiveHint": True})
    findings = detect_unconstrained_destructive(tool)
    assert [f.severity for f in findings] == ["MEDIUM"]
    assert findings[0].evidence["destructive_hint"] is True
    assert "Keep destructiveHint" in findings[0].remediation


def test_destructive_hint_flags_tools_whose_name_says_nothing():
    tool = _tool("move_file", "Move a file.", {"destructiveHint": True})
    assert [f.severity for f in detect_unconstrained_destructive(tool)] == ["MEDIUM"]


def test_destructive_name_without_hint_stays_high():
    tool = _tool("monitor_delete", "Delete a monitor.")
    assert [f.severity for f in detect_unconstrained_destructive(tool)] == ["HIGH"]


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_apostrophe_in_comment_does_not_open_a_string():
    source = "{\n  // the server's own pid\n  pid: z.number(),\n}"
    assert _balanced_braces(source, 0) == len(source) - 1
    assert _split_top_level("// it's a note\n a: 1, b: 2") == ["a: 1", "b: 2"]


def test_zod_object_after_commented_field_is_its_own_body():
    source = (
        "export const Kill = z.object({\n  // 0 is the server's own group\n  pid: z.number(),\n});\n"
        "export const Read = z.object({ path: z.string() });\n"
    )
    objects = collect_zod_objects(source)
    assert "Read" not in objects["Kill"]
    assert "pid" in objects["Kill"]


DESKTOP_COMMANDER_STYLE = {
    "schemas.ts": (
        "export const KillArgs = z.object({\n  // can't be 0: that is the server's group\n  pid: z.number(),\n});\n"
        "export const SearchArgs = z.object({ pattern: z.string() });\n"
    ),
    "server.ts": """
import { KillArgs, SearchArgs as Find } from './schemas.js';
server.setRequestHandler(ListToolsRequestSchema, async () => {
    const allTools = [
        // Process tools
        {
            name: "kill_process",
            description: `Terminate a process.`,
            inputSchema: zodToJsonSchema(KillArgs),
            annotations: { readOnlyHint: false, destructiveHint: true },
        },
        // Search tools
        {
            name: "start_search",
            description: `Start a search; results run in the background.`,
            inputSchema: zodToJsonSchema(Find),
            annotations: { title: "Search", readOnlyHint: true },
        },
    ];
    const filteredTools = allTools.filter(tool => keep(tool.name));
    return { tools: filteredTools };
});
""",
}


def test_listtools_handler_with_local_array_named_imports_and_comments(tmp_path: Path):
    for name, text in DESKTOP_COMMANDER_STYLE.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    tools, stats = extract_from_directory(tmp_path, language="typescript")
    by_name = {tool.name: tool for tool in tools}
    assert set(by_name) == {"kill_process", "start_search"}
    assert stats.pattern_misses == 0
    assert by_name["kill_process"].input_schema["required"] == ["pid"]
    assert by_name["kill_process"].annotations == {"readOnlyHint": False, "destructiveHint": True}
    assert set(by_name["start_search"].input_schema["properties"]) == {"pattern"}
    assert by_name["start_search"].annotations == {"readOnlyHint": True}

    report = scan_tool_definitions(tools, source="fixture").to_dict()
    destructive = [f for f in report["findings"] if f["rule_id"] == "MCP_DESTRUCTIVE_UNCONSTRAINED"]
    assert [(f["tool"], f["severity"]) for f in destructive] == [("kill_process", "MEDIUM")]


def test_unresolved_zod_reference_is_counted_as_a_miss(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [\n'
        '  { name: "x", description: "d", inputSchema: zodToJsonSchema(Missing) },\n'
        ']}));\n',
        encoding="utf-8",
    )
    tools, stats = extract_from_directory(tmp_path, language="typescript")
    assert [tool.name for tool in tools] == ["x"]
    assert stats.pattern_misses == 1


def test_fastmcp_addtool_annotations_are_read(tmp_path: Path):
    (tmp_path / "tools.ts").write_text(
        """
server.addTool({
  name: 'firecrawl_interact',
  description: 'Open a browser session to click controls or run browser code.',
  parameters: z.object({ url: z.string().max(2048) }),
  annotations: {
    title: "Interact", // a comment with an apostrophe: it's fine
    readOnlyHint: false,
    destructiveHint: false,
  },
  execute: async () => '',
});
""",
        encoding="utf-8",
    )
    tools, _ = extract_from_directory(tmp_path, language="typescript")
    assert [tool.name for tool in tools] == ["firecrawl_interact"]
    assert tools[0].annotations == {"readOnlyHint": False, "destructiveHint": False}
