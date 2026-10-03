"""Tests for MCP source extraction (mcpsec/extract.py) and ecosystem aggregation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from lifeforge.mcpsec.extract import (
    ExtractionStats,
    extract_from_directory,
    extract_tools_python,
    extract_tools_typescript,
)


def _load_script():
    """Load scripts/scan_mcp_ecosystem.py as a module for pure-function tests."""
    path = Path(__file__).resolve().parent.parent / "scripts" / "scan_mcp_ecosystem.py"
    spec = importlib.util.spec_from_file_location("scan_mcp_ecosystem", path)
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["scan_mcp_ecosystem"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# TypeScript extraction
# ---------------------------------------------------------------------------


class TestTypeScriptExtraction:
    def test_server_tool_pattern_with_zod(self):
        source = '''
server.tool("search_docs", "Search the documentation.", {
  query: z.string().min(1).describe("The query"),
  limit: z.number().max(50).optional(),
  mode: z.enum(["fast", "deep"]),
}, async ({ query }) => { return results; });
'''
        tools = extract_tools_typescript(source)
        assert [tool.name for tool in tools] == ["search_docs"]
        schema = tools[0].input_schema
        assert schema["required"] == ["mode", "query"]
        assert schema["properties"]["limit"]["type"] == "number"
        assert schema["properties"]["mode"]["enum"] == ["fast", "deep"]
        assert schema["properties"]["query"]["description"] == "The query"

    def test_register_tool_pattern(self):
        source = '''
server.registerTool("delete_record", {
  title: "Delete",
  description: "Deletes a record permanently.",
  inputSchema: { id: z.string(), confirm: z.boolean().optional() },
}, handler);
'''
        tools = extract_tools_typescript(source)
        assert [tool.name for tool in tools] == ["delete_record"]
        assert tools[0].input_schema["required"] == ["id"]
        assert tools[0].description == "Deletes a record permanently."

    def test_braces_inside_describe_do_not_truncate(self):
        source = '''
server.tool("weird", "Format like {object} or {\"nested\": true}.", {
  q: z.string(),
}, handler);
'''
        tools = extract_tools_typescript(source)
        assert tools and tools[0].input_schema["properties"]["q"]["type"] == "string"

    def test_no_matches_returns_empty(self):
        assert extract_tools_typescript("const x = 1; // no tools here") == []

    def test_unmatched_registration_is_counted_not_invented(self):
        stats = ExtractionStats()
        source = 'server.tool("no_schema", "desc only, no schema object");'
        tools = extract_tools_typescript(source, stats=stats)
        assert tools == []
        assert stats.pattern_misses == 1

    def test_string_escapes_in_descriptions_survive(self):
        source = 'server.tool("echo", "Say \\"hello\\" loudly", { text: z.string() }, handler);'
        tools = extract_tools_typescript(source)
        assert tools[0].description == 'Say \\"hello\\" loudly'.replace("\\", "") or "hello" in tools[0].description


# ---------------------------------------------------------------------------
# Python extraction
# ---------------------------------------------------------------------------


class TestPythonExtraction:
    def test_fastmcp_docstring_and_defaults(self):
        source = '''
from fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def lookup_order(order_id: str, verbose: bool = False) -> dict:
    """Retrieve an order record."""
    return {}
'''
        tools = extract_tools_python(source)
        assert [tool.name for tool in tools] == ["lookup_order"]
        assert tools[0].description == "Retrieve an order record."
        assert tools[0].input_schema["required"] == ["order_id"]

    def test_description_kwarg(self):
        source = '''
@mcp.tool(description="Update a stored price")
def set_price(symbol: str, price: float) -> None:
    pass
'''
        tools = extract_tools_python(source)
        assert tools[0].description == "Update a stored price"

    def test_optional_union_annotation(self):
        source = '''
@app.tool
async def fetch_url(url: str | None = None) -> str:
    """Fetch a URL."""
'''
        tools = extract_tools_python(source)
        assert tools[0].input_schema.get("required", []) == []

    def test_broken_python_is_skipped(self):
        assert extract_tools_python("def broken(:\n") == []


# ---------------------------------------------------------------------------
# Directory extraction
# ---------------------------------------------------------------------------


class TestDirectoryExtraction:
    def test_mixed_tree_and_node_modules_skipped(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "server.ts").write_text(
            'server.tool("a", "A", { x: z.string() }, handler);', encoding="utf-8"
        )
        (tmp_path / "src" / "py_server.py").write_text(
            '@mcp.tool()\ndef tool_b(q: str) -> str:\n    """B."""\n    return q', encoding="utf-8"
        )
        vendored = tmp_path / "node_modules" / "lib"
        vendored.mkdir(parents=True)
        (vendored / "vendor.ts").write_text(
            'server.tool("c", "C", { y: z.string() }, handler);', encoding="utf-8"
        )

        tools, stats = extract_from_directory(tmp_path)
        names = {tool.name for tool in tools}
        assert names == {"a", "tool_b"}
        assert stats.files_scanned == 2

    def test_subdir_scoping(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "server.ts").write_text(
            'server.tool("a", "A", { x: z.string() }, handler);', encoding="utf-8"
        )
        (tmp_path / "other").mkdir()
        (tmp_path / "other" / "server.ts").write_text(
            'server.tool("d", "D", { z: z.string() }, handler);', encoding="utf-8"
        )
        tools, _ = extract_from_directory(tmp_path, subdir="src")
        assert {tool.name for tool in tools} == {"a"}


# ---------------------------------------------------------------------------
# Ecosystem aggregation
# ---------------------------------------------------------------------------


def _record(name: str, status: str = "scanned", score: int = 50, band: str = "HIGH",
            critical: int = 1, high: int = 2, medium: int = 3, low: int = 0, tools: int = 8) -> dict:
    record = {
        "target": {"name": name, "method": "live-stdio", "source": f"pkg-{name}"},
        "status": status,
    }
    if status == "scanned":
        record["report"] = {
            "target": name,
            "risk_score": score,
            "risk_band": band,
            "tool_count": tools,
            "counts_by_severity": {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low},
            "findings": (
                [{"rule_id": "MCP_SCHEMA_POISONING", "severity": "CRITICAL", "title": "t", "tool": "x"}] * critical
                + [{"rule_id": "MCP_UNBOUNDED_PARAMETER", "severity": "MEDIUM", "title": "t", "tool": "x"}] * medium
            ),
        }
    else:
        record["error"] = "cannot launch"
    return record


class TestAggregate:
    def test_counts_and_percentages(self):
        module = _load_script()
        records = [
            _record("a", band="CRITICAL", critical=1),
            _record("b", critical=0, high=1),
            _record("c", status="launch_failed"),
        ]
        summary = module.aggregate(records)
        assert summary["servers_scanned"] == 2
        assert summary["launch_failed"] == ["c"]
        assert summary["total_tools"] == 16
        assert summary["pct_servers_band_critical"] == 50.0
        assert summary["servers_band_critical"] == ["a"]
        assert summary["pct_servers_with_findings"] == 100.0
        assert summary["findings_by_rule"]["MCP_SCHEMA_POISONING"] == 1

    def test_empty_batch_is_safe(self):
        module = _load_script()
        summary = module.aggregate([])
        assert summary["servers_scanned"] == 0
        assert summary["pct_servers_band_critical"] == 0.0

    def test_render_includes_headline_and_limitations(self):
        module = _load_script()
        records = [_record("a", band="CRITICAL"), _record("b", critical=0, high=0, medium=1)]
        summary = module.aggregate(records)
        markdown = module.render_markdown(summary, records, "2026-10-03 00:00 UTC")
        assert "MCP Ecosystem Security Scan" in markdown
        assert "50.0%" in markdown or "50%" in markdown
        assert "Methodology & Limitations" in markdown
        assert "not legal" not in markdown  # scanner report, not compliance doc

    def test_render_lists_failed_servers(self):
        module = _load_script()
        records = [_record("dead", status="launch_failed")]
        markdown = module.render_markdown(module.aggregate(records), records, "now")
        assert "not launchable" in markdown
