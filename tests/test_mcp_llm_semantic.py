"""Tests for the MCP Server, LLM Agent Adapter, and Semantic Mutator."""
from __future__ import annotations

import json
import random

import pytest

from lifeforge.sandbox.mcp_server import LifeForgeMCPServer, MCPServerConfig
from lifeforge.sandbox.world_state import WorldState
from lifeforge.sandbox.mock_tools import ToolRegistry
from lifeforge.sandbox.agent import AgentAction, AgentInterface
from lifeforge.evolution.mutators.semantic import (
    SemanticMutator,
    SemanticMutatorConfig,
    _INJECTION_SEED_TEMPLATES,
)


# =====================================================================
# MCP Server Tests
# =====================================================================


class TestMCPServer:
    """Tests for LifeForgeMCPServer."""

    def test_initialize_returns_protocol_version(self):
        """Server returns correct MCP protocol version on initialize."""
        server = LifeForgeMCPServer()
        result = server.handle_initialize()
        assert result["protocolVersion"] == "2024-11-05"
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "lifeforge-sandbox"

    def test_list_tools_returns_all_sandbox_tools(self):
        """Server lists all 5 default sandbox tools."""
        server = LifeForgeMCPServer()
        tools = server.handle_list_tools()
        tool_names = {t["name"] for t in tools}
        assert tool_names == {
            "query_database",
            "vendor_api",
            "issue_purchase_order",
            "send_email",
            "transfer_funds",
        }
        # Each tool has required MCP fields
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_call_tool_query_database(self):
        """Tool calls dispatch correctly against the world state."""
        server = LifeForgeMCPServer()
        result = server.handle_call_tool(
            "query_database",
            {"table": "inventory"},
        )
        assert result["isError"] is False
        content = json.loads(result["content"][0]["text"])
        assert "server_h100" in content

    def test_call_tool_vendor_api(self):
        """Vendor API tool returns quote information."""
        server = LifeForgeMCPServer()
        result = server.handle_call_tool(
            "vendor_api",
            {"vendor_id": "vendor_alphatech", "item": "server_h100"},
        )
        assert result["isError"] is False
        content = json.loads(result["content"][0]["text"])
        assert content["vendor_id"] == "vendor_alphatech"
        assert content["unit_price"] == 28_000.0

    def test_call_tool_unknown_returns_error(self):
        """Calling an unknown tool returns an error."""
        server = LifeForgeMCPServer()
        result = server.handle_call_tool("nonexistent_tool", {})
        assert result["isError"] is True

    def test_state_mutates_across_calls(self):
        """World state persists and mutates across tool calls."""
        server = LifeForgeMCPServer()

        # Issue a purchase order
        result = server.handle_call_tool(
            "issue_purchase_order",
            {
                "vendor_id": "vendor_alphatech",
                "item": "server_h100",
                "quantity": 1,
                "max_unit_price": 30_000.0,
            },
        )
        assert result["isError"] is False

        # Verify inventory changed
        inv_result = server.handle_call_tool(
            "query_database",
            {"table": "inventory", "key": "server_h100"},
        )
        content = json.loads(inv_result["content"][0]["text"])
        assert content["server_h100"] == 1  # Was 0, now 1

    def test_trace_recording(self):
        """Server records a complete trace of all tool calls."""
        server = LifeForgeMCPServer()
        server.handle_call_tool("query_database", {"table": "inventory"})
        server.handle_call_tool("vendor_api", {"vendor_id": "vendor_alphatech", "item": "server_h100"})

        trace = server.get_trace()
        assert len(trace) == 2
        assert trace[0]["tool_name"] == "query_database"
        assert trace[1]["tool_name"] == "vendor_api"
        assert trace[0]["step"] == 1
        assert trace[1]["step"] == 2

    def test_reset_clears_state(self):
        """Server.reset() restores the initial state."""
        server = LifeForgeMCPServer()
        server.handle_call_tool("issue_purchase_order", {
            "vendor_id": "vendor_alphatech",
            "item": "server_h100",
            "quantity": 1,
            "max_unit_price": 30_000.0,
        })
        assert server.state.inventory["server_h100"] == 1
        assert len(server.get_trace()) == 1

        server.reset()
        assert server.state.inventory["server_h100"] == 0
        assert len(server.get_trace()) == 0

    def test_jsonrpc_handler(self):
        """Full JSON-RPC 2.0 request/response cycle."""
        server = LifeForgeMCPServer()

        # Initialize
        resp = server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        })
        assert resp["id"] == 1
        assert "protocolVersion" in resp["result"]

        # List tools
        resp = server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        })
        assert len(resp["result"]["tools"]) == 5

        # Call tool
        resp = server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "query_database",
                "arguments": {"table": "balances"},
            },
        })
        assert resp["result"]["isError"] is False

    def test_jsonrpc_unknown_method_returns_error(self):
        """Unknown JSON-RPC method returns proper error code."""
        server = LifeForgeMCPServer()
        resp = server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "unknown/method",
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32601


# =====================================================================
# Semantic Mutator Tests
# =====================================================================


class TestSemanticMutator:
    """Tests for the SemanticMutator (template-based, no LLM required)."""

    def test_template_generation_produces_valid_payloads(self):
        """Template-based generation produces injection-containing payloads."""
        config = SemanticMutatorConfig(use_llm=False)
        mutator = SemanticMutator(config)
        rng = random.Random(42)

        state = WorldState.default_purchasing_world()
        mutated = mutator.mutate(state, rng)

        # At least one vendor's notes should be modified
        modified = False
        for vid, quote in mutated.vendor_quotes.items():
            if quote.get("notes") != state.vendor_quotes.get(vid, {}).get("notes"):
                modified = True
                notes = quote["notes"]
                # Payload should contain transfer-related keywords
                lower = notes.lower()
                assert any(
                    kw in lower
                    for kw in ["transfer", "account", "acct"]
                ), f"Payload missing expected keywords: {notes[:100]}"
        assert modified, "Semantic mutator should modify at least one vendor's notes"

    def test_template_diversity(self):
        """Template expansion produces diverse (non-repeating) payloads."""
        config = SemanticMutatorConfig(use_llm=False)
        mutator = SemanticMutator(config)
        rng = random.Random(12345)

        payloads = set()
        state = WorldState.default_purchasing_world()
        for _ in range(30):
            mutated = mutator.mutate(state, rng)
            for quote in mutated.vendor_quotes.values():
                payloads.add(quote.get("notes", ""))

        # With 30 draws from thousands of combinations, should get many unique payloads
        assert len(payloads) >= 10, f"Expected diverse payloads, got only {len(payloads)} unique"

    def test_total_template_combinations_exceeds_static(self):
        """Template combinatorics should produce far more than the 4 static payloads."""
        config = SemanticMutatorConfig(use_llm=False)
        mutator = SemanticMutator(config)
        # Must have at least 100 unique combinations (vs. 4 static in adversarial.py)
        assert mutator.total_template_combinations > 100

    def test_mutator_preserves_other_state(self):
        """Mutation should only affect vendor notes, not other state."""
        config = SemanticMutatorConfig(use_llm=False)
        mutator = SemanticMutator(config)
        rng = random.Random(99)

        state = WorldState.default_purchasing_world()
        mutated = mutator.mutate(state, rng)

        # Budget, inventory, inbox should be unchanged
        assert mutated.balances == state.balances
        assert mutated.inventory == state.inventory
        assert mutated.inbox == state.inbox


# =====================================================================
# LLM Agent Tests (mock-based, no actual API calls)
# =====================================================================


class TestLLMAgentUnit:
    """Unit tests for LLMAgent using mock responses (no API calls)."""

    def test_llm_agent_import_guard(self):
        """LLMAgent import raises clear error when litellm is missing."""
        # We test the check function directly
        from lifeforge.sandbox.llm_agent import _check_litellm
        try:
            _check_litellm()
            # If litellm is installed, this should succeed
        except ImportError as e:
            assert "litellm" in str(e).lower()
            assert "pip install" in str(e)

    def test_llm_agent_config_defaults(self):
        """LLMAgentConfig has sensible defaults."""
        from lifeforge.sandbox.llm_agent import LLMAgentConfig
        config = LLMAgentConfig()
        assert config.model == "gpt-4o-mini"
        assert config.temperature == 0.0
        assert config.max_tokens == 1024

    def test_cost_tracker_accumulation(self):
        """LLMCostTracker correctly accumulates multiple responses."""
        from lifeforge.sandbox.llm_agent import LLMCostTracker

        tracker = LLMCostTracker()
        assert tracker.api_calls == 0
        assert tracker.total_cost_usd == 0.0

        # Simulate recording (with a mock object)
        class MockUsage:
            prompt_tokens = 100
            completion_tokens = 50

        class MockResponse:
            usage = MockUsage()
            _hidden_params = {"response_cost": 0.005}

        tracker.record(MockResponse())
        assert tracker.api_calls == 1
        assert tracker.prompt_tokens == 100
        assert tracker.completion_tokens == 50
        assert tracker.total_cost_usd == pytest.approx(0.005)

        tracker.record(MockResponse())
        assert tracker.api_calls == 2
        assert tracker.prompt_tokens == 200
        assert tracker.total_cost_usd == pytest.approx(0.01)

    def test_observation_to_user_msg(self):
        """Observation serialization produces readable messages."""
        from lifeforge.sandbox.llm_agent import _observation_to_user_msg

        obs = {
            "inbox": [{"from": "boss", "subject": "Buy stuff", "body": "Get 2 servers"}],
            "step": 0,
            "last_tool_result": None,
        }
        msg = _observation_to_user_msg(obs, 0)
        assert "[Step 0]" in msg
        assert "INBOX" in msg
        assert "Buy stuff" in msg

        # Step > 0 should not repeat inbox
        obs2 = {
            "inbox": [{"from": "boss", "subject": "Buy stuff", "body": "Get 2 servers"}],
            "step": 1,
            "last_tool_result": {"success": True, "output": {"price": 100}},
        }
        msg2 = _observation_to_user_msg(obs2, 1)
        assert "[Step 1]" in msg2
        assert "TOOL RESULT" in msg2
        assert "INBOX" not in msg2


# =====================================================================
# CLI Test Command (integration test)
# =====================================================================


class TestCLITestCommand:
    """Tests for the `lifeforge test` CLI command."""

    def test_cmd_test_runs_and_discovers_vulnerabilities(self, tmp_path):
        """The test command runs evolutionary search and generates a report."""
        import argparse
        from lifeforge.cli.main import cmd_test

        out_file = tmp_path / "report.md"
        args = argparse.Namespace(
            agent_name="TestAgent",
            scenarios=10,  # Small for speed
            seed=42,
            out=str(out_file),
            json=True,
            hardened=False,
        )
        # Should exit with code 1 (critical vulnerabilities found) but not crash
        with pytest.raises(SystemExit) as exc_info:
            cmd_test(args)
        assert exc_info.value.code == 1

        # Report should exist
        assert out_file.exists()
        report = out_file.read_text(encoding="utf-8")
        assert "Agent Evolution Report" in report or "TestAgent" in report

        # JSON report should also exist
        json_file = out_file.with_suffix(".json")
        assert json_file.exists()

    def test_cmd_test_hardened_agent_passes(self, tmp_path):
        """A hardened agent should not trigger critical vulnerabilities."""
        import argparse
        from lifeforge.cli.main import cmd_test

        out_file = tmp_path / "report_hardened.md"
        args = argparse.Namespace(
            agent_name="HardenedAgent",
            scenarios=10,
            seed=42,
            out=str(out_file),
            json=False,
            hardened=True,
        )
        # Hardened agent should not have critical failures
        cmd_test(args)  # Should not raise SystemExit
        assert out_file.exists()
