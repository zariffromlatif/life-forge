"""Tests for the AutoGen and smolagents adapters (duck-typed fakes, offline)."""
from __future__ import annotations

import json

import pytest

from lifeforge.adapters import AutoGenAdapter, SmolAgentsAdapter
from lifeforge.adapters._parsing import ACTION_PROTOCOL, extract_json_payload, parse_action_payload


def _observation() -> dict:
    return {
        "inbox": [{"from": "boss", "subject": "Procure", "body": "Buy 2 units."}],
        "last_tool_result": None,
    }


# ---------------------------------------------------------------------------
# Shared parsing
# ---------------------------------------------------------------------------


class TestSharedParsing:
    def test_fenced_json_is_extracted(self):
        text = "Here is my decision:\n```json\n{\"action_type\": \"finish\", \"message\": \"done\"}\n```"
        payload = extract_json_payload(text)
        assert payload == {"action_type": "finish", "message": "done"}

    def test_bare_object_is_extracted(self):
        payload = extract_json_payload('decision: {"action_type": "finish", "message": "ok"} thanks')
        assert payload["message"] == "ok"

    def test_nested_braces_inside_strings_do_not_break_extraction(self):
        text = '{"action_type": "tool_call", "tool_name": "t", "arguments": {"q": "a { weird } string"}}'
        assert extract_json_payload(text)["arguments"]["q"] == "a { weird } string"

    def test_no_json_returns_none(self):
        assert extract_json_payload("just prose, nothing else") is None

    def test_malformed_payload_degrades_to_finish(self):
        action = parse_action_payload({"action_type": "tool_call"}, fallback_text="oops")
        assert action.action_type == "finish"
        assert "tool_name" in action.message

    def test_string_arguments_degrade_to_finish(self):
        action = parse_action_payload({"action_type": "tool_call", "tool_name": "t", "arguments": "not-an-object"})
        assert action.action_type == "finish"

    def test_protocol_mentions_both_actions(self):
        assert "tool_call" in ACTION_PROTOCOL and "finish" in ACTION_PROTOCOL


# ---------------------------------------------------------------------------
# AutoGen adapter
# ---------------------------------------------------------------------------


class FakeAutoGenAgent:
    """Duck-typed ConversableAgent: generate_reply over a message list."""

    def __init__(self, replies: list) -> None:
        self.replies = list(replies)
        self.calls: list[list] = []

    def generate_reply(self, messages=None, sender=None):
        self.calls.append(list(messages or []))
        if not self.replies:
            raise AssertionError("unexpected extra reply")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class TestAutoGenAdapter:
    def test_native_tool_call_reply_is_mapped(self):
        reply = {
            "content": None,
            "tool_calls": [
                {"id": "call_1", "function": {"name": "vendor_api", "arguments": json.dumps({"vendor_id": "v1", "item": "server_h100"})}}
            ],
        }
        adapter = AutoGenAdapter(agent=FakeAutoGenAgent([reply]))
        action = adapter.act(_observation(), [])
        assert action.action_type == "tool_call"
        assert action.tool_name == "vendor_api"
        assert action.arguments == {"vendor_id": "v1", "item": "server_h100"}

    def test_flat_tool_call_reply_is_mapped(self):
        reply = {"tool_calls": [{"name": "send_email", "arguments": {"recipient": "x"}}]}
        adapter = AutoGenAdapter(agent=FakeAutoGenAgent([reply]))
        action = adapter.act(_observation(), [])
        assert action.action_type == "tool_call"
        assert action.tool_name == "send_email"

    def test_json_text_reply_is_parsed(self):
        reply = '{"action_type": "tool_call", "tool_name": "query_database", "arguments": {"table": "prices"}, "thought": "check prices"}'
        adapter = AutoGenAdapter(agent=FakeAutoGenAgent([reply]))
        action = adapter.act(_observation(), [])
        assert action.action_type == "tool_call"
        assert action.arguments == {"table": "prices"}

    def test_prose_reply_degrades_to_finish(self):
        adapter = AutoGenAdapter(agent=FakeAutoGenAgent(["I cannot help with that."]))
        action = adapter.act(_observation(), [])
        assert action.action_type == "finish"
        assert "cannot help" in action.message

    def test_raising_agent_becomes_finish(self):
        adapter = AutoGenAdapter(agent=FakeAutoGenAgent([RuntimeError("model exploded")]))
        action = adapter.act(_observation(), [])
        assert action.action_type == "finish"
        assert "model exploded" in action.message

    def test_conversation_history_accumulates_and_reset_clears_it(self):
        fake = FakeAutoGenAgent([
            {"action_type": "tool_call", "tool_name": "t1", "arguments": {}},
            {"action_type": "finish", "message": "done"},
        ])
        adapter = AutoGenAdapter(agent=fake)
        adapter.act(_observation(), [])
        adapter.act(_observation(), [])
        assert len(fake.calls[0]) == 1
        assert len(fake.calls[1]) == 3  # user, assistant, user
        adapter.reset()
        assert adapter._messages == []

    def test_none_agent_is_rejected(self):
        with pytest.raises(ValueError):
            AutoGenAdapter(agent=None)

    def test_object_without_generate_reply_is_rejected(self):
        with pytest.raises(ValueError):
            AutoGenAdapter(agent=object())

    def test_observation_reaches_the_agent(self):
        fake = FakeAutoGenAgent([{"action_type": "finish", "message": "ok"}])
        adapter = AutoGenAdapter(agent=fake)
        adapter.act(_observation(), [])
        sent = fake.calls[0][0]["content"]
        assert "Procure" in sent and "ACTION PROTOCOL" in sent


# ---------------------------------------------------------------------------
# smolagents adapter
# ---------------------------------------------------------------------------


class FakeSmolAgent:
    """Duck-typed smolagents CodeAgent: run() executes the whole loop."""

    def __init__(self, results: list) -> None:
        self.results = list(results)
        self.tasks: list[str] = []

    def run(self, task):
        self.tasks.append(task)
        if not self.results:
            raise AssertionError("unexpected extra run")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class TestSmolAgentsAdapter:
    def test_fenced_json_result_is_parsed(self):
        agent = FakeSmolAgent(['```json\n{"action_type": "tool_call", "tool_name": "issue_purchase_order", "arguments": {"vendor_id": "v", "item": "i", "quantity": 2, "max_unit_price": 10.0}}\n```'])
        action = SmolAgentsAdapter(agent=agent).act(_observation(), [])
        assert action.action_type == "tool_call"
        assert action.tool_name == "issue_purchase_order"

    def test_plain_object_result_with_output_attribute(self):
        class Result:
            output = '{"action_type": "finish", "message": "all done"}'

        agent = FakeSmolAgent([Result()])
        action = SmolAgentsAdapter(agent=agent).act(_observation(), [])
        assert action.action_type == "finish"
        assert action.message == "all done"

    def test_prose_result_degrades_to_finish(self):
        agent = FakeSmolAgent(["The final answer is 42."])
        action = SmolAgentsAdapter(agent=agent).act(_observation(), [])
        assert action.action_type == "finish"
        assert "42" in action.message

    def test_raising_agent_becomes_finish(self):
        agent = FakeSmolAgent([RuntimeError("hf is down")])
        action = SmolAgentsAdapter(agent=agent).act(_observation(), [])
        assert action.action_type == "finish"
        assert "hf is down" in action.message

    def test_task_includes_history_and_protocol(self):
        agent = FakeSmolAgent([{"action_type": "finish", "message": "ok"}])
        adapter = SmolAgentsAdapter(agent=agent)
        adapter.act(_observation(), [{"step": 0, "action": {"action_type": "tool_call", "tool_name": "t", "arguments": {}}}])
        assert "ACTIONS SO FAR" in agent.tasks[0]
        assert "ACTION PROTOCOL" in agent.tasks[0]

    def test_long_unparseable_output_is_truncated(self):
        agent = FakeSmolAgent(["x" * 10000])
        action = SmolAgentsAdapter(agent=agent, max_output_chars=100).act(_observation(), [])
        assert len(action.message) <= 120
        assert action.message.endswith("[truncated]")

    def test_reset_is_idempotent(self):
        adapter = SmolAgentsAdapter(agent=FakeSmolAgent([]))
        adapter.reset()
        adapter.reset()
        assert adapter.name == "SmolAgentsAdapter"

    def test_none_agent_is_rejected(self):
        with pytest.raises(ValueError):
            SmolAgentsAdapter(agent=None)
