"""Tests for the universal agent loader, HTTP webhook adapter, and lifeforge eval command."""
from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from lifeforge.cli.main import cmd_eval
from lifeforge.sandbox.agent import AgentAction, AgentInterface
from lifeforge.sandbox.http_agent import HTTPAgentAdapter
from lifeforge.sandbox.loader import AgentLoadError, load_agent_from_spec


class DummyCustomAgent(AgentInterface):
    """Test agent instance/class for loader verification."""

    def __init__(self, name: str = "DummyAgent") -> None:
        self.name = name

    def act(self, observation: dict[str, Any], history: list[dict[str, Any]]) -> AgentAction:
        return AgentAction(action_type="finish", thought="Dummy completed.")


def dummy_agent_function(observation: dict[str, Any], history: list[dict[str, Any]]) -> AgentAction:
    """Test callable function for loader verification."""
    return AgentAction(
        action_type="tool_call",
        tool_name="query_database",
        arguments={"query": "SELECT 1"},
    )


def test_load_agent_from_class() -> None:
    spec = f"{__file__}:DummyCustomAgent"
    agent = load_agent_from_spec(spec, name="RenamedDummy")
    assert isinstance(agent, AgentInterface)
    assert agent.name == "RenamedDummy"
    action = agent.act({}, [])
    assert action.action_type == "finish"


def test_load_agent_from_callable() -> None:
    spec = f"{__file__}:dummy_agent_function"
    agent = load_agent_from_spec(spec)
    assert isinstance(agent, AgentInterface)
    action = agent.act({}, [])
    assert action.action_type == "tool_call"
    assert action.tool_name == "query_database"


def test_load_agent_missing_colon_raises_error() -> None:
    with pytest.raises(AgentLoadError, match="Format must be"):
        load_agent_from_spec("some_path_without_colon.py")


def test_load_agent_nonexistent_file_raises_error() -> None:
    with pytest.raises(AgentLoadError, match="Target agent file not found"):
        load_agent_from_spec("non_existent_file_xyz_123.py:agent")


def test_load_agent_missing_attribute_raises_error() -> None:
    with pytest.raises(AgentLoadError, match="does not define attribute"):
        load_agent_from_spec(f"{__file__}:non_existent_attribute_456")


class MockWebhookHandler(http.server.BaseHTTPRequestHandler):
    """Mock HTTP handler for testing HTTPAgentAdapter."""

    received_resets = 0

    def do_POST(self) -> None:
        if self.path == "/reset":
            MockWebhookHandler.received_resets += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        if self.path == "/act":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            payload = json.loads(post_data.decode("utf-8"))

            step = payload.get("step", 1)
            if step == 1:
                resp = {
                    "action_type": "tool_call",
                    "tool_name": "query_database",
                    "arguments": {"query": "SELECT * FROM inventory"},
                    "thought": "Checking stock",
                }
            else:
                resp = {
                    "action_type": "finish",
                    "thought": "Finished successfully",
                }

            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def mock_agent_server() -> tuple[str, str]:
    """Start a temporary local mock HTTP agent server."""
    server = socketserver.TCPServer(("127.0.0.1", 0), MockWebhookHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    act_url = f"http://127.0.0.1:{port}/act"
    reset_url = f"http://127.0.0.1:{port}/reset"

    yield act_url, reset_url

    server.shutdown()
    server.server_close()


def test_http_agent_adapter_act_and_reset(mock_agent_server: tuple[str, str]) -> None:
    act_url, reset_url = mock_agent_server
    adapter = HTTPAgentAdapter(endpoint=act_url, reset_endpoint=reset_url, name="TestHTTP")

    adapter.reset()
    assert MockWebhookHandler.received_resets >= 1

    action1 = adapter.act({"inbox": []}, [])
    assert action1.action_type == "tool_call"
    assert action1.tool_name == "query_database"
    assert action1.arguments == {"query": "SELECT * FROM inventory"}

    action2 = adapter.act({"result": "success"}, [{"step": 1}])
    assert action2.action_type == "finish"


def test_http_agent_adapter_connection_error() -> None:
    adapter = HTTPAgentAdapter(endpoint="http://127.0.0.1:59999/act", timeout=1.0)
    action = adapter.act({}, [])
    assert action.action_type == "finish"
    assert "error" in (action.thought or "").lower() or "failure" in (action.message or "").lower()


def test_cmd_eval_target_spec(tmp_path: Path) -> None:
    out_md = tmp_path / "eval_report.md"
    args = argparse.Namespace(
        target=f"{__file__}:DummyCustomAgent",
        endpoint=None,
        reset_endpoint=None,
        timeout=10.0,
        agent_name="CLI_Test_Dummy",
        scenarios=5,
        delay=0.0,
        seed=42,
        out=str(out_md),
        json=True,
        fail_on_critical=False,
    )

    cmd_eval(args)
    assert out_md.exists()
    assert out_md.with_suffix(".json").exists()
    content = out_md.read_text(encoding="utf-8")
    assert "CLI_Test_Dummy" in content


def test_cmd_eval_webhook_endpoint(mock_agent_server: tuple[str, str], tmp_path: Path) -> None:
    act_url, reset_url = mock_agent_server
    out_md = tmp_path / "webhook_report.md"

    args = argparse.Namespace(
        target=None,
        endpoint=act_url,
        reset_endpoint=reset_url,
        timeout=10.0,
        agent_name="Remote_Webhook_Agent",
        scenarios=5,
        delay=0.0,
        seed=42,
        out=str(out_md),
        json=True,
        fail_on_critical=False,
    )

    cmd_eval(args)
    assert out_md.exists()
    assert out_md.with_suffix(".json").exists()
    content = out_md.read_text(encoding="utf-8")
    assert "Remote_Webhook_Agent" in content
