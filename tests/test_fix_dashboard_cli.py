"""Regression tests for the dashboard, quickstart, CLI and adapter audit fixes."""
from __future__ import annotations

import http.client
import importlib
import socket
import sys
import threading
import types
from pathlib import Path

import pytest

from lifeforge.dashboard.server import STATIC_DIR, create_server


# ---------------------------------------------------------------------------
# Dashboard (#1, #2, Host check, CORS, bad ints, threading)
# ---------------------------------------------------------------------------


@pytest.fixture()
def dashboard(tmp_path: Path):
    results = tmp_path / "results"
    results.mkdir()
    (results / "MODEL_SHOWDOWN.md").write_text("# showdown", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("TOPSECRET", encoding="utf-8")
    server = create_server(port=0, host="127.0.0.1", results_dir=results)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server, tmp_path
    finally:
        server.shutdown()
        server.server_close()


def _get(server, path: str, host: str | None = None):
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host if host is not None else f"127.0.0.1:{port}")
    conn.endheaders()
    response = conn.getresponse()
    body = response.read()
    headers = {key.lower(): value for key, value in response.getheaders()}
    conn.close()
    return response.status, body, headers


def test_export_serves_results_file(dashboard):
    server, _ = dashboard
    status, body, _ = _get(server, "/api/export?file=MODEL_SHOWDOWN.md")
    assert status == 200 and b"showdown" in body


@pytest.mark.parametrize(
    "query",
    ["../secret.txt", "..%2fsecret.txt", "..\\secret.txt", "{secret}", "C:/Windows/win.ini", "/etc/passwd", "%00"],
)
def test_export_rejects_traversal_and_absolute_paths(dashboard, query):
    server, root = dashboard
    query = query.replace("{secret}", str(root / "secret.txt").replace("\\", "/"))
    status, body, _ = _get(server, "/api/export?file=" + query)
    assert status == 404
    assert b"TOPSECRET" not in body


@pytest.mark.parametrize(
    "path",
    ["/C:/Windows/win.ini", "/..%2f..%2fserver.py", "/../server.py", "/..\\server.py", "/%2e%2e/server.py"],
)
def test_static_rejects_escape(dashboard, path):
    server, _ = dashboard
    status, body, _ = _get(server, path)
    assert status == 404
    assert b"def create_server" not in body and b"[fonts]" not in body


def test_static_index_still_served(dashboard):
    server, _ = dashboard
    if not (STATIC_DIR / "index.html").exists():
        pytest.skip("no bundled index.html")
    status, _, _ = _get(server, "/index.html")
    assert status == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:80", "127.0.0.1.nip.io", ""])
def test_foreign_host_header_rejected(dashboard, host):
    server, _ = dashboard
    status, _, _ = _get(server, "/api/reports", host=host)
    assert status == 403


def test_localhost_host_header_allowed(dashboard):
    server, _ = dashboard
    port = server.server_address[1]
    assert _get(server, "/api/reports", host=f"localhost:{port}")[0] == 200
    assert _get(server, "/api/reports", host=f"localhost:{port + 1}")[0] == 403


def test_no_wildcard_cors(dashboard):
    server, _ = dashboard
    _, _, headers = _get(server, "/api/reports")
    assert "access-control-allow-origin" not in headers


@pytest.mark.parametrize("query", ["rule=abc", "steps=xyz", "rule=999"])
def test_modes_bad_parameters_return_400(dashboard, query):
    server, _ = dashboard
    status, _, _ = _get(server, "/api/modes/simulate?" + query)
    assert status == 400


def test_server_is_threaded(dashboard):
    server, _ = dashboard
    idle = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5)
    try:
        idle.sendall(b"GET /api/reports HTTP/1.1\r\n")  # never finishes its request
        status, _, _ = _get(server, "/api/mcp_scans")
        assert status == 200
    finally:
        idle.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run_cli(monkeypatch, argv: list[str]) -> int:
    cli = importlib.import_module("lifeforge.cli.main")
    monkeypatch.setattr(sys, "argv", ["lifeforge", *argv])
    try:
        cli.main()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def test_mcp_serve_rejects_unimplemented_sse(monkeypatch):
    assert _run_cli(monkeypatch, ["mcp-serve", "--transport", "sse"]) == 2


# ---------------------------------------------------------------------------
# Quickstart (#14)
# ---------------------------------------------------------------------------


def _langchain_project(root: Path) -> Path:
    (root / "langchain").mkdir()
    (root / "langchain" / "__init__.py").write_text("", encoding="utf-8")
    marker = root / "EXECUTED"
    (root / "agent.py").write_text(
        "from langchain import __name__ as _lc\n"
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('yes')\n"
        "class _Exec:\n"
        "    def invoke(self, d):\n"
        "        return {'output': '{\"action_type\": \"finish\", \"message\": \"done\"}'}\n"
        "agent = _Exec()\n",
        encoding="utf-8",
    )
    return marker


def test_quickstart_without_yes_executes_nothing(tmp_path, capsys):
    from lifeforge.cli.quickstart import run_quickstart

    marker = _langchain_project(tmp_path)
    assert run_quickstart(tmp_path) == 0
    output = capsys.readouterr().out
    assert "IMPORT AND EXECUTE" in output and "--yes" in output
    assert not marker.exists()
    assert not (tmp_path / "lifeforge_harness.py").exists()


def test_quickstart_with_yes_runs_harness_with_flags(tmp_path, capsys):
    from lifeforge.cli.quickstart import run_quickstart

    marker = _langchain_project(tmp_path)
    out = tmp_path / "custom" / "report.md"
    assert run_quickstart(tmp_path, yes=True, scenarios=1, seed=7, out=str(out)) == 0
    assert marker.exists()
    assert (tmp_path / "lifeforge_harness.py").exists()
    assert out.exists()  # --out reached the harness
    assert "IMPORT AND EXECUTE" in capsys.readouterr().out


def test_quickstart_harness_failure_propagates(tmp_path, capsys):
    from lifeforge.cli.quickstart import run_quickstart

    (tmp_path / "bot.py").write_text("import autogen\nagent = None\n", encoding="utf-8")
    code = run_quickstart(tmp_path, yes=True, scenarios=1)
    assert code != 0
    assert "[FAIL]" in capsys.readouterr().out


def test_quickstart_cli_accepts_yes_flag(monkeypatch, tmp_path):
    _langchain_project(tmp_path)
    assert _run_cli(monkeypatch, ["quickstart", "--path", str(tmp_path)]) == 0
    assert not (tmp_path / "EXECUTED").exists()


# ---------------------------------------------------------------------------
# Adapters (#13)
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_langchain(monkeypatch):
    monkeypatch.setitem(sys.modules, "langchain", types.ModuleType("langchain"))


class _Exec:
    def __init__(self, output):
        self.output = output
        self.last = None

    def invoke(self, payload):
        self.last = payload["input"]
        return self.output


def test_langchain_json_output_becomes_tool_call(fake_langchain):
    from lifeforge.adapters.langchain import LangChainAdapter

    executor = _Exec({"output": '{"action_type":"tool_call","tool_name":"execute_transfer","arguments":{"amount":5}}'})
    adapter = LangChainAdapter(executor, sandbox_tools=[{"name": "execute_transfer", "description": "Move money"}])
    action = adapter.act({"inbox": [{"from": "a", "body": "pay"}]}, [])
    assert action.action_type == "tool_call"
    assert action.tool_name == "execute_transfer" and action.arguments == {"amount": 5}
    assert "ACTION PROTOCOL" in executor.last
    assert "execute_transfer" in executor.last


def test_langchain_tools_from_observation_listed(fake_langchain):
    from lifeforge.adapters.langchain import LangChainAdapter

    executor = _Exec("plain prose answer")
    action = LangChainAdapter(executor).act({"available_tools": ["search_vendors"]}, [])
    assert "search_vendors" in executor.last
    assert action.action_type == "finish"


def test_langchain_native_tool_calls_still_supported(fake_langchain):
    from lifeforge.adapters.langchain import LangChainAdapter

    message = types.SimpleNamespace(tool_calls=[{"name": "lookup", "args": {"q": 1}}], content="")
    action = LangChainAdapter(_Exec(message)).act({}, [])
    assert action.action_type == "tool_call" and action.tool_name == "lookup"


def test_langgraph_text_reply_parsed_through_protocol():
    from lifeforge.adapters.langgraph import LangGraphAdapter, _format_observation_for_langgraph

    ai = types.SimpleNamespace(type="ai", content='```json\n{"action_type":"tool_call","tool_name":"refund","arguments":{}}\n```', tool_calls=[])
    action = LangGraphAdapter(app=None)._parse_result({"messages": [ai]})
    assert action.action_type == "tool_call" and action.tool_name == "refund"
    text = _format_observation_for_langgraph({"available_tools": ["refund"]})
    assert "ACTION PROTOCOL" in text and "refund" in text


def test_adapter_modules_warn_about_real_tool_execution():
    import lifeforge.adapters.langchain as lc
    import lifeforge.adapters.langgraph as lg

    assert "FOR REAL" in lg.__doc__
    assert "executed by" in lc.__doc__ and "sandbox cannot intercept" in lc.__doc__
