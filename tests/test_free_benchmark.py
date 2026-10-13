"""Tests for the free-tier benchmark runner and its rate-limit proxy."""
from __future__ import annotations

import http.server
import importlib.util
import json
import sys
import threading
from pathlib import Path

import httpx
import pytest

BENCH = Path(__file__).resolve().parents[1] / "environments" / "refund_desk_v1" / "bench"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, BENCH / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


proxy = _load("ratelimit_proxy")
bench = _load("free_benchmark")


# ---------------------------------------------------------------------------
# Wait parsing and quota detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers, body, expected",
    [
        ({"retry-after": "12"}, "", 12.0),
        ({"x-ratelimit-reset-tokens": "7.66s"}, "", 7.66),
        ({"x-ratelimit-reset-tokens": "1m2.5s"}, "", 62.5),
        ({}, "Rate limit reached ... Please try again in 7m12.48s.", 432.48),
        ({}, '{"error": {"details": [{"retryDelay": "41s"}]}}', 41.0),
        ({}, "nothing useful", None),
    ],
)
def test_wait_parsing(headers, body, expected):
    result = proxy.parse_wait_seconds(httpx.Headers(headers), body)
    assert result == pytest.approx(expected) if expected is not None else result is None


def test_daily_quota_wording_from_both_providers():
    assert proxy.is_daily_quota("Rate limit reached for model on tokens per day (TPD): Limit 200000")
    assert proxy.is_daily_quota('quotaId: "GenerateRequestsPerDayPerProjectPerModel-FreeTier"')
    assert not proxy.is_daily_quota("Rate limit reached on tokens per minute (TPM)")


# ---------------------------------------------------------------------------
# Throttle (fake clock)
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.slept = 0.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds
        self.slept += seconds


def test_throttle_respects_requests_per_minute():
    clock, throttle = FakeClock(), proxy.Throttle(rpm=3, tpm=10**9)
    waits = [throttle.wait_for(10, now=clock.now, sleep=clock.sleep) for _ in range(4)]
    assert waits[:3] == [0.0, 0.0, 0.0]
    assert waits[3] >= 59.0  # the 4th request waits for the window to roll


def test_throttle_respects_tokens_per_minute_and_never_deadlocks_on_large_requests():
    clock, throttle = FakeClock(), proxy.Throttle(rpm=100, tpm=1000)
    assert throttle.wait_for(600, now=clock.now, sleep=clock.sleep) == 0.0
    assert throttle.wait_for(600, now=clock.now, sleep=clock.sleep) >= 59.0
    assert throttle.wait_for(50_000, now=clock.now, sleep=clock.sleep) >= 0.0  # capped, still goes


# ---------------------------------------------------------------------------
# Proxy against a fake provider
# ---------------------------------------------------------------------------


class FakeProvider:
    """Answers 429 according to a script, then 200; records what it received."""

    def __init__(self, script):
        self.script = list(script)
        self.seen = []
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                provider.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                status, headers, text = provider.script.pop(0) if provider.script else (200, {}, '{"ok": true}')
                data = text.encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self):
        self.server.shutdown()


@pytest.fixture
def run_proxy(tmp_path, monkeypatch):
    started = []
    monkeypatch.setattr(proxy.time, "sleep", lambda s: None)  # don't actually wait in tests

    def start(script):
        provider = FakeProvider(script)
        server, state = proxy.serve(provider.url, 0, rpm=1000, tpm=10**9, quota_flag=tmp_path / "quota.flag", max_wait=120)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append((provider, server))
        return provider, state, f"http://127.0.0.1:{server.server_address[1]}/v1"

    yield start
    for provider, server in started:
        server.shutdown()
        provider.close()


def test_short_rate_limit_is_retried_and_auth_passes_through(run_proxy):
    provider, state, url = run_proxy([(429, {"retry-after": "2"}, '{"error": "slow down"}')])
    response = httpx.post(f"{url}/chat/completions", json={"model": "m"}, headers={"Authorization": "Bearer k"})
    assert response.status_code == 200
    assert len(provider.seen) == 2 and state.stats["retries"] == 1
    assert all(r["auth"] == "Bearer k" and r["path"] == "/v1/chat/completions" for r in provider.seen)


def test_daily_quota_stops_the_day_without_more_upstream_calls(run_proxy, tmp_path):
    provider, state, url = run_proxy([(429, {}, "Rate limit reached on tokens per day (TPD). Please try again in 7m12s.")])
    first = httpx.post(f"{url}/chat/completions", json={})
    second = httpx.post(f"{url}/chat/completions", json={})
    assert first.status_code == 429 and second.status_code == 429
    assert (tmp_path / "quota.flag").exists()
    assert len(provider.seen) == 1  # the second request never left the machine


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_eval(monkeypatch):
    monkeypatch.setattr(bench, "eval_binary", lambda: "/venv/bin/eval")


def test_eval_command_uses_samples_flag_and_never_pushes(fake_eval, tmp_path):
    spec = bench.default_models()[0]
    command = bench.eval_command(spec, "http://127.0.0.1:9/v1", tmp_path, 1, 0.7, resume=False, dry_run=False)
    assert command[:2] == ["/venv/bin/eval", "refund-desk-v1"]
    assert command[command.index("-r") + 1] == "1" and "-n" not in command
    assert "--no-push" in command and "--dry-run" not in command
    assert command[command.index("--env.agent.runtime.type") + 1] == "subprocess"  # never Prime's remote runtime
    assert command[command.index("--client.api-key-var") + 1] == "GROQ_API_KEY"


def test_eval_command_resumes_from_the_saved_config(fake_eval, tmp_path):
    spec = bench.default_models()[0]
    saved = tmp_path / spec.run_name / "configs" / "resolved"
    saved.mkdir(parents=True)
    (saved / "eval.json").write_text(json.dumps({"client": {"base_url": "http://127.0.0.1:34889/v1", "api_key_var": "K"}}))
    assert bench.eval_command(spec, "http://127.0.0.1:5555/v1", tmp_path, 1, 0.7, resume=True, dry_run=False) == [
        "/venv/bin/eval", "@", str(saved / "eval.json"), "--resume"
    ]
    # The proxy runs on a new port each day: the resumed config must point at today's.
    client = json.loads((saved / "eval.json").read_text())["client"]
    assert client == {"base_url": "http://127.0.0.1:5555/v1", "api_key_var": "K"}


def test_run_names_are_filesystem_safe():
    names = [m.run_name for m in bench.default_models()]
    assert all("/" not in n and ":" not in n for n in names)
    assert len(set(names)) == len(names)


def test_episodes_done_counts_only_clean_traces(tmp_path):
    spec = bench.default_models()[0]
    run = tmp_path / spec.run_name
    run.mkdir()
    lines = [
        {"traces": [{"ok": True, "errors": []}]},
        {"traces": [{"ok": False, "errors": [{"type": "RateLimit"}]}]},
        {"traces": [{"ok": True, "errors": []}, {"ok": True, "errors": []}]},
    ]
    (run / "traces.jsonl").write_text("\n".join(json.dumps(l) for l in lines))
    assert bench.episodes_done(tmp_path, spec) == 3


def test_preflight_needs_a_key_and_a_real_tool_call(monkeypatch):
    spec = bench.ModelSpec("p", "m", "http://127.0.0.1:9/v1", "LF_TEST_KEY_UNSET", 1, 1)
    monkeypatch.delenv("LF_TEST_KEY_UNSET", raising=False)
    assert "not set" in bench.preflight(spec)

    text_only = FakeProvider([(200, {}, '{"data": [{"id": "m"}]}'), (200, {}, json.dumps({"choices": [{"message": {"content": "sure"}}]}))])
    tooled = FakeProvider([(200, {}, '{"data": [{"id": "m"}]}'), (200, {}, json.dumps({"choices": [{"message": {"tool_calls": [{"id": "1"}]}}]}))])
    try:
        monkeypatch.setenv("LF_TEST_KEY_UNSET", "k")
        assert "without a native tool call" in bench.preflight(bench.ModelSpec("p", "m", text_only.url, "LF_TEST_KEY_UNSET", 1, 1))
        assert bench.preflight(bench.ModelSpec("p", "m", tooled.url, "LF_TEST_KEY_UNSET", 1, 1)) is None
        missing = FakeProvider([(200, {}, '{"data": [{"id": "other-model"}]}')])
        reason = bench.preflight(bench.ModelSpec("p", "m", missing.url, "LF_TEST_KEY_UNSET", 1, 1))
        assert "not offered" in reason and "other-model" in reason  # lists what *is* available
        missing.close()
    finally:
        text_only.close()
        tooled.close()


def test_model_lists_can_be_overridden(monkeypatch):
    monkeypatch.setenv("GROQ_MODELS", "a/one, b/two")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-x")
    assert [m.model for m in bench.default_models()] == ["a/one", "b/two", "gemini-x"]


def test_one_model_running_out_of_quota_does_not_stop_the_others(tmp_path, monkeypatch):
    first, second = bench.default_models()[:2]
    assert first.provider == second.provider
    flags = tmp_path / "_quota_flags"
    flags.mkdir()
    (flags / f"{first.run_name}.quota").write_text("")
    assert "quota" in bench.run_model(first, tmp_path, 1, 0.7, 1, flags)

    started = []
    monkeypatch.setattr(bench.subprocess, "Popen", lambda *a, **k: started.append(a) or (_ for _ in ()).throw(RuntimeError("stop")))
    with pytest.raises(RuntimeError):
        bench.run_model(second, tmp_path, 1, 0.7, 1, flags)
    assert started  # the second model was not skipped
