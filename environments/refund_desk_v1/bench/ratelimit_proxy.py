"""A local OpenAI-compatible pass-through that keeps a run inside free-tier rate limits.

``verifiers`` 0.3.1 sends model requests with retries disabled, so on a free tier
the first ``429`` fails the whole episode. Point ``--client.base-url`` at this
proxy instead of the provider:

* it **paces** requests under a requests-per-minute and an estimated
  tokens-per-minute budget;
* on a ``429`` with a short wait (a per-minute limit) it **sleeps and retries**;
* on a ``429`` with a long wait (a daily quota) it **stops**: it writes a flag
  file, answers ``429`` to everything after, and the orchestrator ends the day's
  run so the next scheduled run can resume.

Authorization headers from the client are passed through unchanged; the proxy
never sees or stores a key other than in transit. It listens on 127.0.0.1 only.

    python ratelimit_proxy.py --upstream https://api.groq.com/openai/v1 --port 8787 \
        --rpm 25 --tpm 7000 --quota-flag /tmp/quota_exhausted
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

#: Request headers that describe the local hop and must not be forwarded.
HOP_HEADERS = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "accept-encoding"}
#: Rough characters-per-token for budgeting (conservative: over-estimates tokens).
CHARS_PER_TOKEN = 3.0
#: Output tokens assumed per request when the body does not cap them.
DEFAULT_OUTPUT_ESTIMATE = 800


def parse_wait_seconds(headers: httpx.Headers, body: str) -> float | None:
    """How long the provider asks us to wait, from headers or the error text."""
    for name in ("retry-after", "x-ratelimit-reset-tokens", "x-ratelimit-reset-requests"):
        value = headers.get(name)
        if value:
            seconds = _duration(value)
            if seconds is not None:
                return seconds
    match = re.search(r"try again in\s+((?:\d+h)?(?:\d+m)?(?:[\d.]+s)?|[\d.]+\s*seconds?)", body, re.IGNORECASE)
    if match:
        return _duration(match.group(1))
    match = re.search(r'"retryDelay"\s*:\s*"([\d.]+)s"', body)  # Google RetryInfo
    if match:
        return float(match.group(1))
    return None


def _duration(text: str) -> float | None:
    """Parse ``12``, ``7.66s``, ``1m2.5s``, ``2h3m`` or ``30 seconds`` into seconds."""
    text = text.strip().lower()
    try:
        return float(text)
    except ValueError:
        pass
    total, found = 0.0, False
    for amount, unit in re.findall(r"([\d.]+)\s*(h|ms|m|s|seconds?)", text):
        found = True
        value = float(amount)
        total += {"h": 3600, "m": 60, "s": 1, "ms": 0.001}.get(unit[:2] if unit == "ms" else unit[0], 1) * value
    return total if found else None


def is_daily_quota(text: str) -> bool:
    """Whether a 429 body names a per-day quota (Groq: "per day (TPD)"; Google: "PerDay")."""
    lowered = text.lower()
    return "per day" in lowered or "perday" in lowered or "(tpd)" in lowered or "(rpd)" in lowered


def estimate_tokens(body: bytes) -> int:
    """Budget estimate for one request: prompt size plus its output cap."""
    tokens = int(len(body) / CHARS_PER_TOKEN)
    try:
        payload = json.loads(body or b"{}")
        cap = payload.get("max_tokens") or payload.get("max_completion_tokens")
    except (ValueError, AttributeError):
        cap = None
    return tokens + int(cap or DEFAULT_OUTPUT_ESTIMATE)


class Throttle:
    """Sliding one-minute window over requests and estimated tokens."""

    def __init__(self, rpm: int, tpm: int) -> None:
        self.rpm, self.tpm = rpm, tpm
        self.events: deque[tuple[float, int]] = deque()
        self.lock = threading.Lock()

    def wait_for(self, tokens: int, now=time.monotonic, sleep=time.sleep) -> float:
        """Block until a request of ``tokens`` fits; return the time waited."""
        waited = 0.0
        tokens = min(tokens, self.tpm)  # one oversized request must still be able to go
        while True:
            with self.lock:
                current = now()
                while self.events and current - self.events[0][0] >= 60.0:
                    self.events.popleft()
                used = sum(t for _, t in self.events)
                if len(self.events) < self.rpm and used + tokens <= self.tpm:
                    self.events.append((current, tokens))
                    return waited
                pause = max(0.05, 60.0 - (current - self.events[0][0])) if self.events else 0.05
            sleep(pause)
            waited += pause


class ProxyState:
    def __init__(self, upstream: str, throttle: Throttle, quota_flag: Path, max_wait: float, max_retries: int) -> None:
        self.upstream = upstream.rstrip("/")
        self.throttle = throttle
        self.quota_flag = quota_flag
        self.max_wait = max_wait
        self.max_retries = max_retries
        self.client = httpx.Client(timeout=httpx.Timeout(connect=10.0, read=300.0, write=60.0, pool=None))
        self.stats = {"requests": 0, "retries": 0, "throttled_seconds": 0.0}


def make_handler(state: ProxyState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep CI logs to one line per event
            sys.stderr.write("[proxy] " + (fmt % args) + "\n")

        def _reply(self, status: int, body: bytes, headers: dict[str, str]) -> None:
            self.send_response(status)
            for name, value in headers.items():
                if name.lower() not in HOP_HEADERS and name.lower() != "content-encoding":
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _forward(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if state.quota_flag.exists():
                payload = {"error": {"message": "daily quota exhausted (proxy)", "type": "rate_limit"}}
                self._reply(429, json.dumps(payload).encode(), {"content-type": "application/json"})
                return
            path = self.path[3:] if self.path.startswith("/v1") else self.path
            url = state.upstream + path
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS}
            for attempt in range(state.max_retries + 1):
                if method == "POST":
                    state.stats["throttled_seconds"] += state.throttle.wait_for(estimate_tokens(body))
                state.stats["requests"] += 1
                try:
                    response = state.client.request(method, url, content=body, headers=headers)
                except httpx.HTTPError as exc:
                    payload = {"error": {"message": f"proxy upstream error: {exc}", "type": "upstream"}}
                    self._reply(502, json.dumps(payload).encode(), {"content-type": "application/json"})
                    return
                if response.status_code != 429 or attempt == state.max_retries:
                    self._reply(response.status_code, response.content, dict(response.headers))
                    return
                wait = parse_wait_seconds(response.headers, response.text)
                if wait is None:
                    wait = min(60.0, 5.0 * (2 ** attempt))
                if wait > state.max_wait or is_daily_quota(response.text):
                    state.quota_flag.parent.mkdir(parents=True, exist_ok=True)
                    state.quota_flag.write_text(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} wait={wait:.0f}s\n{response.text[:500]}\n")
                    sys.stderr.write(f"[proxy] daily quota reached (wait {wait:.0f}s); stopping for today\n")
                    self._reply(response.status_code, response.content, dict(response.headers))
                    return
                state.stats["retries"] += 1
                sys.stderr.write(f"[proxy] 429, waiting {wait:.1f}s (attempt {attempt + 1})\n")
                time.sleep(wait + 0.5)

        def do_POST(self):  # noqa: N802 - stdlib hook
            self._forward("POST")

        def do_GET(self):  # noqa: N802 - stdlib hook
            self._forward("GET")

    return Handler


def serve(upstream: str, port: int, rpm: int, tpm: int, quota_flag: Path, max_wait: float = 120.0, max_retries: int = 6):
    state = ProxyState(upstream, Throttle(rpm, tpm), quota_flag, max_wait, max_retries)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    server.daemon_threads = True
    return server, state


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--upstream", required=True, help="Provider base URL ending in /v1 (or the OpenAI-compatible root)")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--rpm", type=int, default=20, help="Requests per minute budget")
    parser.add_argument("--tpm", type=int, default=6000, help="Estimated tokens per minute budget")
    parser.add_argument("--quota-flag", type=Path, required=True, help="File written when the daily quota is reached")
    parser.add_argument("--max-wait", type=float, default=120.0, help="Longest 429 wait to sit out; longer means daily quota")
    args = parser.parse_args(argv)
    server, _ = serve(args.upstream, args.port, args.rpm, args.tpm, args.quota_flag, args.max_wait)
    sys.stderr.write(f"[proxy] 127.0.0.1:{args.port} -> {args.upstream} (rpm {args.rpm}, tpm {args.tpm})\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
