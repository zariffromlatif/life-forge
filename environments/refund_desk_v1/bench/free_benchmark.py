"""Run the refund-desk benchmark on free-tier hosted models, a little each day.

Free tiers cap tokens per day, so a full pass takes several days. This script is
built to be run repeatedly (the GitHub workflow runs it daily):

1. For each configured model whose API key is present, a **pre-flight** request
   checks the model exists and returns a real tool call (a model that cannot
   call tools would only measure the serving stack).
2. It starts the local rate-limit proxy for that provider and runs ``eval``
   against it, **resuming** the model's run if one exists. A per-model time
   budget and the proxy's daily-quota flag end the day's work cleanly.
3. When every model is complete it compiles the leaderboard.

Nothing is uploaded (``--no-push``). Keys are read from the environment and only
sent to their own provider.

    GROQ_API_KEY=... GEMINI_API_KEY=... python free_benchmark.py --output outputs/free_v1
    python free_benchmark.py --dry-run          # validate configs, no keys or network needed
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
ENV_DIR = HERE.parent
TASKS = 37


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str
    base_url: str
    key_var: str
    rpm: int
    tpm: int

    @property
    def run_name(self) -> str:
        return "eval_" + "".join(c if c.isalnum() or c in "-" else "_" for c in f"{self.provider}_{self.model}")


def default_models() -> list[ModelSpec]:
    """Free-tier models with native tool calling. Limits are deliberately below the
    published free-tier figures (which vary by account and change without notice)."""
    groq = "https://api.groq.com/openai/v1"
    gemini = "https://generativelanguage.googleapis.com/v1beta/openai"
    # Provider catalogs change; override with comma-separated GROQ_MODELS / GEMINI_MODEL.
    groq_models = [m.strip() for m in os.environ.get("GROQ_MODELS", "openai/gpt-oss-120b,qwen/qwen3-32b,meta-llama/llama-4-scout-17b-16e-instruct").split(",") if m.strip()]
    specs = [ModelSpec("groq", model, groq, "GROQ_API_KEY", rpm=20, tpm=6000) for model in groq_models]
    specs.append(ModelSpec("gemini", os.environ.get("GEMINI_MODEL") or "gemini-3.8-flash", gemini, "GEMINI_API_KEY", rpm=8, tpm=200000))
    return specs


def eval_binary() -> str:
    """verifiers 0.3.1 names it ``eval``; later builds ``vf-eval``. Never the shell builtin."""
    bindir = Path(sys.executable).parent
    for name in ("eval", "vf-eval", "eval.exe", "vf-eval.exe"):
        if (bindir / name).exists():
            return str(bindir / name)
    raise SystemExit(f"no verifiers eval command next to {sys.executable}")


def eval_command(spec: ModelSpec, base_url: str, output: Path, rollouts: int, temperature: float, *, resume: bool, dry_run: bool) -> list[str]:
    binary = eval_binary()
    saved = output / spec.run_name / "configs" / "resolved" / "eval.json"
    if resume and saved.exists() and not dry_run:
        return [binary, "@", str(saved), "--resume"]
    command = [
        binary, "refund-desk-v1",
        "-m", spec.model,
        "--client.base-url", base_url,
        "--client.api-key-var", spec.key_var,
        "-r", str(rollouts),
        "--sampling.temperature", str(temperature),
        "-c", "1",
        # Run the agent locally. Without this the taskset's harness defaults to Prime's remote
        # runtime, which needs a Prime login and otherwise hangs (seen 2026-10-12).
        "--env.agent.runtime.type", "subprocess",
        # A stuck episode must cost one task, not the day's budget.
        "--env.agent.timeout.rollout", "900",
        "--run.name", spec.run_name,
        "-o", str(output),
        "--no-push",
    ]
    if dry_run:
        command.append("--dry-run")
    return command


def episodes_done(output: Path, spec: ModelSpec) -> int:
    traces = output / spec.run_name / "traces.jsonl"
    if not traces.exists():
        return 0
    done = 0
    for line in traces.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        done += sum(1 for trace in entry.get("traces") or [] if trace.get("ok", True) and not trace.get("errors"))
    return done


def preflight(spec: ModelSpec) -> str | None:
    """Return None when the model exists and makes a native tool call, else a reason."""
    key = os.environ.get(spec.key_var)
    if not key:
        return f"{spec.key_var} is not set"
    headers = {"Authorization": f"Bearer {key}"}
    try:
        listed = httpx.get(f"{spec.base_url}/models", headers=headers, timeout=30)
        if listed.status_code == 200:
            ids = {m.get("id", "").removeprefix("models/") for m in listed.json().get("data", [])}
            if ids and spec.model not in ids:
                return f"model {spec.model!r} not offered. Available: {', '.join(sorted(ids))}"
        probe = httpx.post(
            f"{spec.base_url}/chat/completions",
            headers=headers,
            timeout=60,
            json={
                "model": spec.model,
                "messages": [{"role": "user", "content": "Look up order ORD-1001 using the tool."}],
                "tools": [{"type": "function", "function": {"name": "lookup_order", "description": "Look up an order.", "parameters": {"type": "object", "properties": {"order_id": {"type": "string"}}, "required": ["order_id"]}}}],
                "tool_choice": "auto",
            },
        )
    except httpx.HTTPError as exc:
        return f"network error: {exc}"
    if probe.status_code != 200:
        return f"probe HTTP {probe.status_code}: {probe.text[:200]}"
    message = probe.json()["choices"][0]["message"]
    if not message.get("tool_calls"):
        return "model answered without a native tool call (not measurable)"
    return None


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_model(spec: ModelSpec, output: Path, rollouts: int, temperature: float, budget_minutes: float, flags: Path) -> str:
    target = TASKS * rollouts
    done = episodes_done(output, spec)
    if done >= target:
        return f"complete ({done}/{target})"
    flag = flags / f"{spec.provider}.quota"
    if flag.exists():
        return "skipped: provider quota already reached today"
    port = free_port()
    proxy = subprocess.Popen(
        [sys.executable, str(HERE / "ratelimit_proxy.py"), "--upstream", spec.base_url, "--port", str(port),
         "--rpm", str(spec.rpm), "--tpm", str(spec.tpm), "--quota-flag", str(flag)],
    )
    time.sleep(1.5)
    try:
        command = eval_command(spec, f"http://127.0.0.1:{port}/v1", output, rollouts, temperature, resume=done > 0, dry_run=False)
        print("$", " ".join(command[:4]), "...", flush=True)
        process = subprocess.Popen(command)
        deadline = time.monotonic() + budget_minutes * 60
        while process.poll() is None:
            if time.monotonic() > deadline or flag.exists():
                reason = "time budget" if time.monotonic() > deadline else "daily quota"
                print(f"  stopping {spec.model}: {reason}; it resumes on the next run", flush=True)
                process.send_signal(signal.SIGINT)  # graceful: finished rollouts are kept
                try:
                    process.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    process.kill()
                break
            time.sleep(5)
    finally:
        proxy.terminate()
    return f"{episodes_done(output, spec)}/{target} episodes"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=ENV_DIR / "outputs" / "free_v1")
    parser.add_argument("--rollouts", type=int, default=1, help="Samples per task (free tiers: 1)")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--budget-minutes", type=float, default=90, help="Max minutes per model per run")
    parser.add_argument("--only", default="", help="Comma-separated substrings to select models")
    parser.add_argument("--dry-run", action="store_true", help="Resolve and validate eval configs only")
    args = parser.parse_args(argv)

    models = [m for m in default_models() if not args.only or any(s in m.model for s in args.only.split(","))]
    args.output.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        for spec in models:
            subprocess.run(eval_command(spec, spec.base_url, args.output, args.rollouts, args.temperature, resume=False, dry_run=True), check=True)
        print("dry run OK:", ", ".join(m.run_name for m in models))
        return 0

    flags = args.output / "_quota_flags"
    if flags.exists():
        for stale in flags.iterdir():  # a new day: yesterday's quota flags no longer apply
            stale.unlink()
    flags.mkdir(exist_ok=True)

    status: dict[str, str] = {}
    for spec in models:
        print(f"== {spec.provider}/{spec.model}", flush=True)
        if episodes_done(args.output, spec) >= TASKS * args.rollouts:
            status[spec.model] = "complete"
            continue
        problem = preflight(spec)
        if problem:
            status[spec.model] = f"skipped: {problem}"
            print("  " + status[spec.model], flush=True)
            continue
        status[spec.model] = run_model(spec, args.output, args.rollouts, args.temperature, args.budget_minutes, flags)
        print("  " + status[spec.model], flush=True)

    (args.output / "STATUS.json").write_text(json.dumps({"updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "models": status}, indent=2) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, str(ENV_DIR / "compile_benchmark.py"), str(args.output)], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
