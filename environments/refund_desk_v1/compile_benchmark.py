#!/usr/bin/env python3
"""Compile refund-desk eval traces into a leaderboard that cannot hide a broken run.

For every ``outputs/<run>/traces.jsonl`` this:

* **recomputes** each episode's reward with the current scorer (``core.py``), so
  the table always reflects today's reward, and reports how many recorded scores
  differ;
* reports **tool-call participation**: a model that never calls a desk tool has
  not been measured (its "100% safety" only means it did nothing), so it is
  listed as *not measurable* instead of being ranked;
* flags runs whose harness offered **code-executing tools** (``bash``/``edit``),
  which are not a valid measurement of this environment;
* breaks reward down **by attack class**.

Usage: ``python compile_benchmark.py outputs``
"""
from __future__ import annotations

import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CODE_TOOLS = {"bash", "edit"}


def _load_core():
    # Load core.py by path: importing the package would import verifiers.
    spec = importlib.util.spec_from_file_location("refund_desk_core", HERE / "refund_desk_v1" / "core.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["refund_desk_core"] = module
    spec.loader.exec_module(module)
    return module


core = _load_core()


def _recorded_reward(trace: dict) -> float:
    value = (trace.get("rewards") or {}).get("resisted_and_helped", 0.0)
    return float(value.get("score", 0.0) if isinstance(value, dict) else (value or 0.0))


def _assistant_messages(trace: dict) -> list:
    messages = []
    for node in trace.get("nodes") or []:
        message = node.get("message") or {}
        if message.get("role") == "assistant" and node.get("sampled", True):
            messages.append(
                SimpleNamespace(
                    tool_calls=[
                        SimpleNamespace(name=call.get("name"), arguments=call.get("arguments"))
                        for call in message.get("tool_calls") or []
                    ]
                )
            )
    return messages


def analyze_run(run_dir: Path) -> dict | None:
    episodes = []
    model = run_dir.name.removeprefix("eval_")
    for line in (run_dir / "traces.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        data = (entry.get("task") or {}).get("data") or {}
        for trace in entry.get("traces") or []:
            model = ((trace.get("agent") or {}).get("config") or {}).get("model") or model
            offered = {tool.get("name") for tool in trace.get("tools") or [] if isinstance(tool, dict)}
            messages = _assistant_messages(trace)
            desk_calls = core.calls_from_assistant_messages(messages)
            foreign = core.foreign_tool_calls(messages, offered)
            result = core.score(data["world"], desk_calls, foreign)
            episodes.append(
                {
                    "attacks": data.get("attacks") or [],
                    "reward": result.reward,
                    "safety": result.safety,
                    "helpfulness": result.helpfulness,
                    "recorded": _recorded_reward(trace),
                    "desk_calls": len(desk_calls),
                    "code_tools_offered": bool(offered & CODE_TOOLS),
                }
            )
    if not episodes:
        return None
    n = len(episodes)
    by_attack: dict[str, list[float]] = defaultdict(list)
    for episode in episodes:
        for attack in episode["attacks"] or ["clean"]:
            by_attack[attack].append(episode["reward"])
    return {
        "model": model,
        "episodes": n,
        "reward": sum(e["reward"] for e in episodes) / n,
        "safety": sum(e["safety"] for e in episodes) / n,
        "helpfulness": sum(e["helpfulness"] for e in episodes) / n,
        "participation": sum(1 for e in episodes if e["desk_calls"]) / n,
        "rescored": sum(1 for e in episodes if abs(e["reward"] - e["recorded"]) > 1e-9),
        "code_tools": any(e["code_tools_offered"] for e in episodes),
        "by_attack": {attack: sum(values) / len(values) for attack, values in by_attack.items()},
    }


def compile_results(results_dir: Path) -> str:
    runs = [
        result
        for run_dir in sorted(p for p in results_dir.iterdir() if (p / "traces.jsonl").exists())
        if (result := analyze_run(run_dir))
    ]
    if not runs:
        return f"No traces.jsonl runs found in {results_dir}"

    measurable = sorted((r for r in runs if r["participation"] > 0), key=lambda r: r["reward"], reverse=True)
    unmeasured = [r for r in runs if r["participation"] == 0]

    lines = ["## refund-desk-v1 results", ""]
    if any(r["code_tools"] for r in runs):
        lines += [
            "> **Not a valid measurement.** These runs used a harness that gave the model a shell and file "
            "editor (`bash`/`edit`). The environment's own harness offers only the desk's tools. Re-run "
            "without overriding the harness before drawing conclusions.",
            "",
        ]
    lines += [
        "| Model | Episodes | Called a desk tool | Helpfulness | Safety | Reward (safety x helpfulness) | Re-scored |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in measurable:
        lines.append(
            f"| `{r['model']}` | {r['episodes']} | {r['participation']:.0%} | {r['helpfulness']:.1%} | "
            f"{r['safety']:.1%} | **{r['reward']:.1%}** | {r['rescored']} |"
        )
    for r in unmeasured:
        lines.append(
            f"| `{r['model']}` | {r['episodes']} | 0% | - | - | not measurable: no tool calls | {r['rescored']} |"
        )

    attacks = sorted({a for r in measurable for a in r["by_attack"]})
    if measurable and attacks:
        lines += ["", "### Reward by attack class", "", "| Model | " + " | ".join(attacks) + " |", "| :--- |" + " ---: |" * len(attacks)]
        for r in measurable:
            lines.append(f"| `{r['model']}` | " + " | ".join(f"{r['by_attack'].get(a, 0.0):.0%}" for a in attacks) + " |")

    lines += [
        "",
        "*Rewards are recomputed from the recorded tool calls with the current scorer. \"Called a desk tool\" is "
        "the share of episodes with at least one desk tool call; a model that never calls a tool (e.g. one served "
        "without native tool-calling support) has not been measured. One sample per task per model unless the "
        "Episodes column says otherwise.*",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "outputs"
    table = compile_results(target)
    print("\n" + table + "\n")
    (target / "BENCHMARK_LEADERBOARD.md").write_text(table + "\n", encoding="utf-8")
    print(f"Saved to {target / 'BENCHMARK_LEADERBOARD.md'}")
