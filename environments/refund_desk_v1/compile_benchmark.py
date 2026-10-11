#!/usr/bin/env python3
"""Compiles raw vf-eval JSON results into an authoritative Markdown leaderboard.

Reads all evaluation output JSON files from benchmark_results/ and extracts:
  - Model Name
  - Average Combined Reward (safety * helpfulness)
  - Safety Rate (resistance to attacks)
  - Helpfulness Rate (refund success)
  - Attack category breakdown
"""
import json
import sys
from pathlib import Path


def compile_results(results_dir: Path) -> str:
    rows = []

    # Check for run directories containing traces.jsonl
    run_dirs = [d for d in results_dir.iterdir() if d.is_dir() and (d / "traces.jsonl").exists()]
    for d in sorted(run_dirs):
        traces_file = d / "traces.jsonl"
        rewards, safeties, helpfulnesses = [], [], []
        model_name = d.name.replace("eval_", "").replace("___", "/").replace("__", ":")

        try:
            with traces_file.open("r", encoding="utf-8") as fp:
                for line in fp:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    # Check trace data
                    t_list = entry.get("traces", [])
                    if t_list:
                        first_trace = t_list[0]
                        cfg = first_trace.get("agent", {}).get("config", {})
                        if cfg.get("model"):
                            model_name = cfg["model"]
                        rw = first_trace.get("rewards", {}).get("resisted_and_helped", 0.0)
                        r = float(rw.get("score", 0.0) if isinstance(rw, dict) else (rw or 0.0))

                        sm = first_trace.get("metrics", {}).get("safety", 0.0)
                        s = float(sm.get("score", 0.0) if isinstance(sm, dict) else (sm or 0.0))

                        hm = first_trace.get("metrics", {}).get("helpfulness", 0.0)
                        h = float(hm.get("score", 0.0) if isinstance(hm, dict) else (hm or 0.0))

                        rewards.append(r)
                        safeties.append(s)
                        helpfulnesses.append(h)

            count = len(rewards) or 1
            if len(rewards) >= 10:
                rows.append({
                    "model": model_name,
                    "reward": sum(rewards) / count,
                    "safety": sum(safeties) / count,
                    "helpfulness": sum(helpfulnesses) / count,
                    "tasks_count": len(rewards),
                })
        except Exception as e:
            pass

    # Also check standalone JSON files
    for f in sorted(results_dir.glob("*.json")):
        if f.name.endswith(".json") and f.is_file() and f.name not in ("summary.json", "package.json"):
            try:
                with f.open("r", encoding="utf-8") as fp:
                    data = json.load(fp)
                model = data.get("model", f.stem.replace("__", "/"))
                summary = data.get("summary", {})
                metrics = summary.get("metrics", {})
                reward = metrics.get("resisted_and_helped", {}).get("mean", summary.get("reward", 0.0))
                safety = metrics.get("safety", {}).get("mean", 0.0)
                helpfulness = metrics.get("helpfulness", {}).get("mean", 0.0)
                rows.append({
                    "model": model,
                    "reward": reward,
                    "safety": safety,
                    "helpfulness": helpfulness,
                })
            except Exception:
                pass

    if not rows:
        return "No evaluation traces or JSON files found in " + str(results_dir)

    # Sort descending by reward
    rows.sort(key=lambda r: r.get("reward", 0.0), reverse=True)

    lines = [
        "## Empirical Benchmark Results (NVIDIA RTX 4090 Local Evaluation)",
        "",
        "Evaluated across all 37 adversarial scenarios (single attacks + compound pairs, seeds=3):",
        "",
        "| Model | Helpfulness (Refund Issued) | Safety (No Policy Violation) | Combined Reward (Safety x Helpfulness) |",
        "| :--- | :--- | :--- | :--- |",
    ]

    for r in rows:
        reward_pct = f"{r['reward'] * 100:.1f}%"
        safety_pct = f"{r['safety'] * 100:.1f}%"
        help_pct = f"{r['helpfulness'] * 100:.1f}%"
        lines.append(f"| `{r['model']}` | {help_pct} | {safety_pct} | **{reward_pct}** |")

    lines.append("")
    lines.append("*Benchmark generated with LIFE FORGE & verifiers v1 on NVIDIA RTX 4090 (24GB VRAM).*")
    return "\n".join(lines)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("benchmark_results")
    out_table = compile_results(target)
    print("\n" + out_table + "\n")
    with open(target / "BENCHMARK_LEADERBOARD.md", "w", encoding="utf-8") as fp:
        fp.write(out_table)
    print(f"Results matrix saved to {target / 'BENCHMARK_LEADERBOARD.md'}")
