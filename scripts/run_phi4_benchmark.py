"""Benchmark script: Microsoft Phi-4 (14B) on the LIFE FORGE evolutionary flight simulator.

Hardware target: Intel i9-14900K + NVIDIA RTX 4090 (24GB VRAM)
Inference: Ollama Q4_K_M quantization, 100% VRAM offload
Seed: 42 (deterministic, reproducible)
Generations: 30
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.analyzer import CausalAnalyzer
from lifeforge.reporting.leaderboard import write_leaderboard
from lifeforge.reporting.report import ReportGenerator
from lifeforge.sandbox.llm_agent import LLMAgent, LLMAgentConfig
from lifeforge.sandbox.world_state import WorldState

MODEL_TAG = "ollama/phi4:14b"
MODEL_LABEL = "phi4:14b"
API_BASE = "http://localhost:11434"
SEED = 42
GENERATIONS = 30
RESULTS_DIR = Path(__file__).parent.parent / "results"


def main() -> None:
    print("=" * 64)
    print("  LIFE FORGE -- Microsoft Phi-4 (14B) Security Benchmark")
    print("=" * 64)
    print(f"  Model:       {MODEL_TAG}")
    print(f"  API Base:    {API_BASE}")
    print(f"  Generations: {GENERATIONS}")
    print(f"  Seed:        {SEED}")
    print("  Hardware:    Intel i9-14900K + RTX 4090 (24GB VRAM)")
    print()

    config = LLMAgentConfig(
        model=MODEL_TAG,
        api_base=API_BASE,
        temperature=0.0,
    )
    agent = LLMAgent(config=config)

    engine = EvolutionEngine(seed=SEED)
    seed_state = WorldState.default_purchasing_world()

    print(f"  Running {GENERATIONS} evolutionary generations...")
    print()
    summary = engine.run(agent, seed_state, generations=GENERATIONS)

    print()
    print("  --- Results ---")
    print(f"  Total evaluations:  {summary.total_evaluations}")
    print(f"  Archive coverage:   {summary.archive_coverage * 100:.1f}%")
    print(f"  Elites:             {summary.elites_count}")
    print(f"  Critical failures:  {summary.critical_failures_count}")
    print(f"  Novel failure modes: {summary.novel_failure_modes}")

    # Generate diagnostic report
    analyzer = CausalAnalyzer()
    diagnostics = analyzer.analyze(agent, summary, seed_state)

    # Write Markdown report
    md_report = ReportGenerator.generate_markdown(diagnostics)
    md_path = RESULTS_DIR / "local_phi4_report.md"
    md_path.write_text(md_report, encoding="utf-8")
    print(f"\n  [OK] Markdown report: {md_path}")

    # Write JSON report
    from dataclasses import asdict
    json_path = RESULTS_DIR / "local_phi4_report.json"
    json_path.write_text(
        json.dumps(asdict(diagnostics), indent=2, default=str),
        encoding="utf-8",
    )
    print(f"  [OK] JSON report:     {json_path}")

    # Regenerate leaderboard with new data
    lb_path = write_leaderboard(RESULTS_DIR)
    print(f"  [OK] Leaderboard:     {lb_path}")

    print()
    if summary.critical_failures_count > 0:
        print(f"  [CRITICAL] {summary.critical_failures_count} critical zero-day vulnerabilities discovered.")
        sys.exit(1)
    else:
        print("  [OK] No critical vulnerabilities found.")
        print(f"  Adversarial failure modes: {summary.novel_failure_modes}")


if __name__ == "__main__":
    main()
