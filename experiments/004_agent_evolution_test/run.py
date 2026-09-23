"""Experiment 004: Agent Evolution Test (The Flight Simulator Demonstration).

Demonstrates:
1. Traditional static evaluation: Agent scores 100% (illusion of security/reliability).
2. Evolutionary co-adaptive testing: LIFE FORGE searches adversarial & environmental niches.
3. Discovery of zero-day vulnerabilities, cycle loops, and cascading failure modes.
4. Generates executive-ready Agent Evolution Report.
"""
from __future__ import annotations

import sys
from pathlib import Path

from lifeforge import (
    CausalAnalyzer,
    EvolutionEngine,
    ReportGenerator,
    RuleBasedPurchasingAgent,
    SandboxRunner,
    WorldState,
)


OUTPUT_DIR = Path("results/004_agent_evolution_test")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 70)
    print(" LIFE FORGE -- Agent Evolution Test (The Flight Simulator for AI)")
    print("=" * 70)

    # 1. Initialize customer agent
    agent = RuleBasedPurchasingAgent(
        name="EnterprisePurchasingAgent-v1",
        vulnerable_to_injection=True,
        max_retries=3,
    )
    print(f"\n[1] Target Customer Agent: {agent.name}")
    print("    Capabilities: DatabaseQuery, VendorApi, IssuePurchaseOrder, SendEmail")
    print("    Environment: Enterprise Hardware Procurement Sandbox")

    # 2. Run traditional static benchmark
    runner = SandboxRunner()
    clean_world = WorldState.default_purchasing_world()
    clean_trace = runner.run(agent, clean_world)

    print("\n[2] Running Traditional Static Benchmark...")
    print(f"    Static Test Status: {'PASSED (100%)' if clean_trace.success else 'FAILED'}")
    print("    Observed: Normal happy-path purchase order completed successfully.")
    print("    Conventional Conclusion: 'Agent is ready for production deployment.'")

    # 3. Launch LIFE FORGE Evolutionary Red-Teaming
    print("\n[3] Launching LIFE FORGE Evolutionary Simulation Engine...")
    print("    Running 3D MAP-Elites co-adaptation over:")
    print("      * Adversarial Prompt Injection Intensity")
    print("      * Supply-Chain Scarcity & Market Volatility")
    print("      * Enterprise Budget Constraints")

    engine = EvolutionEngine(seed=42)
    summary = engine.run(agent, clean_world, generations=75)

    print(f"\n    Completed {summary.total_evaluations} simulated episodes across {summary.elites_count} behavioral niches.")
    print(f"    QD Archive Coverage: {summary.archive_coverage * 100:.1f}%")
    print(f"    Novel Failure Modes Discovered: {len(summary.novel_failure_modes)}")
    print(f"    Critical Vulnerabilities Uncovered: {summary.critical_failures_count}")

    # 4. Causal Analysis & Report Generation
    print("\n[4] Running Causal Reduction & Generating Agent Evolution Report...")
    analyzer = CausalAnalyzer(runner=runner)
    metrics = analyzer.analyze(agent, summary, seed_state=clean_world)

    paths = ReportGenerator.save(metrics, OUTPUT_DIR)

    print(f"\n    Report generated:")
    print(f"      * Markdown: {paths['markdown']}")
    print(f"      * JSON:     {paths['json']}")

    # 5. Print Executive Findings
    print("\n" + "=" * 70)
    print(" AGENT EVOLUTION REPORT -- EXECUTIVE SUMMARY")
    print("=" * 70)
    print(f" Target Agent:          {metrics.agent_name}")
    print(f" Generalization Status: {metrics.generalization_rating}")
    print(f" Adversarial Fail Rate: {metrics.failure_rate}%")
    print(f" Critical Breaches:     {metrics.critical_failures}")
    print(f" Most Vulnerable Area:  {metrics.most_vulnerable_capability}")
    print(f" Worst Behavior:        {metrics.worst_discovered_behavior}")
    print("-" * 70)
    print(" Discovered Failure Categories:")
    for cat, count in sorted(metrics.failure_mode_breakdown.items(), key=lambda x: x[1], reverse=True):
        print(f"   * {cat:<30}: {count} occurrences")

    print("-" * 70)
    print(" Key Causal Findings:")
    for i, finding in enumerate(metrics.findings, 1):
        print(f"   [{i}] {finding.title}")
        print(f"       Trigger: {', '.join(finding.minimal_causal_trigger)}")
        print(f"       Fix:     {finding.recommendation[:80]}...")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
