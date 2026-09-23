"""Quickstart Example: Running an Evolutionary Agent Stress Test programmatically."""
from __future__ import annotations

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.analyzer import CausalAnalyzer
from lifeforge.reporting.report import ReportGenerator
from lifeforge.sandbox.agent import RuleBasedPurchasingAgent
from lifeforge.sandbox.oracle import SandboxRunner


def main() -> None:
    print("=" * 60)
    print("  LIFE FORGE -- Programmatic Stress Test Example")
    print("=" * 60)

    # 1. Instantiate the target agent and sandbox runner
    agent = RuleBasedPurchasingAgent()
    runner = SandboxRunner()
    print(f"\n[*] Target Agent: {agent.name}")

    # 2. Initialize evolutionary red-teaming engine
    engine = EvolutionEngine(runner=runner, seed=42)

    # 3. Run 15 evolutionary generations
    print("[*] Running 15 evolutionary generations...")
    summary = engine.run(agent=agent, generations=15)

    print(f"\n[OK] Completed evolutionary search.")
    print(f"     Niches Discovered:       {summary.elites_count}")
    print(f"     Critical Exploit Niches: {summary.critical_failures_count}")
    print(f"     Archive Coverage:        {summary.archive_coverage * 100:.1f}%")

    # 4. Extract causal vulnerability findings and metrics
    analyzer = CausalAnalyzer(runner=runner)
    metrics = analyzer.analyze(agent=agent, summary=summary)
    print(f"     Unique Vulnerability Findings: {len(metrics.findings)}")

    for i, finding in enumerate(metrics.findings, 1):
        print(f"\n  Finding #{i}: {finding.title}")
        print(f"    Severity:        [{finding.severity}]")
        print(f"    Causal Triggers: {', '.join(finding.minimal_causal_trigger)}")
        print(f"    Recommendation:  {finding.recommendation}")

    # 5. Generate formatted markdown report
    report_md = ReportGenerator.generate_markdown(metrics)
    print(f"\n[OK] Audit report successfully generated in memory ({len(report_md)} bytes).")
    print("     First 300 characters of report:")
    print("     " + "-" * 40)
    for line in report_md.splitlines()[:10]:
        print(f"     {line}")


if __name__ == "__main__":
    main()
