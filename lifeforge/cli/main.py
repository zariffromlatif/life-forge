"""Command-line interface (CLI) for LIFE FORGE scientific laboratory."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from lifeforge.experiments.database import ExperimentDatabase
from lifeforge.metrics.modes import analyze_modes
from lifeforge.substrates.ca.elementary import ElementaryCA
from lifeforge.substrates.ca.totalistic import OuterTotalisticCA


def cmd_run(args: argparse.Namespace) -> None:
    """Run a single universe simulation and print its MODES vector."""
    if args.substrate == "elementary":
        ca = ElementaryCA(args.rule)
        state = ElementaryCA.seed_random(args.width, density=args.density, seed=args.seed)
    else:
        # Default Conway or outer totalistic
        ca = OuterTotalisticCA.conway()
        state = OuterTotalisticCA.random_state(args.height, args.width, density=args.density, seed=args.seed)

    print(f"Running {ca.description} for {args.steps} steps...")
    traj = ca.rollout(state, steps=args.steps)
    modes = analyze_modes(traj)

    print("\n--- MODES Scientific Profile ---")
    print(f"Dynamic Regime:       {modes.wolfram_class}")
    print(f"Complexity Gap:       {modes.complexity_gap:.4f}")
    print(f"Shannon Entropy:      {modes.shannon_entropy:.4f}")
    print(f"Compressibility:      {modes.compressibility_ratio:.4f}")
    print(f"Cumulative Activity:  {modes.cumulative_activity:,.1f}")
    print(f"Cluster Count:        {modes.cluster_count}")
    print(f"Persistence Ratio:    {modes.persistence_ratio * 100:.1f}%")
    print(f"Class IV Candidate:   {modes.is_class_iv_candidate}")


def cmd_survey(args: argparse.Namespace) -> None:
    """Survey candidate universe rules and record to the experiment database."""
    db = ExperimentDatabase(args.db)
    print(f"Initiating universe survey of {args.count} rules -> {args.db}")

    class_counts: dict[str, int] = {}
    class_iv_rules: list[str] = []

    for i in range(args.count):
        seed = args.seed + i
        ca = OuterTotalisticCA.random(seed=seed)
        state = OuterTotalisticCA.random_state(args.height, args.width, density=0.20, seed=seed)
        record = db.log_simulation(ca, state, steps=args.steps, seed=seed)

        w_class = record.modes.get("wolfram_class", "Unknown")
        class_counts[w_class] = class_counts.get(w_class, 0) + 1
        if record.modes.get("is_class_iv_candidate"):
            class_iv_rules.append(record.rule_notation)

        if (i + 1) % max(1, args.count // 10) == 0 or (i + 1) == args.count:
            print(f"  [{i + 1}/{args.count}] Surveyed rules logged. Discovered {len(class_iv_rules)} Class IV candidates so far.")

    print("\n=== Survey Complete ===")
    print(f"Total universes logged: {db.count()}")
    for wc, count in class_counts.items():
        print(f"  • {wc:<40}: {count}")
    print(f"\nClass IV Candidates Found: {len(class_iv_rules)}")
    if class_iv_rules:
        print(f"Sample candidates: {', '.join(class_iv_rules[:5])}")


def cmd_test(args: argparse.Namespace) -> None:
    """Run the evolutionary red-teaming engine against an agent."""
    from lifeforge.sandbox.agent import RuleBasedPurchasingAgent
    from lifeforge.sandbox.oracle import SandboxRunner
    from lifeforge.sandbox.world_state import WorldState
    from lifeforge.evolution.engine import EvolutionEngine
    from lifeforge.reporting.analyzer import CausalAnalyzer
    from lifeforge.reporting.report import ReportGenerator

    print("=" * 60)
    print("  LIFE FORGE — Evolutionary Agent Stress Test")
    print("=" * 60)

    # Configure agent
    if getattr(args, "model", None):
        from lifeforge.sandbox.llm_agent import LLMAgent, LLMAgentConfig
        import os
        api_key = args.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        config = LLMAgentConfig(
            model=args.model,
            api_key=api_key,
            api_base=args.api_base,
            temperature=args.temperature,
        )
        agent = LLMAgent(config=config)
        print(f"\n  Agent:        {agent.name}")
        print(f"  Model:        {args.model}")
        print(f"  API Base:     {args.api_base or 'Default Cloud Provider'}")
        print(f"  Scenarios:    {args.scenarios}")
        print(f"  Seed:         {args.seed}")
    else:
        vuln = not args.hardened
        agent = RuleBasedPurchasingAgent(
            name=args.agent_name or "PurchasingAgent-v1",
            vulnerable_to_injection=vuln,
        )
        print(f"\n  Agent:        {agent.name}")
        print(f"  Vulnerable:   {vuln}")
        print(f"  Scenarios:    {args.scenarios}")
        print(f"  Seed:         {args.seed}")

    # Run evolution
    delay = getattr(args, "delay", 0.0)
    engine = EvolutionEngine(seed=args.seed, delay=delay)
    seed_state = WorldState.default_purchasing_world()

    print(f"\n  Running evolutionary search ({args.scenarios} generations)...")
    summary = engine.run(agent, seed_state, generations=args.scenarios)

    print(f"\n  Evaluations:      {summary.total_evaluations}")
    print(f"  Archive Coverage: {summary.archive_coverage * 100:.1f}%")
    print(f"  Elites:           {summary.elites_count}")
    print(f"  Critical Fails:   {summary.critical_failures_count}")
    print(f"  Failure Modes:    {summary.novel_failure_modes}")

    # Generate report
    analyzer = CausalAnalyzer()
    diagnostics = analyzer.analyze(agent, summary, seed_state)

    report = ReportGenerator.generate_markdown(diagnostics)

    # Output
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"\n  Report saved to: {out_path}")

    # JSON output
    if args.json:
        from dataclasses import asdict
        json_path = out_path.with_suffix(".json")
        json_path.write_text(
            json.dumps(asdict(diagnostics), indent=2, default=str),
            encoding="utf-8",
        )
        print(f"  JSON report:  {json_path}")

    # Exit code
    if summary.critical_failures_count > 0:
        print(f"\n  ⚠ CRITICAL: {summary.critical_failures_count} critical vulnerabilities discovered.")
        sys.exit(1)
    else:
        print("\n  ✓ No critical vulnerabilities found.")


def cmd_mcp_serve(args: argparse.Namespace) -> None:
    """Start the LIFE FORGE MCP server."""
    from lifeforge.sandbox.mcp_server import LifeForgeMCPServer, MCPServerConfig

    config = MCPServerConfig(
        enable_mutations=args.adversarial,
        mutation_probability=args.mutation_rate,
    )

    mutators = []
    if args.adversarial:
        from lifeforge.evolution.mutators.adversarial import (
            IndirectPromptInjectionMutator,
        )
        from lifeforge.evolution.mutators.semantic import SemanticMutator

        mutators = [IndirectPromptInjectionMutator(), SemanticMutator()]

    server = LifeForgeMCPServer(config=config, mutators=mutators)

    if args.transport == "stdio":
        print("Starting LIFE FORGE MCP Server (stdio)...", file=sys.stderr)
        server.run_stdio()
    else:
        print(f"Transport '{args.transport}' not yet implemented. Use 'stdio'.", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="LIFE FORGE: Evolutionary AI Agent Flight Simulator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Run command
    run_parser = subparsers.add_parser("run", help="Run a single universe simulation")
    run_parser.add_argument("--substrate", choices=["elementary", "totalistic"], default="totalistic")
    run_parser.add_argument("--rule", type=int, default=110, help="ECA rule number (0-255)")
    run_parser.add_argument("--width", type=int, default=50)
    run_parser.add_argument("--height", type=int, default=50)
    run_parser.add_argument("--steps", type=int, default=100)
    run_parser.add_argument("--density", type=float, default=0.20)
    run_parser.add_argument("--seed", type=int, default=42)

    # Survey command
    survey_parser = subparsers.add_parser("survey", help="Survey random universes and log to database")
    survey_parser.add_argument("--count", type=int, default=50)
    survey_parser.add_argument("--steps", type=int, default=150)
    survey_parser.add_argument("--width", type=int, default=40)
    survey_parser.add_argument("--height", type=int, default=40)
    survey_parser.add_argument("--db", type=str, default="results/survey_experiments.jsonl")
    survey_parser.add_argument("--seed", type=int, default=1000)

    # Test command — evolutionary red-teaming
    test_parser = subparsers.add_parser("test", help="Run evolutionary red-teaming against an agent")
    test_parser.add_argument("--model", type=str, default=None, help="LLM model (e.g. gemini/gemini-2.0-flash, ollama/llama3.1:8b, gpt-4o-mini)")
    test_parser.add_argument("--api-key", type=str, default=None, help="API key for cloud model (or set GEMINI_API_KEY/OPENAI_API_KEY)")
    test_parser.add_argument("--api-base", type=str, default=None, help="API base URL (e.g. http://localhost:11434 for local Ollama)")
    test_parser.add_argument("--temperature", type=float, default=0.0, help="LLM temperature")
    test_parser.add_argument("--agent-name", type=str, default=None, help="Agent identifier")
    test_parser.add_argument("--scenarios", type=int, default=100, help="Number of evolutionary generations")
    test_parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between generations (useful for free tier API rate limits)")
    test_parser.add_argument("--seed", type=int, default=42, help="Random seed")
    test_parser.add_argument("--out", type=str, default="results/agent_evolution_report.md", help="Output report path")
    test_parser.add_argument("--json", action="store_true", help="Also generate JSON report")
    test_parser.add_argument("--hardened", action="store_true", help="Test a hardened (non-vulnerable) agent")

def cmd_compare(args: argparse.Namespace) -> None:
    """Compare multiple agent evaluation reports side-by-side."""
    import json
    from pathlib import Path

    reports = []
    for fpath in args.reports:
        p = Path(fpath)
        if not p.exists():
            print(f"Error: report file not found: {p}")
            sys.exit(1)
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
            reports.append(data)

    if len(reports) < 2:
        print("Error: please provide at least 2 report files to compare.")
        sys.exit(1)

    lines = [
        "# LIFE FORGE: Frontier Model Security Showdown",
        "",
        "> **Platform**: LIFE FORGE Evolutionary AI Simulation Engine",
        "> **Benchmark Type**: Co-Evolutionary Adversarial Red-Teaming & Stress Test",
        "",
        "---",
        "",
        "## Head-to-Head Comparison Matrix",
        "",
    ]

    # Build comparison table
    headers = ["Metric"] + [f"`{r.get('agent_name', 'Agent')}`" for r in reports]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join([":---"] * len(headers)) + " |")

    lines.append("| **Security Rating** | " + " | ".join([f"**{r.get('generalization_rating', 'N/A')}**" for r in reports]) + " |")
    lines.append("| **Total Simulations** | " + " | ".join([f"{r.get('total_evaluations', 0):,}" for r in reports]) + " |")
    lines.append("| **Scenarios Explored** | " + " | ".join([f"{r.get('scenarios_generated', 0):,}" for r in reports]) + " |")
    lines.append("| **Baseline Success Rate** | " + " | ".join([f"{r.get('success_rate', 0.0)}%" for r in reports]) + " |")
    lines.append("| **Adversarial Failure Rate** | " + " | ".join([f"**{r.get('failure_rate', 0.0)}%**" for r in reports]) + " |")
    lines.append("| **Critical Vulnerabilities** | " + " | ".join([f"🔴 **{r.get('critical_failures', 0)}**" for r in reports]) + " |")
    lines.append("| **Novel Failure Modes** | " + " | ".join([f"{r.get('novel_failure_modes_count', 0)}" for r in reports]) + " |")
    lines.append("| **Most Vulnerable Capability** | " + " | ".join([f"*{r.get('most_vulnerable_capability', 'N/A')}*" for r in reports]) + " |")

    lines.extend([
        "",
        "---",
        "",
        "## Failure Mode Breakdown Comparison",
        "",
    ])

    all_categories = sorted(list({cat for r in reports for cat in r.get("failure_mode_breakdown", {}).keys()}))
    cat_headers = ["Failure Category"] + [f"`{r.get('agent_name', 'Agent')}`" for r in reports]
    lines.append("| " + " | ".join(cat_headers) + " |")
    lines.append("| " + " | ".join([":---"] * len(cat_headers)) + " |")

    for cat in all_categories:
        row = [f"`{cat}`"]
        for r in reports:
            cnt = r.get("failure_mode_breakdown", {}).get(cat, 0)
            sev = "🔴 " if "UNAUTHORIZED" in cat else ("🟠 " if "LOOP" in cat or "BUDGET" in cat else "🟡 ")
            row.append(f"{sev}{cnt}" if cnt > 0 else "0")
        lines.append("| " + " | ".join(row) + " |")

    # Winner determination
    sorted_by_crit = sorted(reports, key=lambda x: (x.get("critical_failures", 0), x.get("failure_rate", 100.0)))
    winner = sorted_by_crit[0]
    lines.extend([
        "",
        "---",
        "",
        f"## Security Winner: `{winner.get('agent_name')}`",
        "",
        f"Demonstrated superior resilience with only **{winner.get('critical_failures', 0)} critical vulnerabilities** "
        f"and an adversarial failure rate of **{winner.get('failure_rate', 0.0)}%** under identical evolutionary pressures.",
        "",
        "*LIFE FORGE — The Flight Simulator for AI Agents*",
    ])

    output_text = "\n".join(lines)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output_text, encoding="utf-8")
    print(f"\n  [OK] Comparison report generated: {out_path}\n")
    # Print safe ASCII table preview
    try:
        print(output_text)
    except UnicodeEncodeError:
        print(output_text.encode("ascii", errors="replace").decode("ascii"))


def main() -> None:
    parser = argparse.ArgumentParser(description="LIFE FORGE: Evolutionary AI Agent Flight Simulator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Run command
    run_parser = subparsers.add_parser("run", help="Run a single universe simulation")
    run_parser.add_argument("--substrate", choices=["elementary", "totalistic"], default="totalistic")
    run_parser.add_argument("--rule", type=int, default=110, help="ECA rule number (0-255)")
    run_parser.add_argument("--width", type=int, default=50)
    run_parser.add_argument("--height", type=int, default=50)
    run_parser.add_argument("--steps", type=int, default=100)
    run_parser.add_argument("--density", type=float, default=0.20)
    run_parser.add_argument("--seed", type=int, default=42)

    # Survey command
    survey_parser = subparsers.add_parser("survey", help="Survey random universes and log to database")
    survey_parser.add_argument("--count", type=int, default=50)
    survey_parser.add_argument("--steps", type=int, default=150)
    survey_parser.add_argument("--width", type=int, default=40)
    survey_parser.add_argument("--height", type=int, default=40)
    survey_parser.add_argument("--db", type=str, default="results/survey_experiments.jsonl")
    survey_parser.add_argument("--seed", type=int, default=1000)

    # Test command — evolutionary red-teaming
    test_parser = subparsers.add_parser("test", help="Run evolutionary red-teaming against an agent")
    test_parser.add_argument("--model", type=str, default=None, help="LLM model (e.g. gemini/gemini-2.0-flash, ollama/llama3.1:8b, gpt-4o-mini)")
    test_parser.add_argument("--api-key", type=str, default=None, help="API key for cloud model (or set GEMINI_API_KEY/OPENAI_API_KEY)")
    test_parser.add_argument("--api-base", type=str, default=None, help="API base URL (e.g. http://localhost:11434 for local Ollama)")
    test_parser.add_argument("--temperature", type=float, default=0.0, help="LLM temperature")
    test_parser.add_argument("--agent-name", type=str, default=None, help="Agent identifier")
    test_parser.add_argument("--scenarios", type=int, default=100, help="Number of evolutionary generations")
    test_parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between generations (useful for free tier API rate limits)")
    test_parser.add_argument("--seed", type=int, default=42, help="Random seed")
    test_parser.add_argument("--out", type=str, default="results/agent_evolution_report.md", help="Output report path")
    test_parser.add_argument("--json", action="store_true", help="Also generate JSON report")
    test_parser.add_argument("--hardened", action="store_true", help="Test a hardened (non-vulnerable) agent")

    # Compare command — head-to-head model comparison
    compare_parser = subparsers.add_parser("compare", help="Compare multiple agent evaluation reports")
    compare_parser.add_argument("reports", nargs="+", help="Paths to JSON report files")
    compare_parser.add_argument("--out", type=str, default="results/HEAD_TO_HEAD_SHOWDOWN.md", help="Output comparison path")

    # MCP serve command
    mcp_parser = subparsers.add_parser("mcp-serve", help="Start LIFE FORGE as an MCP server")
    mcp_parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio", help="MCP transport")
    mcp_parser.add_argument("--adversarial", action="store_true", help="Enable adversarial mutations during session")
    mcp_parser.add_argument("--mutation-rate", type=float, default=0.3, help="Probability of mutation per tool call")

    args = parser.parse_args()
    if args.command == "run":
        cmd_run(args)
    elif args.command == "survey":
        cmd_survey(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "mcp-serve":
        cmd_mcp_serve(args)


if __name__ == "__main__":
    main()
