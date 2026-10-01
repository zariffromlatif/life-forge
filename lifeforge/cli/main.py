"""Command-line interface (CLI) for LIFE FORGE scientific laboratory."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure UTF-8 output with replacement fallback across all platforms (e.g. Windows CP1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

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
        print(f"  * {wc:<40}: {count}")
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
    print("  LIFE FORGE -- Evolutionary Agent Stress Test")
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
    domain = _resolve_domain(getattr(args, "domain", None))
    if domain is not None:
        print(f"  Domain:       {domain.name} ({domain.title})")
    delay = getattr(args, "delay", 0.0)
    engine = EvolutionEngine(
        seed=args.seed,
        delay=delay,
        domain=domain,
        frontier_mutators=getattr(args, "frontier", False),
    )
    seed_state = domain.build_world() if domain is not None else WorldState.default_purchasing_world()

    print(f"\n  Running evolutionary search ({args.scenarios} generations)...")
    summary = engine.run(agent, seed_state, generations=args.scenarios)

    print(f"\n  Evaluations:      {summary.total_evaluations}")
    print(f"  Archive Coverage: {summary.archive_coverage * 100:.1f}%")
    print(f"  Elites:           {summary.elites_count}")
    print(f"  Critical Fails:   {summary.critical_failures_count}")
    print(f"  Failure Modes:    {summary.novel_failure_modes}")

    # Generate report
    analyzer = CausalAnalyzer(runner=engine.runner)
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
        print(f"\n  [!] CRITICAL: {summary.critical_failures_count} critical vulnerabilities discovered.")
        sys.exit(1)
    else:
        print("\n  [OK] No critical vulnerabilities found.")


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
    lines.append("| **Critical Vulnerabilities** | " + " | ".join([f"**{r.get('critical_failures', 0)}**" for r in reports]) + " |")
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
            sev = "[CRITICAL] " if "UNAUTHORIZED" in cat else ("[HIGH] " if "LOOP" in cat or "BUDGET" in cat else "[MEDIUM] ")
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
        "*LIFE FORGE -- The Flight Simulator for AI Agents*",
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


def cmd_eval(args: argparse.Namespace) -> None:
    """Evaluate a user-defined agent via file specification or HTTP webhook."""
    from lifeforge.evolution.engine import EvolutionEngine
    from lifeforge.reporting.analyzer import CausalAnalyzer
    from lifeforge.reporting.report import ReportGenerator
    from lifeforge.sandbox.http_agent import HTTPAgentAdapter
    from lifeforge.sandbox.loader import load_agent_from_spec
    from lifeforge.sandbox.world_state import WorldState

    print("=" * 60)
    print("  LIFE FORGE -- Universal Agent Evaluation Harness")
    print("=" * 60)

    # 1. Resolve agent
    if getattr(args, "target", None):
        agent = load_agent_from_spec(args.target, name=args.agent_name)
        print(f"\n  Target:       {args.target}")
        print(f"  Agent Name:   {agent.name}")
        print(f"  Agent Type:   {type(agent).__name__}")
    elif getattr(args, "endpoint", None):
        agent = HTTPAgentAdapter(
            endpoint=args.endpoint,
            reset_endpoint=args.reset_endpoint,
            name=args.agent_name or "RemoteHTTPAgent",
            timeout=args.timeout,
        )
        print(f"\n  Webhook URL:  {args.endpoint}")
        print(f"  Reset URL:    {args.reset_endpoint or 'None'}")
        print(f"  Agent Name:   {agent.name}")
    else:
        print("\n  [FAIL] Either --target or --endpoint must be specified.")
        sys.exit(1)

    print(f"  Scenarios:    {args.scenarios}")
    print(f"  Seed:         {args.seed}")

    domain = _resolve_domain(getattr(args, "domain", None))
    seed_state = domain.build_world() if domain else WorldState.default_purchasing_world()
    runner = domain.build_runner() if domain else None
    if domain:
        print(f"  Domain:       {domain.name} ({domain.title})")

    # 2. Run evolution
    delay = getattr(args, "delay", 0.0)
    engine = EvolutionEngine(
        seed=args.seed,
        delay=delay,
        runner=runner,
        domain=domain,
        frontier_mutators=getattr(args, "frontier", False),
    )

    print(f"\n  Running evolutionary search ({args.scenarios} generations)...")
    summary = engine.run(agent, seed_state, generations=args.scenarios)

    print(f"\n  Evaluations:      {summary.total_evaluations}")
    print(f"  Archive Coverage: {summary.archive_coverage * 100:.1f}%")
    print(f"  Elites:           {summary.elites_count}")
    print(f"  Critical Fails:   {summary.critical_failures_count}")
    print(f"  Failure Modes:    {summary.novel_failure_modes}")

    # 3. Generate diagnostic reports
    analyzer = CausalAnalyzer(runner=runner) if runner else CausalAnalyzer()
    diagnostics = analyzer.analyze(agent, summary, seed_state)

    report = ReportGenerator.generate_markdown(diagnostics)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"\n  Report saved to: {out_path}")

    if args.json:
        from dataclasses import asdict
        json_path = out_path.with_suffix(".json")
        json_path.write_text(
            json.dumps(asdict(diagnostics), indent=2, default=str),
            encoding="utf-8",
        )
        print(f"  JSON report:  {json_path}")

    # 4. Gating
    if getattr(args, "fail_on_critical", False) and summary.critical_failures_count > 0:
        print(f"\n  [FAIL] GATING FAILED: {summary.critical_failures_count} critical vulnerabilities discovered.")
        sys.exit(1)
    elif summary.critical_failures_count > 0:
        print(f"\n  [CRITICAL] {summary.critical_failures_count} critical vulnerabilities discovered.")
    else:
        print("\n  [OK] Evaluation passed with 0 critical vulnerabilities.")


def cmd_leaderboard(args: argparse.Namespace) -> None:
    """Generate or display the ranked model security leaderboard."""
    from lifeforge.reporting.leaderboard import write_leaderboard
    from pathlib import Path

    results_dir = Path(args.results_dir) if getattr(args, "results_dir", None) else None
    out_path = Path(args.out) if getattr(args, "out", None) else None

    output = write_leaderboard(results_dir=results_dir, output_path=out_path)
    print(f"  [OK] Leaderboard written: {output}")

    if not getattr(args, "no_print", False):
        try:
            print(output.read_text(encoding="utf-8"))
        except UnicodeEncodeError:
            print(output.read_text(encoding="utf-8").encode("ascii", errors="replace").decode("ascii"))


def cmd_ui(args: argparse.Namespace) -> None:
    """Launch the interactive LIFE FORGE Web Dashboard."""
    from lifeforge.dashboard.server import start_dashboard

    start_dashboard(port=args.port, open_browser=not args.no_browser)


def _resolve_domain(name: str | None):
    """Resolve a scenario domain by name, or None for the built-in default.

    ``procurement`` is registered, so naming it explicitly returns a domain
    whose world and policies match the historical default and whose run is
    reproducible against the published leaderboard.
    """
    if not name:
        return None
    from lifeforge.sandbox.domains import get_domain

    return get_domain(name)


def cmd_domains(args: argparse.Namespace) -> None:
    """List the registered scenario domains and what each one tests."""
    from lifeforge.sandbox.domains import DOMAIN_REGISTRY, get_domain

    print("=" * 72)
    print("  LIFE FORGE -- Scenario Domains")
    print("=" * 72)

    names = [args.name] if getattr(args, "name", None) else sorted(DOMAIN_REGISTRY)
    for name in names:
        try:
            domain = get_domain(name)
        except KeyError as exc:
            print(f"\n  [FAIL] {exc}")
            sys.exit(1)

        summary = domain.summary()
        print()
        print(f"  {summary['name']} -- {summary['title']}")
        print(f"    {summary['description']}")
        print(f"    Tools    : {', '.join(summary['tools'])}")
        print(f"    Policies : {', '.join(summary['policies'])}")
        if summary["mutators"]:
            print(f"    Mutators : {', '.join(summary['mutators'])}")

    print()
    print("  Run a domain with:  lifeforge eval --domain <name> --target agent.py:my_agent")


def cmd_report(args: argparse.Namespace) -> None:
    """Render a PDF audit report from a benchmark JSON report."""
    from pathlib import Path

    fmt = str(getattr(args, "format", "pdf")).lower()
    if fmt != "pdf":
        print(f"  [FAIL] Unsupported report format '{fmt}'. Supported formats: pdf")
        sys.exit(1)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"  [FAIL] Report file not found: {input_path}")
        sys.exit(1)

    with input_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)

    output_path = Path(args.output) if args.output else input_path.with_suffix(".pdf")

    try:
        from lifeforge.reporting.pdf import PdfExportUnavailable, render_from_report_dict
    except ImportError as exc:
        print(f"  [FAIL] PDF export module unavailable: {exc}")
        sys.exit(1)

    try:
        written = render_from_report_dict(
            report,
            output_path,
            customer=getattr(args, "customer", None),
            model=getattr(args, "model", None) or report.get("agent_name"),
            hardware=getattr(args, "hardware", None),
            seed=getattr(args, "seed", 42),
            generations=getattr(args, "generations", None),
        )
    except PdfExportUnavailable as exc:
        print(f"  [FAIL] {exc}")
        sys.exit(1)

    print(f"  [OK] PDF report written: {written}")


def cmd_harden(args: argparse.Namespace) -> None:
    """Generate tool-boundary guards that remediate discovered violations."""
    from lifeforge.hardening import (
        VIOLATION_GUARDS,
        violations_from_report,
        write_hardening_module,
    )

    violations: list[str] = list(args.violation or [])
    tool_name_map: dict[str, str] = {}

    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"  [FAIL] Report file not found: {input_path}")
            sys.exit(1)
        with input_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
        detected = violations_from_report(report)
        if not detected:
            print("  [NOTE] The report records no violations; nothing to harden.")
        for violation in detected:
            if violation not in violations:
                violations.append(violation)
        # Best-effort mapping from violation to the tool named in its findings.
        for finding in report.get("findings", []) or []:
            category = str(finding.get("category", ""))
            step = finding.get("trace_snippet") or []
            for event in step:
                if isinstance(event, dict) and event.get("tool"):
                    tool_name_map.setdefault(category, str(event["tool"]))

    if not violations:
        print("  [FAIL] No violations specified. Use --violation TYPE (repeatable) or --input report.json.")
        print(f"         Known violations: {', '.join(sorted(VIOLATION_GUARDS))}")
        sys.exit(1)

    if getattr(args, "tool", None):
        for violation in violations:
            tool_name_map.setdefault(violation, args.tool)

    out_path = Path(args.out)
    written = write_hardening_module(
        violations,
        out_path,
        tool_name_map=tool_name_map or None,
    )

    known = [v for v in violations if v in VIOLATION_GUARDS]
    unknown = [v for v in violations if v not in VIOLATION_GUARDS]

    print(f"  [OK] Hardening module written: {written}")
    print(f"       Guards generated: {len(known)}")
    for violation in known:
        policy = VIOLATION_GUARDS[violation]["policy"]
        tool = tool_name_map.get(violation, "<tool_function_name>")
        print(f"         - {violation} -> {policy} on {tool}")
    if unknown:
        print(f"       [NOTE] No template for: {', '.join(unknown)} (manual review markers emitted)")


def cmd_audit(args: argparse.Namespace) -> None:
    """Produce the customer-deliverable audit bundle."""
    from lifeforge.reporting.audit import build_audit_bundle

    print("=" * 68)
    print("  LIFE FORGE -- Audit Deliverable Package")
    print("=" * 68)

    if getattr(args, "input", None):
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"  [FAIL] Report file not found: {input_path}")
            sys.exit(1)
        with input_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
        print(f"  Source report: {input_path}")
    else:
        # Run a fresh audit against the requested target.
        from lifeforge.evolution.engine import EvolutionEngine
        from lifeforge.reporting.analyzer import CausalAnalyzer
        from lifeforge.sandbox.http_agent import HTTPAgentAdapter
        from lifeforge.sandbox.loader import load_agent_from_spec
        from lifeforge.sandbox.world_state import WorldState

        if getattr(args, "target", None):
            agent = load_agent_from_spec(args.target)
        elif getattr(args, "endpoint", None):
            agent = HTTPAgentAdapter(endpoint=args.endpoint, name="RemoteHTTPAgent")
        else:
            print("  [FAIL] Provide either --input report.json or --target agent.py:my_agent")
            sys.exit(1)

        domain = _resolve_domain(getattr(args, "domain", None))
        seed_state = domain.build_world() if domain else WorldState.default_purchasing_world()
        if domain:
            print(f"  Domain:        {domain.name} ({domain.title})")

        print(f"  Target:        {agent.name}")
        print(f"  Scenarios:     {args.scenarios}")
        print(f"  Seed:          {args.seed}")
        print("  Running evolutionary search...")

        engine = EvolutionEngine(
            seed=args.seed,
            delay=args.delay,
            domain=domain,
            frontier_mutators=getattr(args, "frontier", False),
        )
        summary = engine.run(agent, seed_state, generations=args.scenarios)

        analyzer = CausalAnalyzer(runner=engine.runner)
        diagnostics = analyzer.analyze(agent, summary, seed_state)

        from dataclasses import asdict

        report = asdict(diagnostics)
        print(f"  Critical findings: {report.get('critical_failures', 0)}")

    written = build_audit_bundle(
        report,
        Path(args.out),
        customer=getattr(args, "customer", None),
        model=getattr(args, "model", None),
        target=getattr(args, "target", None),
        domain=getattr(args, "domain", None),
        hardware=getattr(args, "hardware", None),
        scenarios=getattr(args, "scenarios", 30),
        seed=getattr(args, "seed", 42),
        include_pdf=not getattr(args, "no_pdf", False),
    )

    print()
    print(f"  [OK] Audit bundle written to {Path(args.out).resolve()}")
    for key, path in sorted(written.items()):
        print(f"         {path.name:32} ({key})")
    print()
    print("  Deliverable complete. Review MANIFEST.md for the full contents.")


def cmd_gateway(args: argparse.Namespace) -> None:
    """Generate a runtime gateway policy config from a benchmark report."""
    from lifeforge.gateway import GatewayRule, write_gateway_config, rules_from_report
    from lifeforge.hardening import _VIOLATION_SEVERITY

    if getattr(args, "list_rules", False):
        print("  Supported runtime rule kinds: whitelist, amount, recipient, markers, rate, sequence")
        print("  Supported gateway policies:")
        from lifeforge.sandbox.policies import POLICY_REGISTRY

        for name in sorted(POLICY_REGISTRY):
            print(f"    - {name} ({POLICY_REGISTRY[name].violation_type})")
        return

    rules: list[GatewayRule] = []
    if getattr(args, "input", None):
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"  [FAIL] Report file not found: {input_path}")
            sys.exit(1)
        with input_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
        rules = rules_from_report(report)
        print(f"  Discovered {len(rules)} rule(s) from {input_path.name}")

    if getattr(args, "tool", None) and getattr(args, "violation", None):
        severity = _VIOLATION_SEVERITY.get(args.violation.upper(), "HIGH")
        rules.append(
            GatewayRule(
                name=f"manual_{args.violation.lower()}",
                violation_type=args.violation.upper(),
                action=args.action,
                tools=(args.tool,),
                kind=getattr(args, "kind", "whitelist"),
                config={},
                severity=severity,
            )
        )

    if not rules:
        print("  [FAIL] No rules produced. Use --input report.json or --tool X --violation TYPE.")
        sys.exit(1)

    out_path = write_gateway_config(rules, Path(args.out))
    print(f"  [OK] Gateway config written: {out_path}")
    for rule in rules:
        print(f"       {rule.action.upper():6} {rule.kind:10} {rule.violation_type} ({rule.severity})")
    print()
    print("  Load it in production with:")
    print(f"    gateway = PolicyGateway.from_config('{out_path.as_posix()}')")
    print("    guarded = gateway.wrap_executor(original_executor)")


def cmd_quickstart(args: argparse.Namespace) -> None:
    """Auto-detect an agent framework in the current project and evaluate it."""
    from lifeforge.cli.quickstart import run_quickstart

    exit_code = run_quickstart(
        Path(getattr(args, "path", ".") or "."),
        dry_run=getattr(args, "dry_run", False),
        force=getattr(args, "force", False),
        scenarios=getattr(args, "scenarios", 30),
        seed=getattr(args, "seed", 42),
        out=getattr(args, "out", "results/eval_report.md"),
    )
    if exit_code != 0:
        sys.exit(exit_code)


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

    # Test command -- evolutionary red-teaming
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
    test_parser.add_argument("--domain", type=str, default=None, help="Scenario domain (e.g. procurement, customer_support, devops, financial)")
    test_parser.add_argument("--frontier", action="store_true", help="Include 2026 frontier attacks (prompt worms, memory poisoning, context flood, multilingual)")

    # Compare command -- head-to-head model comparison
    compare_parser = subparsers.add_parser("compare", help="Compare multiple agent evaluation reports")
    compare_parser.add_argument("reports", nargs="+", help="Paths to JSON report files")
    compare_parser.add_argument("--out", type=str, default="results/HEAD_TO_HEAD_SHOWDOWN.md", help="Output comparison path")

    # MCP serve command
    mcp_parser = subparsers.add_parser("mcp-serve", help="Start LIFE FORGE as an MCP server")
    mcp_parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio", help="MCP transport")
    mcp_parser.add_argument("--adversarial", action="store_true", help="Enable adversarial mutations during session")
    mcp_parser.add_argument("--mutation-rate", type=float, default=0.3, help="Probability of mutation per tool call")

    # UI command -- interactive visual web dashboard
    ui_parser = subparsers.add_parser("ui", help="Launch interactive visual web dashboard")
    ui_parser.add_argument("--port", type=int, default=8000, help="Port to serve dashboard on (default: 8000)")
    ui_parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")

    # Leaderboard command -- ranked model security comparison
    lb_parser = subparsers.add_parser("leaderboard", help="Generate ranked model security leaderboard from all benchmark reports")
    lb_parser.add_argument("--results-dir", type=str, default=None, help="Directory containing *_report.json files (default: results/)")
    lb_parser.add_argument("--out", type=str, default=None, help="Output path for leaderboard Markdown (default: results/LEADERBOARD.md)")
    lb_parser.add_argument("--no-print", action="store_true", help="Write file only, do not print to stdout")

    # Eval command -- universal bring-your-own-agent evaluation
    eval_parser = subparsers.add_parser("eval", help="Evaluate a user-defined agent via Python spec or HTTP webhook")
    eval_parser.add_argument("--target", type=str, default=None, help="Target Python specifier (e.g. agent.py:my_agent or module:AgentClass)")
    eval_parser.add_argument("--endpoint", type=str, default=None, help="HTTP webhook URL to receive observations (e.g. http://localhost:5000/act)")
    eval_parser.add_argument("--reset-endpoint", type=str, default=None, help="Optional HTTP reset URL for episode initialization")
    eval_parser.add_argument("--timeout", type=float, default=30.0, help="HTTP request timeout in seconds (default: 30.0)")
    eval_parser.add_argument("--agent-name", type=str, default=None, help="Custom identifier for the evaluated agent")
    eval_parser.add_argument("--scenarios", type=int, default=30, help="Number of evolutionary generations (default: 30)")
    eval_parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between generations")
    eval_parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic exploration (default: 42)")
    eval_parser.add_argument("--out", type=str, default="results/eval_report.md", help="Output markdown report path")
    eval_parser.add_argument("--json", action="store_true", help="Also generate structured JSON diagnostic report")
    eval_parser.add_argument("--fail-on-critical", action="store_true", help="Exit with code 1 if critical zero-day vulnerabilities are discovered")
    eval_parser.add_argument("--domain", type=str, default=None, help="Scenario domain (procurement, customer_support, devops, financial)")
    eval_parser.add_argument("--frontier", action="store_true", help="Include 2026 frontier attacks (prompt worms, memory poisoning, context flood, multilingual)")

    # Report command -- PDF deliverable from a benchmark JSON report
    report_parser = subparsers.add_parser("report", help="Render a CISO-ready PDF audit report from a benchmark JSON report")
    report_parser.add_argument("--input", type=str, required=True, help="Path to a results/*_report.json file")
    report_parser.add_argument("--format", type=str, default="pdf", choices=["pdf"], help="Output format (default: pdf)")
    report_parser.add_argument("--output", type=str, default=None, help="Output PDF path (default: alongside the input)")
    report_parser.add_argument("--customer", type=str, default=None, help="Customer name shown on the cover page")
    report_parser.add_argument("--model", type=str, default=None, help="Model label override (default: the report's agent name)")
    report_parser.add_argument("--hardware", type=str, default=None, help="Hardware description for the reproducibility appendix")
    report_parser.add_argument("--seed", type=int, default=42, help="Seed to record in the reproducibility appendix")
    report_parser.add_argument("--generations", type=int, default=None, help="Generation count to record")

    # Harden command -- generate remediation guards
    harden_parser = subparsers.add_parser("harden", help="Generate tool-boundary hardening guards for discovered violations")
    harden_parser.add_argument("--input", type=str, default=None, help="Benchmark JSON report to read violations from")
    harden_parser.add_argument("--violation", action="append", default=None, help="Violation type to guard (repeatable)")
    harden_parser.add_argument("--tool", type=str, default=None, help="Tool function name to guard")
    harden_parser.add_argument("--out", type=str, default="remediation_decorators.py", help="Output module path")

    # Audit command -- customer-deliverable bundle
    audit_parser = subparsers.add_parser("audit", help="Produce the full customer-deliverable audit bundle")
    audit_parser.add_argument("--input", type=str, default=None, help="Existing benchmark JSON report (skips the live run)")
    audit_parser.add_argument("--target", type=str, default=None, help="Agent spec to audit (e.g. agent.py:my_agent)")
    audit_parser.add_argument("--endpoint", type=str, default=None, help="HTTP webhook agent to audit")
    audit_parser.add_argument("--customer", type=str, default=None, help="Customer name for the deliverable")
    audit_parser.add_argument("--model", type=str, default=None, help="Model label for the reproducibility appendix")
    audit_parser.add_argument("--hardware", type=str, default=None, help="Hardware description for the appendix")
    audit_parser.add_argument("--domain", type=str, default=None, help="Scenario domain to audit against")
    audit_parser.add_argument("--scenarios", type=int, default=30, help="Number of evolutionary generations (default: 30)")
    audit_parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    audit_parser.add_argument("--delay", type=float, default=0.0, help="Delay between generations in seconds")
    audit_parser.add_argument("--frontier", action="store_true", help="Include 2026 frontier attacks")
    audit_parser.add_argument("--out", type=str, default="audit_report", help="Output directory (default: audit_report)")
    audit_parser.add_argument("--no-pdf", action="store_true", help="Skip the PDF deliverables")

    # Gateway command -- runtime enforcement config
    gateway_parser = subparsers.add_parser("gateway", help="Generate a runtime PolicyGateway enforcement config")
    gateway_parser.add_argument("--input", type=str, default=None, help="Benchmark JSON report to derive rules from")
    gateway_parser.add_argument("--tool", type=str, default=None, help="Tool to guard for a manual rule")
    gateway_parser.add_argument("--violation", type=str, default=None, help="Violation type for a manual rule")
    gateway_parser.add_argument("--action", type=str, default="block", choices=["block", "warn", "allow"], help="Action for the manual rule")
    gateway_parser.add_argument("--kind", type=str, default="whitelist", choices=["whitelist", "denylist", "amount", "recipient", "markers", "rate", "sequence"], help="Rule kind for the manual rule")
    gateway_parser.add_argument("--out", type=str, default="lifeforge_policy.yaml", help="Output config path")
    gateway_parser.add_argument("--list-rules", action="store_true", help="List supported rule kinds and policies, then exit")

    # Domains command -- list scenario domains
    domains_parser = subparsers.add_parser("domains", help="List registered scenario domains and what each one tests")
    domains_parser.add_argument("name", nargs="?", default=None, help="Show details for one domain")

    # Quickstart command -- auto-detect framework and evaluate
    quick_parser = subparsers.add_parser("quickstart", help="Auto-detect an agent framework in the current directory and evaluate the agent")
    quick_parser.add_argument("--path", type=str, default=".", help="Directory to scan (default: current directory)")
    quick_parser.add_argument("--dry-run", action="store_true", help="Detect and configure without running the evaluation")
    quick_parser.add_argument("--force", action="store_true", help="Overwrite an existing generated harness file")
    quick_parser.add_argument("--scenarios", type=int, default=30, help="Number of evolutionary generations (default: 30)")
    quick_parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    quick_parser.add_argument("--out", type=str, default="results/eval_report.md", help="Output report path")

    args = parser.parse_args()
    if args.command == "run":
        cmd_run(args)
    elif args.command == "survey":
        cmd_survey(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "eval":
        cmd_eval(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "mcp-serve":
        cmd_mcp_serve(args)
    elif args.command == "ui":
        cmd_ui(args)
    elif args.command == "leaderboard":
        cmd_leaderboard(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "harden":
        cmd_harden(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "gateway":
        cmd_gateway(args)
    elif args.command == "domains":
        cmd_domains(args)
    elif args.command == "quickstart":
        cmd_quickstart(args)


if __name__ == "__main__":
    main()
