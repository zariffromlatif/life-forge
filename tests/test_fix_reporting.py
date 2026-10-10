"""Regression tests for the evolution/reporting audit fixes (one test per finding)."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import shlex
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.analyzer import CausalAnalyzer
from lifeforge.reporting.failure_surface import (
    VERDICT_IMPROVED,
    VERDICT_REGRESSED,
    VERDICT_UNCHANGED,
    diff_surfaces,
    render_diff_markdown,
)
from lifeforge.sandbox.agent import RuleBasedPurchasingAgent
from lifeforge.sandbox.oracle import SandboxRunner

RESULTS = Path(__file__).resolve().parent.parent / "results"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _cell(cell: str, *, failed: bool, critical: bool = False, category: str | None = None) -> dict:
    return {
        "cell": cell,
        "coords": [0.1, 0.2, 0.3],
        "fitness": 40.0,
        "failed": failed,
        "critical": critical,
        "category": category if failed else None,
        "severity": ("CRITICAL" if critical else "HIGH") if failed else None,
        "steps": 4,
        "mutations": ["price_volatility"],
        "generation": 2,
    }


def _snapshot(cells: dict[str, dict], **extra) -> dict:
    breakdown: dict[str, int] = {}
    for record in cells.values():
        if record["failed"] and record["category"]:
            breakdown[record["category"]] = breakdown.get(record["category"], 0) + 1
    snap = {
        "schema": "lifeforge.failure_surface",
        "schema_version": 1,
        "agent_name": "agent",
        "domain": None,
        "seed": 42,
        "generations": 10,
        "coverage": 0.25,
        "critical_failures_count": sum(1 for r in cells.values() if r["critical"]),
        "failure_mode_breakdown": breakdown,
        "cells": cells,
    }
    snap.update(extra)
    return snap


class _CountingRunner(SandboxRunner):
    def __init__(self) -> None:
        super().__init__()
        self.traces = []

    def run(self, agent, initial_state, max_steps=None):
        trace = super().run(agent, initial_state, max_steps)
        self.traces.append(trace)
        return trace


def _run(generations: int = 30, *, vulnerable: bool = True, frontier: bool = False, runner=None):
    engine = EvolutionEngine(runner=runner, seed=42, frontier_mutators=frontier)
    agent = RuleBasedPurchasingAgent(name="probe", vulnerable_to_injection=vulnerable)
    with contextlib.redirect_stdout(io.StringIO()):
        summary = engine.run(agent, None, generations=generations)
    return engine, agent, summary


def _committed_reports() -> list[dict]:
    reports = []
    for path in sorted(RESULTS.glob("*_report.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if "agent_name" in data and "failure_rate" in data:
            reports.append(data)
    return reports


# ---------------------------------------------------------------------------
# 1. Surface diff misses escalations and category changes
# ---------------------------------------------------------------------------


def test_fix1_escalation_and_recategorisation_in_failing_cell_regress():
    base = _snapshot({"1,1,1": _cell("1,1,1", failed=True, category="BUDGET_EXCEEDED")})

    escalated = _snapshot(
        {"1,1,1": _cell("1,1,1", failed=True, critical=True, category="UNAUTHORIZED_FINANCIAL_DRAIN")}
    )
    diff = diff_surfaces(base, escalated)
    assert diff.verdict == VERDICT_REGRESSED
    assert diff.has_regressions
    assert [item["cell"] for item in diff.new_criticals] == ["1,1,1"]
    assert diff.changed_failures[0]["previous_category"] == "BUDGET_EXCEEDED"
    assert "New Critical Cells (CI gate)" in render_diff_markdown(diff)

    # Category change without escalation is still a regression.
    recat = _snapshot({"1,1,1": _cell("1,1,1", failed=True, category="RECURSIVE_LOOP_TRAP")})
    diff = diff_surfaces(base, recat)
    assert diff.verdict == VERDICT_REGRESSED and diff.new_criticals == []
    assert len(diff.changed_failures) == 1

    # Escalation elsewhere is not hidden by a resolved cell (was IMPROVED).
    base2 = _snapshot(
        {
            "0,0,0": _cell("0,0,0", failed=True, category="BUDGET_EXCEEDED"),
            "1,1,1": _cell("1,1,1", failed=True, category="BUDGET_EXCEEDED"),
        }
    )
    curr2 = _snapshot(
        {
            "0,0,0": _cell("0,0,0", failed=False),
            "1,1,1": _cell("1,1,1", failed=True, critical=True, category="BUDGET_EXCEEDED"),
        }
    )
    assert diff_surfaces(base2, curr2).verdict == VERDICT_REGRESSED

    # Unchanged / improved semantics are preserved.
    assert diff_surfaces(base, base).verdict == VERDICT_UNCHANGED
    fixed = _snapshot({"1,1,1": _cell("1,1,1", failed=False)})
    assert diff_surfaces(base, fixed).verdict == VERDICT_IMPROVED

    # De-escalation in a still-failing cell (same category) is a resolved critical.
    crit_base = _snapshot({"2,2,2": _cell("2,2,2", failed=True, critical=True, category="X")})
    crit_now = _snapshot({"2,2,2": _cell("2,2,2", failed=True, critical=False, category="X")})
    diff = diff_surfaces(crit_base, crit_now)
    assert diff.verdict == VERDICT_UNCHANGED
    assert len(diff.resolved_criticals) == 1


# ---------------------------------------------------------------------------
# 2. Markdown and PDF risk scores disagree / saturate on MEDIUM-only reports
# ---------------------------------------------------------------------------


def test_fix2_single_shared_risk_score_for_markdown_and_pdf():
    from lifeforge.reporting.audit import _risk_score
    from lifeforge.reporting.pdf import _metrics_from_dict, compute_risk_score, risk_band

    reports = _committed_reports()
    assert reports, "expected committed benchmark reports under results/"
    for report in reports:
        pdf_score = compute_risk_score(_metrics_from_dict(report))
        assert _risk_score(report) == (pdf_score, risk_band(pdf_score)), report["agent_name"]

    # Many cells of one MEDIUM category must not saturate the scale.
    medium_only = {
        "agent_name": "m",
        "failure_rate": 100.0,
        "critical_failures": 0,
        "failure_mode_breakdown": {"GOAL_INVENTORY_DEFICIT": 17},
        "findings": [{"severity": "MEDIUM", "category": "GOAL_INVENTORY_DEFICIT"}],
    }
    score, band = _risk_score(medium_only)
    assert band in ("LOW", "MODERATE") and score < 50

    # A CRITICAL finding is never reported below HIGH.
    critical = dict(medium_only, findings=[{"severity": "CRITICAL", "category": "UNAUTHORIZED_TOOL_EXECUTION"}])
    assert _risk_score(critical)[1] in ("HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# 3. Compliance pack: secondary violations dropped, missing register => PASS
# ---------------------------------------------------------------------------


def test_fix3_compliance_uses_full_violation_register_and_refuses_false_pass():
    from lifeforge.reporting.compliance import build_compliance_pack

    def status(pack, control_id):
        return next(a.status for a in pack.assessments if a.control_id == control_id)

    # The analyzer now records every violation type, not only the primary one.
    _, agent, summary = _run(60, frontier=True)
    metrics = CausalAnalyzer().analyze(agent, summary)
    expected: dict[str, int] = {}
    for elite in summary.elites:
        for vtype in {v.violation_type for v in elite.trace.violations}:
            expected[vtype] = expected.get(vtype, 0) + 1
    assert metrics.violation_breakdown == expected
    assert set(metrics.failure_mode_breakdown) <= set(metrics.violation_breakdown)
    json.dumps(asdict(metrics))  # still JSON-serialisable

    # A secondary violation (never the primary category) now reaches the register.
    report = {
        "agent_name": "x",
        "failure_rate": 50.0,
        "critical_failures": 1,
        "failure_mode_breakdown": {"UNAUTHORIZED_TOOL_EXECUTION": 9},
        "violation_breakdown": {"UNAUTHORIZED_TOOL_EXECUTION": 9, "CONFIRMATION_NOT_SENT": 11},
    }
    pack = build_compliance_pack(report)
    assert status(pack, "transparency") == "GAP"
    # Older reports without the full register still fall back to the primary one.
    legacy = {k: v for k, v in report.items() if k != "violation_breakdown"}
    assert status(build_compliance_pack(legacy), "human_oversight") == "GAP"

    # No register at all, but headline metrics report failures: never PASS.
    pack = build_compliance_pack({"agent_name": "x", "failure_rate": 90.0, "critical_failures": 5})
    assert all(a.status != "PASS" for a in pack.assessments)
    assert status(pack, "risk_management") == "UNVERIFIED"

    # Empty register that contradicts the headline metrics: never PASS.
    pack = build_compliance_pack({"agent_name": "x", "failure_mode_breakdown": {}, "critical_failures": 2})
    assert all(a.status != "PASS" for a in pack.assessments)

    # A genuinely clean report still passes.
    clean = {"agent_name": "c", "failure_mode_breakdown": {}, "critical_failures": 0, "failure_rate": 0.0}
    assert status(build_compliance_pack(clean), "robustness") == "PASS"


# ---------------------------------------------------------------------------
# 4. Reproduction script / leaderboard instructions use invalid CLI flags
# ---------------------------------------------------------------------------


_ORIGINAL_PARSE_ARGS = argparse.ArgumentParser.parse_args


class _Parsed(Exception):
    def __init__(self, namespace):
        super().__init__("parsed")
        self.namespace = namespace


def _parse_cli(argv: list[str], monkeypatch) -> argparse.Namespace:
    """Parse argv with the real CLI parser, without dispatching the command."""
    import importlib

    cli_main = importlib.import_module("lifeforge.cli.main")
    original = _ORIGINAL_PARSE_ARGS

    def capture(self, args=None, namespace=None):
        raise _Parsed(original(self, args, namespace))

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", capture)
    monkeypatch.setattr(sys, "argv", ["lifeforge", *argv])
    with pytest.raises(_Parsed) as caught:
        cli_main.main()
    return caught.value.namespace


def _shell_commands(script: str) -> list[list[str]]:
    joined = script.replace("\\\n", " ")
    commands = []
    for line in joined.splitlines():
        line = line.strip()
        if not line.startswith("lifeforge "):
            continue
        line = line.split("||")[0].strip()
        commands.append(shlex.split(line, comments=True)[1:])
    return commands


def test_fix4_reproduction_commands_parse_with_the_real_cli(monkeypatch):
    from lifeforge.reporting.audit import _reproduction_commands

    cases = [
        dict(model="ollama/qwen2.5:14b", target=None, domain="devops"),
        dict(model=None, target="agent.py:my_agent", domain=None),
        dict(model=None, target=None, domain=None),
    ]
    for case in cases:
        script = _reproduction_commands({}, scenarios=30, seed=42, **case)
        commands = _shell_commands(script)
        produced_json = None
        for argv in commands:
            ns = _parse_cli(argv, monkeypatch)  # SystemExit(2) on an invalid flag
            if argv[0] in ("test", "eval"):
                produced_json = str(Path(ns.out).with_suffix(".json")).replace("\\", "/")
                if case["domain"]:
                    assert ns.domain == case["domain"]
            if argv[0] == "report":
                # The PDF step must read the JSON the benchmark step wrote.
                assert produced_json is not None and ns.input == produced_json
        if case["model"]:
            assert commands[0][:3] == ["test", "--model", case["model"]]
            assert "|| test $? -eq 1" in script  # criticals (exit 1) must not abort set -e

    from lifeforge.reporting.leaderboard import generate_leaderboard

    board = generate_leaderboard(RESULTS, generated_utc="2026-01-01 00:00 UTC")
    how_to = board.split("## How to Add Your Model", 1)[1]
    block = how_to.split("```bash", 1)[1].split("```", 1)[0]
    for argv in _shell_commands(block):
        if argv[0] in ("test", "eval", "leaderboard"):
            _parse_cli(argv, monkeypatch)


# ---------------------------------------------------------------------------
# 5. PDF severity bands diverge from the shared severity table
# ---------------------------------------------------------------------------


def test_fix5_pdf_severity_bands_match_shared_table():
    from lifeforge.hardening import _VIOLATION_SEVERITY
    from lifeforge.reporting.pdf import _severity_band_for_category

    for category, severity in _VIOLATION_SEVERITY.items():
        assert _severity_band_for_category(category) == severity, category
    assert _severity_band_for_category("PRIVILEGE_ESCALATION") == "CRITICAL"
    assert _severity_band_for_category("CONTEXT_FLOOD_ATTACK") == "HIGH"


# ---------------------------------------------------------------------------
# 6. Failure rate measured over selection-biased elites only
# ---------------------------------------------------------------------------


def test_fix6_per_evaluation_counters_and_leaderboard_grading(tmp_path):
    from lifeforge.reporting.leaderboard import _compute_grade, generate_leaderboard
    from lifeforge.reporting.report import ReportGenerator

    runner = _CountingRunner()
    _, agent, summary = _run(30, vulnerable=False, runner=runner)
    traces = runner.traces
    assert summary.total_evaluations == len(traces)
    assert summary.failed_evaluations == sum(not t.success for t in traces)
    assert summary.critical_evaluations == sum(bool(t.critical_failure) for t in traces)
    assert summary.seed == 42

    metrics = CausalAnalyzer().analyze(agent, summary)
    expected = round(summary.failed_evaluations / summary.total_evaluations * 100, 1)
    assert metrics.evaluation_failure_rate == expected
    assert metrics.failed_evaluations == summary.failed_evaluations

    # Summaries built without the counters (older callers) fall back cleanly.
    from lifeforge.evolution.engine import EvolutionaryRunSummary

    legacy = EvolutionaryRunSummary(
        total_generations=summary.total_generations,
        total_evaluations=summary.total_evaluations,
        archive_coverage=summary.archive_coverage,
        elites_count=summary.elites_count,
        novel_failure_modes=summary.novel_failure_modes,
        critical_failures_count=summary.critical_failures_count,
        elites=summary.elites,
    )
    legacy_metrics = CausalAnalyzer().analyze(agent, legacy)
    assert legacy_metrics.evaluation_failure_rate is None
    assert "not recorded" in ReportGenerator.generate_markdown(legacy_metrics)
    markdown = ReportGenerator.generate_markdown(metrics)
    assert "Evaluation Failure Rate" in markdown and "Elite-Cell Failure Rate" in markdown

    # Leaderboard grades on the evaluation rate when present, else falls back.
    base = {"agent_name": "LLMAgent(ollama/a:7b)", "critical_failures": 0, "failure_rate": 90.0}
    new = dict(base, agent_name="LLMAgent(ollama/b:7b)", evaluation_failure_rate=15.0)
    (tmp_path / "old_report.json").write_text(json.dumps(base), encoding="utf-8")
    (tmp_path / "new_report.json").write_text(json.dumps(new), encoding="utf-8")
    board = generate_leaderboard(tmp_path, generated_utc="2026-01-01 00:00 UTC")
    grade_new = _compute_grade(0, 15.0)[0]
    grade_old = _compute_grade(0, 90.0)[0]
    assert f"`b:7b` -- Grade {grade_new} " in board
    assert f"`a:7b` -- Grade {grade_old} " in board
    ranked = [line for line in board.splitlines() if line.startswith("| 1 |")]
    assert "`b:7b`" in ranked[0]


# ---------------------------------------------------------------------------
# 7. Diff rendering crashes on snapshots missing keys
# ---------------------------------------------------------------------------


def test_fix7_render_diff_tolerates_missing_keys_and_warns_on_mismatch():
    diff = diff_surfaces({"cells": {}}, {"cells": {}})
    markdown = render_diff_markdown(diff)
    assert "0.0000" in markdown

    a = _snapshot({}, seed=42, domain="devops")
    b = _snapshot({}, seed=7, domain="devops")
    diff = diff_surfaces(a, b)
    assert any("seed" in w for w in diff.warnings)
    assert "**Warning**" in render_diff_markdown(diff)


# ---------------------------------------------------------------------------
# 8. Deliverables claiming determinism embed wall-clock time
# ---------------------------------------------------------------------------


def test_fix8_timestamps_can_be_pinned_and_header_is_derived(tmp_path, monkeypatch):
    from lifeforge.reporting.audit import build_audit_bundle
    from lifeforge.reporting.compliance import write_compliance_pack
    from lifeforge.reporting.leaderboard import generate_leaderboard
    from lifeforge.reporting.report import resolve_generated_utc

    report = json.loads((RESULTS / "local_qwen_report.json").read_text(encoding="utf-8"))

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert resolve_generated_utc() == "2023-11-14 22:13:20 UTC"
    first = write_compliance_pack(report, tmp_path / "a" / "pack.md")
    second = write_compliance_pack(report, tmp_path / "b" / "pack.md")
    for x, y in zip(first, second):
        assert x.read_bytes() == y.read_bytes()
    monkeypatch.delenv("SOURCE_DATE_EPOCH")

    pinned = "2026-01-01 00:00:00 UTC"
    b1 = build_audit_bundle(report, tmp_path / "bundle1", include_pdf=False, generated_utc=pinned)
    b2 = build_audit_bundle(report, tmp_path / "bundle2", include_pdf=False, generated_utc=pinned)
    for key in ("executive_summary", "technical_report", "manifest", "reproduction_commands"):
        assert b1[key].read_bytes() == b2[key].read_bytes(), key
    assert pinned in b1["executive_summary"].read_text(encoding="utf-8")

    board_a = generate_leaderboard(RESULTS, generated_utc="2026-01-01 00:00 UTC")
    board_b = generate_leaderboard(RESULTS, generated_utc="2026-01-01 00:00 UTC")
    assert board_a == board_b
    # Header comes from the reports, not a hard-coded "30 generations, seed=42".
    assert "30 generations, `seed=42`" not in board_a
    evals = sorted({r.get("total_evaluations") for r in _committed_reports()})
    assert f"{evals[0]}-{evals[-1]} evaluations per model" in board_a or f"{evals[0]} evaluations" in board_a


# ---------------------------------------------------------------------------
# 9. Mode-shift table printed the delta twice
# ---------------------------------------------------------------------------


def test_fix9_mode_shift_table_shows_baseline_and_current_counts():
    base = _snapshot({"0,0,0": _cell("0,0,0", failed=True, category="RECURSIVE_LOOP_TRAP")})
    curr = _snapshot(
        {
            "0,0,0": _cell("0,0,0", failed=True, category="RECURSIVE_LOOP_TRAP"),
            "1,0,0": _cell("1,0,0", failed=True, category="RECURSIVE_LOOP_TRAP"),
        }
    )
    diff = diff_surfaces(base, curr)
    assert diff.mode_counts == {"RECURSIVE_LOOP_TRAP": [1, 2]}
    assert "| `RECURSIVE_LOOP_TRAP` | 1 -> 2 | +1 |" in render_diff_markdown(diff)


# ---------------------------------------------------------------------------
# 10. Gap register vanished when no recorded violation maps to a control
# ---------------------------------------------------------------------------


def test_fix10_gap_register_rendered_when_no_control_is_gapped():
    from lifeforge.reporting.compliance import build_compliance_pack, render_compliance_markdown

    report = {
        "agent_name": "x",
        "failure_mode_breakdown": {"BUDGET_EXCEEDED": 7, "GOAL_INVENTORY_DEFICIT": 3},
        "critical_failures": 0,
    }
    pack = build_compliance_pack(report)
    assert not any(a.status == "GAP" for a in pack.assessments)
    markdown = render_compliance_markdown(pack)
    assert "## Gap Register" in markdown
    assert "`BUDGET_EXCEEDED` | 7" in markdown
    assert "`GOAL_INVENTORY_DEFICIT` | 3" in markdown


# ---------------------------------------------------------------------------
# 11. 'seed_baseline' leaked into every descendant's lineage
# ---------------------------------------------------------------------------


def test_fix11_seed_baseline_not_inherited_by_children():
    _, agent, summary = _run(40)
    baseline = [e for e in summary.elites if e.generation == 0]
    children = [e for e in summary.elites if e.generation > 0]
    assert children
    assert all("seed_baseline" not in e.mutations_applied for e in children)
    assert all(e.mutations_applied for e in children)
    for elite in baseline:
        assert elite.mutations_applied == ["seed_baseline"]

    metrics = CausalAnalyzer().analyze(agent, summary)
    for finding in metrics.findings:
        assert "seed_baseline" not in finding.minimal_causal_trigger
