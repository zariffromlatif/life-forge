"""Tests for the audit engagement kit (regression baseline, CI gate, review answers)."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
from pathlib import Path

import yaml

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.engagement import (
    render_gate_workflow,
    render_security_review_answers,
    write_regression_kit,
)
from lifeforge.reporting.failure_surface import load_surface
from lifeforge.sandbox.agent import RuleBasedPurchasingAgent

REPO = Path(__file__).resolve().parents[1]
EXAMPLE_AGENT = (REPO / "examples" / "custom_agent_evaluation.py").as_posix() + ":MyCustomProcurementAgent"


def test_regression_kit_writes_replayable_baseline_and_valid_workflow(tmp_path: Path):
    agent = RuleBasedPurchasingAgent()
    engine = EvolutionEngine(seed=42)
    with contextlib.redirect_stdout(io.StringIO()):
        summary = engine.run(agent, generations=8)
    written = write_regression_kit(tmp_path, summary, agent, engine.runner, target="src/agent.py:agent", scenarios=8)

    baseline = load_surface(written["regression_baseline"])
    assert baseline["corpus"]["entries"]

    workflow = yaml.safe_load(written["ci_workflow"].read_text(encoding="utf-8"))
    step = workflow["jobs"]["lifeforge-gate"]["steps"][1]
    assert step["uses"].startswith("zariffromlatif/life-forge@v")
    assert step["with"]["mode"] == "surface"
    assert step["with"]["surface-agent-target"] == "src/agent.py:agent"
    assert step["with"]["surface-fail-on-regression"] == "true"


def test_workflow_values_are_quoted_against_yaml_injection():
    text = render_gate_workflow(
        target='a.py:x"\n  evil: true', endpoint=None, domain_spec=None, domain=None, scenarios=5, seed=1, frontier=False
    )
    data = yaml.safe_load(text)
    assert "evil" not in data["jobs"]["lifeforge-gate"]["steps"][1]["with"]


def test_review_answers_use_evidence_and_mark_gaps():
    report = {
        "agent_name": "RefundBot",
        "total_evaluations": 31,
        "generations": 30,
        "seed": 42,
        "evaluation_failure_rate": 12.5,
        "violation_breakdown": {"UNAUTHORIZED_TOOL_EXECUTION": 2, "CONFIRMATION_NOT_SENT": 4},
    }
    text = render_security_review_answers(report, customer="Acme", approval_gated_tools=["issueRefund"], has_regression_gate=True)
    assert "Acme tests RefundBot" in text
    assert "**31**" in text and "seed 42" in text
    assert "2 critical / 0 high / 0 medium / 4 low" in text
    assert "`issueRefund`" in text
    assert "not a certification" in text
    assert text.count("**TODO**") >= 2  # remediation status and logging cannot come from testing


def test_review_answers_without_gate_or_approvals_are_todos():
    text = render_security_review_answers({"agent_name": "X"})
    assert "No violations were recorded" in text
    assert "list the actions that require approval" in text
    assert "describe the regression testing" in text


def test_audit_cli_produces_the_full_kit(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, "-m", "lifeforge.cli", "audit", "--target", EXAMPLE_AGENT, "--scenarios", "8", "--customer", "Acme", "--out", "kit", "--no-pdf"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    kit = tmp_path / "kit"
    for name in ("regression_baseline.json", "ci/lifeforge-gate.yml", "security_review_answers.md", "MANIFEST.md"):
        assert (kit / name).exists(), name
    assert "Engagement kit" in (kit / "MANIFEST.md").read_text(encoding="utf-8")
    assert json.loads((kit / "regression_baseline.json").read_text(encoding="utf-8"))["corpus"]["entries"]


def test_audit_cli_reports_missing_agent_cleanly(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, "-m", "lifeforge.cli", "audit", "--target", "missing.py:agent", "--out", "kit"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 1
    assert "Could not load agent" in result.stdout
    assert "Traceback" not in result.stderr
