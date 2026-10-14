"""An audit saves every episode, and `lifeforge audit --rebuild` regenerates its reports offline.

Why: every report fix used to need the agent run again (three 1-hour local GPU runs and a
3-hour hosted run in one week). The bundle now keeps simulations.json.gz, and a rebuild
re-judges those episodes with the current oracle without calling the agent.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting import simulations
from lifeforge.sandbox.agent import AgentAction, AgentInterface
from lifeforge.sandbox.domains import get_domain

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_AGENT = str(ROOT / "examples" / "custom_agent_evaluation.py") + ":MyCustomProcurementAgent"
COUNTS = ("total_evaluations", "failed_evaluations", "critical_evaluations", "invalid_evaluations",
          "evaluation_failure_rate", "violation_breakdown", "failure_mode_breakdown", "generalization_rating")


def _audit(*args, cwd):
    return subprocess.run([sys.executable, "-m", "lifeforge.cli", "audit", *args], cwd=cwd,
                          capture_output=True, text=True, encoding="utf-8", timeout=300, check=False)


def test_a_rebuilt_bundle_matches_the_original(tmp_path: Path):
    live = _audit("--target", EXAMPLE_AGENT, "--domain", "procurement", "--scenarios", "6", "--customer", "Acme",
                  "--out", "live", "--no-pdf", cwd=tmp_path)
    assert live.returncode == 0, live.stdout + live.stderr
    assert (tmp_path / "live" / "simulations.json.gz").exists()

    rebuilt = _audit("--rebuild", "live", "--out", "rebuilt", "--no-pdf", cwd=tmp_path)
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    original = json.loads((tmp_path / "live" / "raw_data.json").read_text(encoding="utf-8"))
    again = json.loads((tmp_path / "rebuilt" / "raw_data.json").read_text(encoding="utf-8"))
    assert {k: original["report"][k] for k in COUNTS} == {k: again["report"][k] for k in COUNTS}
    assert [f["category"] for f in original["report"]["findings"]] == [f["category"] for f in again["report"]["findings"]]
    # Labels carry over, the baseline and gate are the original run's, and the MANIFEST says so.
    assert "**Prepared for**: Acme" in (tmp_path / "rebuilt" / "executive_summary.md").read_text(encoding="utf-8")
    for name in ("regression_baseline.json", "ci/lifeforge-gate.yml", "simulations.json.gz", "security_review_answers.md"):
        assert (tmp_path / "rebuilt" / name).exists(), name
    assert "Rebuilt offline" in (tmp_path / "rebuilt" / "MANIFEST.md").read_text(encoding="utf-8")


def test_rebuild_needs_saved_simulations(tmp_path: Path):
    (tmp_path / "old").mkdir()
    result = _audit("--rebuild", "old", "--out", "x", cwd=tmp_path)
    assert result.returncode == 1 and "No simulations.json.gz" in result.stdout


class Refunds(AgentInterface):
    name = "refunds"

    def reset(self):
        self.done = False

    def act(self, observation, history):
        if self.done:
            return AgentAction(action_type="finish")
        self.done = True
        return AgentAction(action_type="tool_call", tool_name="issue_refund",
                           arguments={"order_id": "ORD-1001", "amount": 120.0, "reason": "dup"})


def test_rejudging_uses_the_current_oracle_not_stored_verdicts(tmp_path: Path, monkeypatch):
    domain = get_domain("customer_support")
    engine = EvolutionEngine(seed=4, domain=domain)
    summary = engine.run(Refunds(), domain.build_world(), generations=4)
    path = simulations.save_simulations(tmp_path / "s.json.gz", summary, agent_name="refunds", domain=domain)
    record = simulations.load_simulations(path)
    assert record["complete"] and len(record["evaluations"]) == summary.total_evaluations

    rebuilt, _, _ = simulations.rejudge(record)
    assert (rebuilt.failed_evaluations, rebuilt.critical_evaluations) == (summary.failed_evaluations, summary.critical_evaluations)

    # A stricter oracle (here: every episode gets a CRITICAL finding) changes the rebuilt verdicts.
    from lifeforge.sandbox.oracle import PolicyViolation, SandboxRunner

    original_judge = SandboxRunner.judge

    def stricter(self, initial, final, events, agent_error=None):
        trace = original_judge(self, initial, final, events, agent_error)
        trace.violations.append(PolicyViolation(violation_type="TEST_RULE", severity="CRITICAL", description="x", step=0))
        trace.success, trace.critical_failure = False, True
        return trace

    monkeypatch.setattr(SandboxRunner, "judge", stricter)
    stricter_run, _, _ = simulations.rejudge(record)
    assert stricter_run.critical_evaluations == stricter_run.total_evaluations == summary.total_evaluations
