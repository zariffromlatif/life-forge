"""An audit reports every failing simulation, not only the one elite kept per archive cell.

Found in the first real sample audit: 21 simulations, 5 critical, but they shared 3
archive cells, so the report said "1 critical" and the CI baseline replayed 3 scenarios.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.analyzer import CausalAnalyzer
from lifeforge.reporting.engagement import render_security_review_answers, write_regression_kit
from lifeforge.sandbox.agent import AgentAction, AgentInterface
from lifeforge.sandbox.domains import get_domain


class AlwaysGrantsAdmin(AgentInterface):
    name = "always-grants-admin"

    def reset(self):
        self.done = False

    def act(self, observation, history):
        if self.done:
            return AgentAction(action_type="finish")
        self.done = True
        return AgentAction(
            action_type="tool_call",
            tool_name="grant_account_access",
            arguments={"customer_id": "CUST-1001", "access_type": "admin_grant"},
        )


def _audit(generations=12):
    domain = get_domain("customer_support")
    engine = EvolutionEngine(seed=11, domain=domain)
    agent = AlwaysGrantsAdmin()
    summary = engine.run(agent, domain.build_world(), generations=generations)
    return domain, engine, agent, summary


def test_every_critical_simulation_is_counted_even_when_cells_are_shared():
    domain, engine, agent, summary = _audit()
    assert summary.critical_evaluations == summary.total_evaluations  # every episode is critical
    assert len(summary.elites) < summary.total_evaluations  # ...but they share cells

    metrics = CausalAnalyzer(runner=engine.runner).analyze(agent, summary, domain.build_world())
    assert metrics.critical_failures == summary.total_evaluations
    assert metrics.violation_breakdown["UNAUTHORIZED_TOOL_EXECUTION"] == summary.total_evaluations

    answers = render_security_review_answers(asdict(metrics))
    assert f"**{summary.total_evaluations} critical" in answers


def test_the_regression_baseline_replays_every_failing_scenario(tmp_path):
    domain, engine, agent, summary = _audit(generations=8)
    write_regression_kit(tmp_path, summary, agent, engine.runner, domain="customer_support", scenarios=8, seed=11)
    corpus = json.loads((tmp_path / "regression_baseline.json").read_text(encoding="utf-8"))["corpus"]
    distinct_failing = {json.dumps(f.scenario.to_dict(), sort_keys=True, default=str) for f in summary.failures}
    assert len(corpus["entries"]) == len(distinct_failing) > len(summary.elites)
