"""Tests for the replayable regression corpus."""
from __future__ import annotations

import contextlib
import io
import json
import random

import pytest

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.regression_corpus import (
    VERDICT_IMPROVED,
    VERDICT_REGRESSED,
    VERDICT_UNCHANGED,
    build_corpus,
    render_replay_markdown,
    replay_corpus,
    scenario_id,
)
from lifeforge.sandbox.agent import AgentAction, AgentInterface, RuleBasedPurchasingAgent
from lifeforge.sandbox.oracle import SandboxRunner
from lifeforge.sandbox.world_state import WorldState


def _campaign(agent: AgentInterface, generations: int = 25):
    engine = EvolutionEngine(seed=42)
    with contextlib.redirect_stdout(io.StringIO()):
        summary = engine.run(agent, generations=generations)
    return summary.elites, engine.runner


@pytest.fixture(scope="module")
def vulnerable_corpus():
    agent = RuleBasedPurchasingAgent(name="vulnerable", vulnerable_to_injection=True)
    elites, runner = _campaign(agent)
    return build_corpus(elites, agent, runner, agent_name="vulnerable")


@pytest.fixture(scope="module")
def hardened_corpus():
    agent = RuleBasedPurchasingAgent(name="hardened", vulnerable_to_injection=False, verify_price_before_po=True)
    elites, runner = _campaign(agent)
    return build_corpus(elites, agent, runner, agent_name="hardened")


def test_same_agent_replays_unchanged(vulnerable_corpus):
    agent = RuleBasedPurchasingAgent(name="vulnerable", vulnerable_to_injection=True)
    result = replay_corpus(vulnerable_corpus, agent, SandboxRunner())
    assert result.verdict == VERDICT_UNCHANGED
    assert result.total == len(vulnerable_corpus["entries"]) > 0


def test_weakening_the_agent_is_a_regression(hardened_corpus):
    weaker = RuleBasedPurchasingAgent(name="weaker", vulnerable_to_injection=True)
    result = replay_corpus(hardened_corpus, weaker, SandboxRunner())
    assert result.verdict == VERDICT_REGRESSED
    assert all(item["reasons"] for item in result.regressed)


def test_hardening_the_agent_is_an_improvement(vulnerable_corpus):
    stronger = RuleBasedPurchasingAgent(name="stronger", vulnerable_to_injection=False, verify_price_before_po=True)
    result = replay_corpus(vulnerable_corpus, stronger, SandboxRunner())
    assert result.verdict == VERDICT_IMPROVED
    assert result.fixed and not result.regressed


def test_corpus_survives_a_json_round_trip(vulnerable_corpus):
    restored = json.loads(json.dumps(vulnerable_corpus))
    agent = RuleBasedPurchasingAgent(name="vulnerable", vulnerable_to_injection=True)
    assert replay_corpus(restored, agent, SandboxRunner()).verdict == VERDICT_UNCHANGED
    for entry in restored["entries"]:
        assert scenario_id(WorldState.from_dict(entry["scenario"])) == entry["id"]


def test_corpus_keeps_passing_scenarios_and_strips_seed_marker(hardened_corpus):
    assert any(entry["baseline"]["failure_rate"] == 0.0 for entry in hardened_corpus["entries"])
    assert all("seed_baseline" not in entry["mutations"] for entry in hardened_corpus["entries"])


class CoinFlipAgent(AgentInterface):
    """Calls the prohibited wire tool on a seeded fraction of episodes."""

    def __init__(self, p: float, seed: int) -> None:
        self.name = "coin"
        self.p = p
        self.rng = random.Random(seed)
        self.decided = False

    def reset(self):
        self.decided = False

    def act(self, observation, history):
        if not self.decided:
            self.decided = True
            if self.rng.random() < self.p:
                return AgentAction("tool_call", "transfer_funds", {"destination_account": "X", "amount": 1.0, "authorization_code": "?"})
        return AgentAction("finish")


def test_tolerance_absorbs_sampling_noise_for_stochastic_agents():
    runner = SandboxRunner()

    class Elite:
        scenario = WorldState.default_purchasing_world()
        cell_index = (0, 0, 0)
        mutations_applied = ["seed_baseline"]

    corpus = build_corpus([Elite()], CoinFlipAgent(0.3, seed=1), runner, repeats=20)
    same_policy = replay_corpus(corpus, CoinFlipAgent(0.3, seed=2), runner, repeats=20, tolerance=0.25)
    assert same_policy.verdict != VERDICT_REGRESSED
    much_worse = replay_corpus(corpus, CoinFlipAgent(0.95, seed=3), runner, repeats=20, tolerance=0.25)
    assert much_worse.verdict == VERDICT_REGRESSED


def test_agent_errors_are_invalid_not_fixed(vulnerable_corpus):
    class Down(AgentInterface):
        name = "down"

        def act(self, observation, history):
            return AgentAction(action_type="error", message="connection refused")

    result = replay_corpus(vulnerable_corpus, Down(), SandboxRunner())
    assert not result.fixed
    assert len(result.invalid) == result.total
    assert "not evidence of safety" in render_replay_markdown(result)


def test_rejects_non_corpus_input():
    with pytest.raises(ValueError):
        replay_corpus({"schema": "something_else"}, RuleBasedPurchasingAgent(), SandboxRunner())
