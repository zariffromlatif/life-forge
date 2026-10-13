"""A baseline whose replays failed (e.g. a provider quota) is flagged, and can be re-recorded
from its own scenarios without a new search. Found in the gpt-oss-120b sample audit: Groq's
daily quota ran out during the replays, 18 of 24 failed, and nothing said so."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.regression_corpus import build_corpus, corpus_health, health_warning, rerecord_corpus
from lifeforge.sandbox.agent import AgentAction, AgentInterface
from lifeforge.sandbox.domains import get_domain


class Refunds(AgentInterface):
    name = "refunds"

    def reset(self):
        self.done = False

    def act(self, observation, history):
        if self.done:
            return AgentAction(action_type="finish")
        self.done = True
        return AgentAction(action_type="tool_call", tool_name="issue_refund",
                           arguments={"order_id": "ORD-1001", "amount": 120.0, "reason": "double charge"})


class QuotaExhausted(AgentInterface):
    name = "quota-exhausted"

    def reset(self):
        pass

    def act(self, observation, history):
        return AgentAction(action_type="error", message="LLM API error (rate_limit): daily quota exhausted")


def _corpus(agent, repeats=2):
    domain = get_domain("customer_support")
    engine = EvolutionEngine(seed=2, domain=domain)
    summary = engine.run(Refunds(), domain.build_world(), generations=3)
    return build_corpus(summary.elites, agent, engine.runner, repeats=repeats, domain="customer_support"), engine


def test_a_baseline_with_failed_replays_is_flagged():
    corpus, _ = _corpus(QuotaExhausted())
    health = corpus_health(corpus)
    assert health["errored_runs"] == health["runs"] > 0
    assert health["scenarios_without_valid_run"] == health["scenarios"]
    warning = health_warning(corpus)
    assert warning and "--rerecord" in warning


def test_rerecording_fills_the_same_scenarios_without_a_search():
    broken, engine = _corpus(QuotaExhausted())
    fixed = rerecord_corpus(broken, Refunds(), engine.runner, repeats=2)
    assert [e["id"] for e in fixed["entries"]] == [e["id"] for e in broken["entries"]]
    assert corpus_health(fixed)["errored_runs"] == 0 and health_warning(fixed) is None
    assert {e["baseline"]["runs"] for e in fixed["entries"]} == {2}


def test_surface_rerecord_cli(tmp_path: Path):
    def run(*args):
        return subprocess.run([sys.executable, "-m", "lifeforge.cli", "surface", *args], cwd=tmp_path,
                              capture_output=True, text=True, encoding="utf-8", timeout=300)

    assert run("--record", "--hardened", "--scenarios", "6", "--out", "base.json").returncode == 0
    result = run("--rerecord", "base.json", "--hardened", "--repeats", "2", "--out", "again.json")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[Replay 1/" in result.stdout and "Baseline re-recorded" in result.stdout
    before = json.loads((tmp_path / "base.json").read_text(encoding="utf-8"))["corpus"]["entries"]
    after = json.loads((tmp_path / "again.json").read_text(encoding="utf-8"))["corpus"]
    assert [e["id"] for e in after["entries"]] == [e["id"] for e in before] and after["repeats"] == 2
