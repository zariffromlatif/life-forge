"""Each domain gives an LLM agent its own job description, never a description of the test."""
from __future__ import annotations

import argparse

import pytest

from lifeforge.sandbox.domains import get_domain
from lifeforge.sandbox.domains.compiler import CompiledDomain
from lifeforge.sandbox.llm_agent import LLMAgentConfig

#: Words from the testers' ``description`` fields that must never reach the agent.
TEST_GIVEAWAYS = ("tests ", "honeypot", "benchmark", "social engineering", "injection", "twin", "simulat")


@pytest.mark.parametrize(
    "name, job_words",
    [
        ("customer_support", ("customer-support", "refund", "escalat")),
        ("devops", ("ci/cd", "test", "merg")),
        ("financial", ("trading desk", "portfolio", "report")),
    ],
)
def test_builtin_domains_describe_their_own_job(name, job_words):
    prompt = get_domain(name).agent_system_prompt().lower()
    assert all(word in prompt for word in job_words)
    assert "purchasing" not in prompt  # the old one-size-fits-all prompt
    assert not any(word in prompt for word in TEST_GIVEAWAYS)
    assert 'say "done"' in prompt


def test_procurement_keeps_the_original_prompt_for_comparable_results():
    assert get_domain("procurement").agent_system_prompt() == LLMAgentConfig().system_prompt


def _compiled(title, agent_prompt=None):
    domain = {"name": "expense_approval", "title": title, "description": "Tests approval bypass."}
    if agent_prompt:
        domain["agent_prompt"] = agent_prompt
    return CompiledDomain(
        {
            "domain": domain,
            "declared_tools": ["lookup_expense"],
            "world": {"inbox": [{"from": "manager", "subject": "s", "body": "b"}]},
            "tools": [{"name": "lookup_expense", "description": "Look up an expense.", "args": {}}, {"builtin_email": True}],
            "policies": [],
        }
    )


def test_compiled_twins_get_a_generic_prompt_that_hides_the_twin():
    prompt = _compiled("Expense Desk (OpenAPI twin)").agent_system_prompt()
    assert "Expense Desk" in prompt and "twin" not in prompt.lower()
    assert "lookup_expense" in prompt and "approval bypass" not in prompt.lower()


def test_compiled_spec_can_set_its_own_prompt():
    assert _compiled("Expense Desk", agent_prompt="You approve expenses.").agent_system_prompt() == "You approve expenses."


def test_cli_test_command_passes_the_domain_prompt_to_the_llm_agent(monkeypatch):
    import importlib

    cli = importlib.import_module("lifeforge.cli.main")

    captured = {}

    class FakeAgent:
        def __init__(self, config):
            captured["prompt"] = config.system_prompt
            self.name = "fake"

    class Stop(Exception):
        pass

    def stop(*args, **kwargs):
        raise Stop

    monkeypatch.setattr("lifeforge.sandbox.llm_agent.LLMAgent", FakeAgent)
    monkeypatch.setattr("lifeforge.evolution.engine.EvolutionEngine", stop)
    args = argparse.Namespace(
        model="openai/fake", api_key="k", api_base=None, temperature=0.0, domain="customer_support",
        domain_spec=None, scenarios=1, seed=42, delay=0.0, frontier=False, hardened=False, agent_name=None,
    )
    with pytest.raises(Stop):
        cli.cmd_test(args)
    assert captured["prompt"] == get_domain("customer_support").agent_system_prompt()
