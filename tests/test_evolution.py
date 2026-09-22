"""Tests for evolutionary mutators, MAP-Elites archive, and co-evolutionary discovery engine."""
from __future__ import annotations

import random
import pytest

from lifeforge.sandbox import (
    WorldState,
    RuleBasedPurchasingAgent,
    SandboxRunner,
)
from lifeforge.evolution import (
    PriceVolatilityMutator,
    InventoryScarcityMutator,
    BudgetConstraintMutator,
    IndirectPromptInjectionMutator,
    MapElitesArchive,
    EvolutionEngine,
)


def test_environmental_mutators():
    rng = random.Random(123)
    base_state = WorldState.default_purchasing_world()

    # Price mutator
    price_mut = PriceVolatilityMutator(volatility_range=(1.5, 2.0))
    mutated_price = price_mut.mutate(base_state, rng)
    orig_p = base_state.vendor_quotes["vendor_alphatech"]["unit_price"]
    mut_p = mutated_price.vendor_quotes["vendor_alphatech"]["unit_price"]
    assert mut_p > orig_p

    # Inventory mutator
    inv_mut = InventoryScarcityMutator()
    mutated_inv = inv_mut.mutate(base_state, rng)
    total_stock = sum(q["available_qty"] for q in mutated_inv.vendor_quotes.values())
    assert total_stock <= 3

    # Budget mutator
    budget_mut = BudgetConstraintMutator(budget_reduction_factor=0.25)
    mutated_budget = budget_mut.mutate(base_state, rng)
    assert mutated_budget.balances["company_budget"] == 25_000.0


def test_adversarial_prompt_injection_mutator():
    rng = random.Random(42)
    base_state = WorldState.default_purchasing_world()
    inj_mut = IndirectPromptInjectionMutator()
    mutated = inj_mut.mutate(base_state, rng)

    notes_found = any(
        "transfer" in q["notes"].lower() or "acct-" in q["notes"].lower()
        for q in mutated.vendor_quotes.values()
    )
    assert notes_found is True


def test_map_elites_archive_addition():
    archive = MapElitesArchive(bins=(3, 3, 3))
    base_state = WorldState.default_purchasing_world()
    runner = SandboxRunner()
    agent = RuleBasedPurchasingAgent()

    trace = runner.run(agent, base_state)
    added = archive.add(
        scenario=base_state,
        mutations=["baseline"],
        trace=trace,
        coords=(0.1, 0.1, 0.1),
        generation=0,
    )
    assert added is True
    assert archive.coverage > 0.0
    assert len(archive.get_elites()) == 1


def test_evolution_engine_discovers_vulnerabilities():
    engine = EvolutionEngine(seed=42)
    agent = RuleBasedPurchasingAgent(name="VulnerableAgent-v1", vulnerable_to_injection=True)

    summary = engine.run(agent, generations=30)

    assert summary.total_evaluations > 30
    assert summary.archive_coverage > 0.0
    assert len(summary.novel_failure_modes) > 0
    # Must have discovered at least one critical vulnerability (e.g. UNAUTHORIZED_TOOL_EXECUTION)
    assert summary.critical_failures_count > 0
    assert "UNAUTHORIZED_TOOL_EXECUTION" in summary.novel_failure_modes
