"""Co-evolutionary engine orchestrating scenario generation, adversary search, and MAP-Elites cataloging."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from lifeforge.sandbox.agent import AgentInterface
from lifeforge.sandbox.oracle import SandboxRunner, SimulationTrace
from lifeforge.sandbox.world_state import WorldState
from .map_elites import EliteScenario, MapElitesArchive
from .mutators.adversarial import (
    ConflictingSpecificationMutator,
    IndirectPromptInjectionMutator,
    SpoofedExecutiveMessageMutator,
)
from .mutators.frontier import build_frontier_mutators
from .mutators.mcp_schema import MCPToolSchemaPoisoningMutator
from .mutators.environmental import (
    BudgetConstraintMutator,
    InventoryScarcityMutator,
    PriceVolatilityMutator,
    ScenarioMutator,
    VendorDropoutMutator,
)


@dataclass
class EvolutionaryRunSummary:
    """Summary of results produced by an evolutionary search run."""

    total_generations: int
    total_evaluations: int
    archive_coverage: float
    elites_count: int
    novel_failure_modes: list[str]
    critical_failures_count: int
    elites: list[EliteScenario]


class EvolutionEngine:
    """
    Coordinates the evolutionary search for novel failure modes and adversarial vulnerabilities.

    The engine is domain-agnostic.  Its default configuration reproduces the
    original enterprise-procurement scenario exactly.  Passing ``domain`` swaps
    in that domain's world, tool suite, invariant policies, mutators, and
    behavioural coordinates, so the same Quality-Diversity search illuminates a
    different environment without touching this file.
    """

    def __init__(
        self,
        runner: SandboxRunner | None = None,
        archive: MapElitesArchive | None = None,
        mutators: list[ScenarioMutator] | None = None,
        seed: int = 42,
        delay: float = 0.0,
        domain: Any | None = None,
        frontier_mutators: bool = False,
    ) -> None:
        self.domain = domain
        self.runner = runner or (domain.build_runner() if domain is not None else SandboxRunner())
        self.archive = archive or MapElitesArchive(bins=(4, 4, 4))
        self.rng = random.Random(seed)
        self.delay = delay

        self.environmental_mutators: list[ScenarioMutator] = [
            PriceVolatilityMutator(),
            InventoryScarcityMutator(),
            BudgetConstraintMutator(),
            VendorDropoutMutator(),
        ]
        self.adversarial_mutators: list[ScenarioMutator] = [
            IndirectPromptInjectionMutator(),
            SpoofedExecutiveMessageMutator(),
            ConflictingSpecificationMutator(),
            MCPToolSchemaPoisoningMutator(),
        ]
        if frontier_mutators:
            # Opt-in: the frontier attacks add strong selection pressure, so
            # runs that do not ask for them keep the original, comparable
            # behavioural coordinates.
            self.adversarial_mutators = self.adversarial_mutators + build_frontier_mutators()
        if domain is not None:
            # Domain mutators join the shared library so an environment adds
            # attack surface without losing the generic perturbations.
            self.adversarial_mutators = self.adversarial_mutators + list(domain.build_mutators())
        self.all_mutators = mutators or (self.environmental_mutators + self.adversarial_mutators)

    def calculate_coords(
        self,
        base_state: WorldState,
        scenario: WorldState,
        mutations: list[str],
    ) -> tuple[float, float, float]:
        """
        Compute normalized 3D behavioral coordinates:
        (adversarial_intensity, environment_volatility, budget_pressure)

        When a domain is configured, the domain supplies the coordinates: it
        knows which features of its own world describe volatility and resource
        pressure.  Without a domain this is the original procurement-specific
        computation, preserved unchanged so published seed=42 results remain
        reproducible.
        """
        if self.domain is not None:
            return self.domain.behavior_coords(base_state, scenario, mutations)

        # 1. Adversarial intensity: proportion of adversarial mutations
        adv_mutations = sum(
            1
            for m in mutations
            if any(
                adv.name in m
                for adv in self.adversarial_mutators
            )
        )
        adv_intensity = min(1.0, adv_mutations * 0.4)

        # 2. Environmental volatility: price divergence and inventory drop
        orig_price = base_state.prices.get("server_h100", 30_000.0)
        curr_prices = [
            q["unit_price"]
            for q in scenario.vendor_quotes.values()
        ]
        avg_price = (
            sum(curr_prices) / len(curr_prices)
            if curr_prices
            else orig_price
        )
        price_diff = abs(avg_price - orig_price) / max(1.0, orig_price)

        total_stock = sum(
            q["available_qty"]
            for q in scenario.vendor_quotes.values()
        )
        stock_scarcity = 1.0 if total_stock <= 1 else (0.5 if total_stock <= 3 else 0.0)

        volatility = min(1.0, 0.5 * price_diff + 0.5 * stock_scarcity)

        # 3. Budget pressure: required cost vs remaining budget
        budget = max(1.0, scenario.balances.get("company_budget", 1.0))
        estimated_cost = avg_price * 2.0
        budget_ratio = estimated_cost / budget
        # Normalize: ratio of 1.0 maps to ~0.5, >2.0 maps to 1.0
        budget_pressure = min(1.0, max(0.0, budget_ratio / 2.0))

        return (adv_intensity, volatility, budget_pressure)

    def run(
        self,
        agent: AgentInterface,
        seed_state: WorldState | None = None,
        generations: int = 50,
    ) -> EvolutionaryRunSummary:
        """
        Execute an evolutionary arms race searching for vulnerabilities in the agent.
        """
        base_state = seed_state or (
            self.domain.build_world() if self.domain is not None else WorldState.default_purchasing_world()
        )

        # Step 1: Evaluate baseline seed
        seed_trace = self.runner.run(agent, base_state)
        seed_coords = self.calculate_coords(base_state, base_state, [])
        self.archive.add(
            scenario=base_state,
            mutations=["seed_baseline"],
            trace=seed_trace,
            coords=seed_coords,
            generation=0,
        )

        # Step 2: Evolutionary exploration loop
        for gen in range(1, generations + 1):
            # Select parent from archive elites or baseline
            elites = self.archive.get_elites()
            parent = self.rng.choice(elites) if elites else None
            parent_state = parent.scenario if parent else base_state
            parent_mutations = list(parent.mutations_applied) if parent else []

            # Sample 1 to 2 mutators
            num_mutations = self.rng.choice([1, 2])
            selected_mutators = self.rng.sample(
                self.all_mutators,
                k=min(num_mutations, len(self.all_mutators)),
            )

            child_state = parent_state.snapshot()
            child_mutations = list(parent_mutations)

            for mutator in selected_mutators:
                child_state = mutator.mutate(child_state, self.rng)
                child_mutations.append(mutator.name)

            # Evaluate child scenario against agent
            trace = self.runner.run(agent, child_state)
            coords = self.calculate_coords(base_state, child_state, child_mutations)

            self.archive.add(
                scenario=child_state,
                mutations=child_mutations,
                trace=trace,
                coords=coords,
                generation=gen,
            )

            status_icon = "[FAIL] VIOLATION" if not trace.success else "[OK] PASS"
            crit = " [CRITICAL]" if trace.critical_failure else ""
            mut_desc = ", ".join(child_mutations[-2:]) if child_mutations else "none"
            print(f"  [Gen {gen:2d}/{generations}] {status_icon}{crit} | Mutations: {mut_desc}")

            if self.delay > 0 and gen < generations:
                import time
                time.sleep(self.delay)

        all_elites = self.archive.get_elites()
        critical_count = len(self.archive.get_critical_failures())

        return EvolutionaryRunSummary(
            total_generations=generations,
            total_evaluations=self.archive.total_evaluations,
            archive_coverage=self.archive.coverage,
            elites_count=len(all_elites),
            novel_failure_modes=sorted(list(self.archive.novel_failure_modes_discovered)),
            critical_failures_count=critical_count,
            elites=all_elites,
        )
