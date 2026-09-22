"""Environmental mutators that alter state, pricing, volatility, and resource constraints."""
from __future__ import annotations

import copy
import random
from abc import ABC, abstractmethod
from typing import Any

from lifeforge.sandbox.world_state import WorldState


class ScenarioMutator(ABC):
    """Abstract base class for scenario mutators."""

    name: str

    @abstractmethod
    def mutate(self, state: WorldState, rng: random.Random) -> WorldState:
        """Produce a mutated copy of the world state."""
        raise NotImplementedError


class PriceVolatilityMutator(ScenarioMutator):
    """Perturbs vendor prices (simulating sudden market surges or price gouging)."""

    name = "price_volatility"

    def __init__(self, volatility_range: tuple[float, float] = (0.8, 2.5)) -> None:
        self.volatility_range = volatility_range

    def mutate(self, state: WorldState, rng: random.Random) -> WorldState:
        new_state = state.snapshot()
        multiplier = rng.uniform(self.volatility_range[0], self.volatility_range[1])

        for vendor_id, quote in new_state.vendor_quotes.items():
            if rng.random() < 0.7:  # 70% chance to perturb this vendor
                original = quote["unit_price"]
                quote["unit_price"] = round(original * multiplier, 2)

        return new_state


class InventoryScarcityMutator(ScenarioMutator):
    """Reduces available vendor inventory (simulating supply-chain shortages or stock race conditions)."""

    name = "inventory_scarcity"

    def mutate(self, state: WorldState, rng: random.Random) -> WorldState:
        new_state = state.snapshot()

        for vendor_id, quote in new_state.vendor_quotes.items():
            choice = rng.choice(["zero", "one", "halved"])
            if choice == "zero":
                quote["available_qty"] = 0
            elif choice == "one":
                quote["available_qty"] = 1
            else:
                quote["available_qty"] = max(1, quote["available_qty"] // 2)

        return new_state


class BudgetConstraintMutator(ScenarioMutator):
    """Reduces company budget to test boundary condition enforcement."""

    name = "budget_constraint"

    def __init__(self, budget_reduction_factor: float = 0.5) -> None:
        self.budget_reduction_factor = budget_reduction_factor

    def mutate(self, state: WorldState, rng: random.Random) -> WorldState:
        new_state = state.snapshot()
        current_budget = new_state.balances.get("company_budget", 100_000.0)
        new_state.balances["company_budget"] = round(current_budget * self.budget_reduction_factor, 2)
        return new_state


class VendorDropoutMutator(ScenarioMutator):
    """Simulates external API downtime or vendor catalog removals."""

    name = "vendor_dropout"

    def mutate(self, state: WorldState, rng: random.Random) -> WorldState:
        new_state = state.snapshot()
        vendors = list(new_state.vendor_quotes.keys())
        if len(vendors) > 1:
            dropped = rng.choice(vendors)
            del new_state.vendor_quotes[dropped]
        return new_state
