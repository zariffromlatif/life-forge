from __future__ import annotations

from dataclasses import dataclass, field

from .rules import Rule
from .world import World


@dataclass
class Simulation:
    """Runs a cellular automaton using a World and a Rule."""

    world: World
    rule: Rule
    history: list[World] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.history.append(self.world.copy())

    @property
    def generation(self) -> int:
        """Current generation number."""
        return len(self.history) - 1

    def step(self) -> World:
        """Advance the simulation by one generation."""
        self.world = self.rule.apply(self.world)
        self.history.append(self.world.copy())

        return self.world

    def run(self, steps: int) -> World:
        """Advance the simulation by a given number of steps."""
        if steps < 0:
            raise ValueError("steps must be non-negative.")

        for _ in range(steps):
            self.step()

        return self.world