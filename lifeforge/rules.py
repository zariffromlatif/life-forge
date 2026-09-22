from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import numpy as np

from .world import World


class Rule(ABC):
    """Base interface for cellular automaton transition rules."""

    @abstractmethod
    def apply(self, world: World) -> World:
        """Produce the next world state."""
        raise NotImplementedError


def count_neighbors(state: np.ndarray) -> np.ndarray:
    """Count the eight Moore-neighborhood neighbors for each cell."""

    return (
        np.roll(np.roll(state, -1, axis=0), -1, axis=1)
        + np.roll(np.roll(state, -1, axis=0), 0, axis=1)
        + np.roll(np.roll(state, -1, axis=0), 1, axis=1)
        + np.roll(np.roll(state, 0, axis=0), -1, axis=1)
        + np.roll(np.roll(state, 0, axis=0), 1, axis=1)
        + np.roll(np.roll(state, 1, axis=0), -1, axis=1)
        + np.roll(np.roll(state, 1, axis=0), 0, axis=1)
        + np.roll(np.roll(state, 1, axis=0), 1, axis=1)
    )


@dataclass(frozen=True)
class OuterTotalisticRule(Rule):
    """
    Binary 2D outer-totalistic cellular automaton rule.

    birth:
        Neighbor counts that cause dead cells to become alive.

    survival:
        Neighbor counts that allow live cells to remain alive.
    """

    birth: frozenset[int]
    survival: frozenset[int]

    def __post_init__(self) -> None:
        valid_counts = set(range(9))

        if not self.birth.issubset(valid_counts):
            raise ValueError("Birth counts must be between 0 and 8.")

        if not self.survival.issubset(valid_counts):
            raise ValueError("Survival counts must be between 0 and 8.")

    @property
    def notation(self) -> str:
        """Return standard B/S rule notation."""
        birth = "".join(str(n) for n in sorted(self.birth))
        survival = "".join(str(n) for n in sorted(self.survival))

        return f"B{birth}/S{survival}"
    @property
    def rule_id(self) -> int:
      """Return a compact 18-bit integer representation of the rule."""

      value = 0

      for n in self.birth:
          value |= 1 << n

      for n in self.survival:
          value |= 1 << (9 + n)

      return value

    def apply(self, world: World) -> World:
        state = world.state
        neighbors = count_neighbors(state)

        born = (
            (state == 0)
            & np.isin(neighbors, list(self.birth))
        )

        survive = (
            (state == 1)
            & np.isin(neighbors, list(self.survival))
        )

        next_state = (born | survive).astype(np.uint8)

        return World(
            width=world.width,
            height=world.height,
            state=next_state,
        )


class ConwayRule(OuterTotalisticRule):
    """Conway's Game of Life: B3/S23."""

    def __init__(self) -> None:
        super().__init__(
            birth=frozenset({3}),
            survival=frozenset({2, 3}),
        )


def random_outer_totalistic_rule(
    seed: int | None = None,
    birth_probability: float = 0.5,
    survival_probability: float = 0.5,
) -> OuterTotalisticRule:
    """Generate a reproducible random outer-totalistic rule."""

    if not 0.0 <= birth_probability <= 1.0:
        raise ValueError("birth_probability must be between 0 and 1.")

    if not 0.0 <= survival_probability <= 1.0:
        raise ValueError("survival_probability must be between 0 and 1.")

    rng = np.random.default_rng(seed)

    birth = frozenset(
        n
        for n in range(9)
        if rng.random() < birth_probability
    )

    survival = frozenset(
        n
        for n in range(9)
        if rng.random() < survival_probability
    )

    return OuterTotalisticRule(
        birth=birth,
        survival=survival,
    )