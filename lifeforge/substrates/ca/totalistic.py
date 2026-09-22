"""2D Vectorized Outer-Totalistic Cellular Automata (OTCA) substrate."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

import numpy as np

from lifeforge.substrates.base import Substrate


def count_moore_neighbors(state: np.ndarray) -> np.ndarray:
    """Fast 8-neighbor Moore convolution using periodic roll."""
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


def count_von_neumann_neighbors(state: np.ndarray) -> np.ndarray:
    """Fast 4-neighbor von Neumann convolution using periodic roll."""
    return (
        np.roll(state, -1, axis=0)
        + np.roll(state, 1, axis=0)
        + np.roll(state, -1, axis=1)
        + np.roll(state, 1, axis=1)
    )


class OuterTotalisticCA(Substrate):
    """
    2D Outer-Totalistic Cellular Automaton parameterized by Birth (B) and Survival (S) neighbor counts.
    """

    name = "outer_totalistic_ca"

    def __init__(
        self,
        birth: set[int] | frozenset[int],
        survival: set[int] | frozenset[int],
        topology: Literal["moore", "von_neumann"] = "moore",
    ) -> None:
        self.birth = frozenset(birth)
        self.survival = frozenset(survival)
        self.topology = topology

        max_n = 8 if topology == "moore" else 4
        valid_counts = set(range(max_n + 1))
        if not self.birth.issubset(valid_counts):
            raise ValueError(f"Birth counts must be subset of {valid_counts}")
        if not self.survival.issubset(valid_counts):
            raise ValueError(f"Survival counts must be subset of {valid_counts}")

        # Precompute fast binary lookup masks of size max_n + 1
        self._birth_mask = np.zeros(max_n + 1, dtype=bool)
        for b in self.birth:
            self._birth_mask[b] = True

        self._survival_mask = np.zeros(max_n + 1, dtype=bool)
        for s in self.survival:
            self._survival_mask[s] = True

    @property
    def notation(self) -> str:
        b_str = "".join(str(n) for n in sorted(self.birth))
        s_str = "".join(str(n) for n in sorted(self.survival))
        return f"B{b_str}/S{s_str}"

    @property
    def description(self) -> str:
        return f"{self.notation} ({self.topology})"

    @property
    def rule_hash(self) -> str:
        raw = f"OTCA:{self.notation}:{self.topology}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def step(self, state: np.ndarray) -> np.ndarray:
        """Advance the 2D grid state by one discrete generation."""
        if state.ndim != 2:
            raise ValueError(f"Expected 2D grid state, got shape {state.shape}")

        if self.topology == "moore":
            neighbors = count_moore_neighbors(state)
        else:
            neighbors = count_von_neumann_neighbors(state)

        # Vectorized lookup
        born = (state == 0) & self._birth_mask[neighbors]
        survived = (state == 1) & self._survival_mask[neighbors]

        return (born | survived).astype(np.uint8)

    @classmethod
    def conway(cls) -> OuterTotalisticCA:
        """Conway's Game of Life: B3/S23 (The canonical Class IV computing universe)."""
        return cls(birth={3}, survival={2, 3})

    @classmethod
    def highlife(cls) -> OuterTotalisticCA:
        """HighLife: B36/S23 (Features a natural self-replicating pattern)."""
        return cls(birth={3, 6}, survival={2, 3})

    @classmethod
    def seeds(cls) -> OuterTotalisticCA:
        """Seeds: B2/S (Pure chaotic expansion without cell survival)."""
        return cls(birth={2}, survival=set())

    @classmethod
    def life_without_death(cls) -> OuterTotalisticCA:
        """Life Without Death (Inkspot): B3/S012345678."""
        return cls(birth={3}, survival=set(range(9)))

    @classmethod
    def day_and_night(cls) -> OuterTotalisticCA:
        """Day & Night: B3678/S34678 (Symmetric on/off state dynamics)."""
        return cls(birth={3, 6, 7, 8}, survival={3, 4, 6, 7, 8})

    @classmethod
    def diamoeba(cls) -> OuterTotalisticCA:
        """Diamoeba: B35678/S5678 (Forms large fluctuating amoebic forms)."""
        return cls(birth={3, 5, 6, 7, 8}, survival={5, 6, 7, 8})

    @classmethod
    def random(
        cls,
        birth_prob: float = 0.5,
        survival_prob: float = 0.5,
        topology: Literal["moore", "von_neumann"] = "moore",
        seed: int | None = None,
    ) -> OuterTotalisticCA:
        """Generate a random outer-totalistic rule."""
        rng = np.random.default_rng(seed)
        max_n = 8 if topology == "moore" else 4
        b = {n for n in range(max_n + 1) if rng.random() < birth_prob}
        s = {n for n in range(max_n + 1) if rng.random() < survival_prob}
        return cls(birth=b, survival=s, topology=topology)

    @staticmethod
    def random_state(
        height: int,
        width: int,
        density: float = 0.2,
        seed: int | None = None,
    ) -> np.ndarray:
        """Create a randomly initialized 2D binary grid."""
        rng = np.random.default_rng(seed)
        return (rng.random((height, width)) < density).astype(np.uint8)
