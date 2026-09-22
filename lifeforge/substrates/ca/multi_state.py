"""Multi-state 2D Cellular Automata engine (foundations for Langton loops and evoloops)."""
from __future__ import annotations

import hashlib
from typing import Any

import numpy as np

from lifeforge.substrates.base import Substrate


class MultiStateCA(Substrate):
    """
    2D Multi-State Cellular Automaton with von Neumann neighborhood (Center, North, East, South, West).
    Supports K discrete cell states (e.g. K=8 for Langton Loops / Sayama Evoloops).
    Uses a 5D lookup table for O(1) vectorized state updates.
    """

    name = "multi_state_ca"

    def __init__(
        self,
        num_states: int,
        transition_table: dict[tuple[int, int, int, int, int], int] | None = None,
        rotation_symmetric: bool = True,
    ) -> None:
        if num_states > 16:
            raise ValueError("Direct dense table supports up to 16 states for memory efficiency.")
        self.num_states = num_states
        self.rotation_symmetric = rotation_symmetric

        # 5D lookup table: (C, N, E, S, W)
        self._table = np.zeros(
            (num_states, num_states, num_states, num_states, num_states),
            dtype=np.uint8,
        )

        # Default rule: identity (state remains unchanged unless specified)
        for c in range(num_states):
            self._table[c, :, :, :, :] = c

        if transition_table:
            for (c, n, e, s, w), next_val in transition_table.items():
                self.set_transition(c, n, e, s, w, next_val)

    def set_transition(self, c: int, n: int, e: int, s: int, w: int, next_val: int) -> None:
        """Set a single transition rule, automatically applying 4-fold rotational symmetry if enabled."""
        if self.rotation_symmetric:
            rotations = [
                (c, n, e, s, w),
                (c, w, n, e, s),
                (c, s, w, n, e),
                (c, e, s, w, n),
            ]
            for rc, rn, re, rs, rw in rotations:
                self._table[rc, rn, re, rs, rw] = next_val
        else:
            self._table[c, n, e, s, w] = next_val

    @property
    def rule_hash(self) -> str:
        data = self._table.tobytes()
        return hashlib.sha256(data).hexdigest()[:16]

    @property
    def description(self) -> str:
        return f"{self.num_states}-State Von Neumann CA (Hash: {self.rule_hash})"

    def step(self, state: np.ndarray) -> np.ndarray:
        """Advance the multi-state 2D grid by one step using vectorized 5D table indexing."""
        if state.ndim != 2:
            raise ValueError(f"Expected 2D grid, got shape {state.shape}")

        c = state
        n = np.roll(state, 1, axis=0)
        s = np.roll(state, -1, axis=0)
        w = np.roll(state, 1, axis=1)
        e = np.roll(state, -1, axis=1)

        return self._table[c, n, e, s, w]

    @classmethod
    def brian_brain(cls) -> MultiStateCA:
        """
        Brian's Brain (3 states: 0=Ready/Off, 1=Firing/On, 2=Refractory/Dying).
        Firing cells become dying; dying become ready; ready fire if exactly 2 neighbors are firing.
        """
        ca = cls(num_states=3, rotation_symmetric=False)
        # Clear table
        ca._table.fill(0)
        # 1 -> 2
        ca._table[1, :, :, :, :] = 2
        # 2 -> 0
        ca._table[2, :, :, :, :] = 0
        # 0 -> 1 if exactly 2 firing neighbors (in Moore or von Neumann)
        for n in range(3):
            for e in range(3):
                for s in range(3):
                    for w in range(3):
                        firing_count = (n == 1) + (e == 1) + (s == 1) + (w == 1)
                        if firing_count == 2:
                            ca._table[0, n, e, s, w] = 1
                        else:
                            ca._table[0, n, e, s, w] = 0
        return ca
