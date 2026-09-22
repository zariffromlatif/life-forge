"""1D Elementary Cellular Automata (ECA) substrate (Wolfram Rules 0 to 255)."""
from __future__ import annotations

import hashlib
from typing import ClassVar

import numpy as np

from lifeforge.substrates.base import Substrate


class ElementaryCA(Substrate):
    """
    1D Elementary Cellular Automaton defined by an 8-bit Wolfram rule number (0 to 255).
    Neighborhood consists of: left, center, right cells.
    """

    name = "elementary_ca"

    def __init__(self, rule_number: int) -> None:
        if not 0 <= rule_number <= 255:
            raise ValueError(f"Rule number must be in [0, 255], got {rule_number}")
        self.rule_number = rule_number
        # Lookup table for indices 0..7
        self._lookup = np.array([(rule_number >> i) & 1 for i in range(8)], dtype=np.uint8)

    @property
    def rule_hash(self) -> str:
        return hashlib.sha256(f"ECA:{self.rule_number}".encode()).hexdigest()[:16]

    @property
    def description(self) -> str:
        return f"Rule {self.rule_number}"

    def step(self, state: np.ndarray) -> np.ndarray:
        """Advance a 1D state array by one generation with periodic boundaries."""
        if state.ndim != 1:
            raise ValueError(f"Expected 1D state, got shape {state.shape}")

        left = np.roll(state, 1)
        center = state
        right = np.roll(state, -1)

        # Map (left, center, right) to 3-bit integer index (0..7)
        indices = (left << 2) | (center << 1) | right
        return self._lookup[indices]

    def spacetime_diagram(self, initial_state: np.ndarray, steps: int) -> np.ndarray:
        """Generate a 2D spacetime matrix of shape (steps + 1, width)."""
        trajectory = self.rollout(initial_state, steps)
        return np.stack(trajectory, axis=0)

    @classmethod
    def rule_30(cls) -> ElementaryCA:
        """Wolfram Rule 30: Deterministic chaos and pseudorandom number generation."""
        return cls(30)

    @classmethod
    def rule_90(cls) -> ElementaryCA:
        """Wolfram Rule 90: Additive modulo-2 rule producing the Sierpinski fractal."""
        return cls(90)

    @classmethod
    def rule_110(cls) -> ElementaryCA:
        """Wolfram Rule 110: Proven Turing-complete computational cellular automaton."""
        return cls(110)

    @classmethod
    def rule_184(cls) -> ElementaryCA:
        """Wolfram Rule 184: Soliton-like particle dynamics and traffic-flow model."""
        return cls(184)

    @staticmethod
    def seed_center(width: int) -> np.ndarray:
        """Create a 1D state with a single active cell in the exact center."""
        state = np.zeros(width, dtype=np.uint8)
        state[width // 2] = 1
        return state

    @staticmethod
    def seed_random(width: int, density: float = 0.5, seed: int | None = None) -> np.ndarray:
        """Create a 1D state with uniformly random binary activations."""
        rng = np.random.default_rng(seed)
        return (rng.random(width) < density).astype(np.uint8)
