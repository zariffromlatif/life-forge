"""Abstract base interfaces for universe substrates in LIFE FORGE."""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import numpy as np


class Substrate(ABC):
    """Abstract interface defining a dynamical universe substrate."""

    name: str

    @abstractmethod
    def step(self, state: np.ndarray) -> np.ndarray:
        """Advance the universe state by one discrete time step."""
        raise NotImplementedError

    def rollout(self, initial_state: np.ndarray, steps: int) -> list[np.ndarray]:
        """Advance the universe for a sequence of steps, returning the trajectory of states."""
        if steps < 0:
            raise ValueError("steps must be non-negative.")

        trajectory: list[np.ndarray] = [initial_state.copy()]
        current = initial_state.copy()

        for _ in range(steps):
            current = self.step(current)
            trajectory.append(current.copy())

        return trajectory

    @property
    @abstractmethod
    def rule_hash(self) -> str:
        """Deterministic SHA-256 fingerprint uniquely identifying the rule parameters."""
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description or standard mathematical notation of the rule."""
        raise NotImplementedError
