"""World representations and state management."""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np


@dataclass
class World:
    """Represents the state of a 2D cellular-automaton world."""

    width: int
    height: int
    state: np.ndarray

    def __post_init__(self) -> None:
        if self.state.shape != (self.height, self.width):
            raise ValueError(
                f"Expected state shape {(self.height, self.width)}, "
                f"got {self.state.shape}"
            )

    @classmethod
    def empty(cls, width: int, height: int) -> "World":
        """Create an empty world."""
        if width <= 0 or height <= 0:
            raise ValueError("World dimensions must be positive.")

        state = np.zeros((height, width), dtype=np.uint8)
        return cls(width=width, height=height, state=state)

    @classmethod
    def random(
        cls,
        width: int,
        height: int,
        density: float = 0.2,
        seed: int | None = None,
    ) -> "World":
        """Create a randomly initialized world."""
        if width <= 0 or height <= 0:
            raise ValueError("World dimensions must be positive.")

        if not 0.0 <= density <= 1.0:
            raise ValueError("Density must be between 0 and 1.")

        rng = np.random.default_rng(seed)

        state = (
            rng.random((height, width)) < density
        ).astype(np.uint8)

        return cls(width=width, height=height, state=state)

    @property
    def population(self) -> int:
        """Number of active cells."""
        return int(self.state.sum())

    def copy(self) -> "World":
        """Return an independent copy of the world."""
        return World(
            width=self.width,
            height=self.height,
            state=self.state.copy(),
        )