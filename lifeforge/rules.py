from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

from .world import World


class Rule(ABC):
    """Base interface for cellular automaton transition rules."""

    @abstractmethod
    def apply(self, world: World) -> World:
        """Produce the next world state."""
        raise NotImplementedError


class ConwayRule(Rule):
    """Conway's Game of Life transition rule."""

    def apply(self, world: World) -> World:
        state = world.state

        neighbors = (
            np.roll(np.roll(state, -1, axis=0), -1, axis=1)
            + np.roll(np.roll(state, -1, axis=0), 0, axis=1)
            + np.roll(np.roll(state, -1, axis=0), 1, axis=1)
            + np.roll(np.roll(state, 0, axis=0), -1, axis=1)
            + np.roll(np.roll(state, 0, axis=0), 1, axis=1)
            + np.roll(np.roll(state, 1, axis=0), -1, axis=1)
            + np.roll(np.roll(state, 1, axis=0), 0, axis=1)
            + np.roll(np.roll(state, 1, axis=0), 1, axis=1)
        )

        next_state = (
            ((state == 1) & ((neighbors == 2) | (neighbors == 3)))
            | ((state == 0) & (neighbors == 3))
        ).astype(np.uint8)

        return World(
            width=world.width,
            height=world.height,
            state=next_state,
        )