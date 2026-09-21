from __future__ import annotations

import numpy as np

from .world import World


def population(world: World) -> int:
    """Return the number of active cells."""
    return world.population


def density(world: World) -> float:
    """Return the fraction of active cells in the world."""
    total_cells = world.width * world.height

    if total_cells == 0:
        return 0.0

    return world.population / total_cells


def activity(previous: World, current: World) -> float:
    """
    Return the fraction of cells whose state changed
    between two consecutive generations.
    """
    if (
        previous.width != current.width
        or previous.height != current.height
    ):
        raise ValueError("World dimensions must match.")

    changed = np.count_nonzero(
        previous.state != current.state
    )

    total_cells = current.width * current.height

    if total_cells == 0:
        return 0.0

    return changed / total_cells