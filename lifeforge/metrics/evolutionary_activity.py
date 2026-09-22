"""Bedau-Packard evolutionary activity metrics and neutral shadow model controls."""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np


@dataclass(frozen=True)
class ActivityMetrics:
    """Bedau-Packard evolutionary activity statistics."""

    cumulative_activity: float
    mean_component_activity: float
    max_component_activity: int
    shadow_cumulative_activity: float
    excess_evolutionary_activity: float  # Real activity minus neutral shadow activity
    has_non_neutral_dynamics: bool


def compute_bedau_packard_activity(
    trajectory: list[np.ndarray],
    shadow_trajectory: list[np.ndarray] | None = None,
) -> ActivityMetrics:
    """
    Compute Bedau-Packard evolutionary activity waves for a trajectory.
    Tracks persistent active components (cells/loci that maintain non-inert continuity).

    If shadow_trajectory is provided, computes excess evolutionary activity
    to verify that persistence is not merely neutral drift or static inertia.
    """
    if not trajectory:
        raise ValueError("Trajectory cannot be empty.")

    steps = len(trajectory)
    shape = trajectory[0].shape

    # Component age tracker
    age_matrix = np.zeros(shape, dtype=np.int32)
    cumulative_activity = 0.0
    all_final_activities: list[int] = []

    for t in range(steps):
        state = trajectory[t]
        # Active cells increment age; inactive cells reset
        active_mask = (state > 0)
        age_matrix[active_mask] += 1
        age_matrix[~active_mask] = 0

        # Accumulate activity of currently surviving components
        current_step_activity = float(np.sum(age_matrix))
        cumulative_activity += current_step_activity

    active_components = age_matrix[age_matrix > 0]
    mean_activity = float(np.mean(active_components)) if len(active_components) > 0 else 0.0
    max_activity = int(np.max(age_matrix)) if len(age_matrix) > 0 else 0

    # Shadow run comparison
    shadow_cumulative = 0.0
    if shadow_trajectory:
        shadow_age = np.zeros(shape, dtype=np.int32)
        for t in range(len(shadow_trajectory)):
            s_state = shadow_trajectory[t]
            active_mask = (s_state > 0)
            shadow_age[active_mask] += 1
            shadow_age[~active_mask] = 0
            shadow_cumulative += float(np.sum(shadow_age))
    else:
        # Default theoretical neutral baseline for random walk of identical mean density
        densities = [float(np.mean(s > 0)) for s in trajectory]
        avg_density = float(np.mean(densities))
        # For uncorrelated random Bernoulli process with density p, survival prob is p^k
        # Cumulative expectation:
        total_cells = np.prod(shape)
        shadow_cumulative = float(total_cells * avg_density * (1.0 / max(0.01, 1.0 - avg_density)) * steps * 0.1)

    excess_activity = cumulative_activity - shadow_cumulative
    has_non_neutral = excess_activity > 0 and max_activity > (steps * 0.1)

    return ActivityMetrics(
        cumulative_activity=cumulative_activity,
        mean_component_activity=mean_activity,
        max_component_activity=max_activity,
        shadow_cumulative_activity=shadow_cumulative,
        excess_evolutionary_activity=excess_activity,
        has_non_neutral_dynamics=has_non_neutral,
    )
