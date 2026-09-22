"""Novelty metrics: tracking state innovation rate, vocabulary growth, and behavioral drift."""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np


@dataclass(frozen=True)
class NoveltyMetrics:
    """Quantitative metrics tracking the discovery of new phenotypic/state configurations."""

    unique_patterns_count: int
    pattern_growth_rate: float  # Slope of new pattern discovery in the late phase
    trajectory_divergence: float  # Macro-feature divergence across time windows
    has_cumulative_novelty: bool


def extract_local_patterns(state: np.ndarray) -> set[int]:
    """Extract integer hashes of all local 3x3 (2D) or 3-cell (1D) neighborhoods."""
    patterns = set()

    if state.ndim == 1:
        left = np.roll(state, 1)
        center = state
        right = np.roll(state, -1)
        indices = (left << 2) | (center << 1) | right
        patterns.update(np.unique(indices).tolist())

    elif state.ndim == 2:
        # Extract 3x3 patches via 9-bit binary representation (for binary CA)
        h, w = state.shape
        # Bit shifts for 9 neighbors
        p = np.zeros((h, w), dtype=np.int32)
        idx = 0
        for dr in (-1, 0, 1):
            for dc in (-1, 0, 1):
                shifted = np.roll(np.roll(state, dr, axis=0), dc, axis=1)
                p |= (shifted.astype(np.int32) & 1) << idx
                idx += 1
        patterns.update(np.unique(p).tolist())

    return patterns


def compute_novelty_metrics(
    trajectory: list[np.ndarray],
    burn_in_fraction: float = 0.3,
) -> NoveltyMetrics:
    """
    Measure how open-ended or novel the system's trajectory is.
    Calculates whether the system exhausts its pattern repertoire early (stagnant/periodic)
    or continuously discovers new spatial configurations over time.
    """
    if len(trajectory) < 2:
        return NoveltyMetrics(
            unique_patterns_count=0,
            pattern_growth_rate=0.0,
            trajectory_divergence=0.0,
            has_cumulative_novelty=False,
        )

    burn_in = max(1, int(len(trajectory) * burn_in_fraction))
    all_patterns: set[int] = set()
    vocabulary_over_time: list[int] = []

    for state in trajectory:
        current_patterns = extract_local_patterns(state)
        all_patterns.update(current_patterns)
        vocabulary_over_time.append(len(all_patterns))

    # Pattern growth in second half of simulation
    late_phase_growth = vocabulary_over_time[-1] - vocabulary_over_time[burn_in]
    late_steps = len(trajectory) - burn_in
    growth_rate = float(late_phase_growth / max(1, late_steps))

    # Compute behavioral trajectory divergence across two halves
    halfway = len(trajectory) // 2
    early_densities = [float(np.mean(s > 0)) for s in trajectory[:halfway]]
    late_densities = [float(np.mean(s > 0)) for s in trajectory[halfway:]]
    divergence = float(abs(np.mean(late_densities) - np.mean(early_densities)))

    has_novelty = growth_rate > 0.05 or (divergence > 0.05 and late_phase_growth > 0)

    return NoveltyMetrics(
        unique_patterns_count=len(all_patterns),
        pattern_growth_rate=growth_rate,
        trajectory_divergence=divergence,
        has_cumulative_novelty=has_novelty,
    )
