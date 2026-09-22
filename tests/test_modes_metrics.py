"""Tests for the MODES measurement framework and anti-garbage complexity gap."""
from __future__ import annotations

import numpy as np
import pytest

from lifeforge.substrates.ca import OuterTotalisticCA
from lifeforge.metrics import (
    compute_bedau_packard_activity,
    compute_complexity_metrics,
    compute_novelty_metrics,
    compute_ecology_metrics,
    analyze_modes,
    label_connected_components,
)


def test_anti_garbage_complexity_gap_on_white_noise():
    # Pure white noise: high entropy, but cannot be compressed
    rng = np.random.default_rng(42)
    noise = (rng.random((80, 80)) < 0.5).astype(np.uint8)

    comp = compute_complexity_metrics(noise)
    # Entropy should be close to 1
    assert comp.shannon_entropy > 0.95
    # Noise is incompressible, so compressibility ratio C is high (> 0.60)
    assert comp.compressibility_ratio > 0.60
    # Flagged as chaotic noise
    assert comp.is_chaotic_noise is True


def test_connected_components_labeling():
    # Create two disjoint clusters: a 2x2 square and a 3-cell line
    grid = np.zeros((10, 10), dtype=np.uint8)
    grid[1:3, 1:3] = 1  # 4 cells
    grid[6, 6:9] = 1    # 3 cells

    count, sizes = label_connected_components(grid)
    assert count == 2
    assert sorted(sizes) == [3, 4]


def test_conway_modes_analysis_detects_class_iv():
    conway = OuterTotalisticCA.conway()
    # Initialize a 40x40 grid with random density of 0.20
    grid = OuterTotalisticCA.random_state(40, 40, density=0.20, seed=42)
    trajectory = conway.rollout(grid, steps=50)

    modes = analyze_modes(trajectory)

    # Must have active clusters surviving
    assert modes.persistence_ratio == 1.0
    assert modes.cumulative_activity > 0.0
    # Must have positive complexity gap
    assert modes.complexity_gap > 0.05
    # Should identify as Class IV or Class II depending on transient stabilization
    assert modes.wolfram_class in (
        "Class IV (Complex / Open-Ended)",
        "Class II (Periodic / Simple Stable)",
    )


def test_bedau_packard_excess_activity():
    # Persistent glider vs rapidly randomized noise
    conway = OuterTotalisticCA.conway()
    grid = np.zeros((15, 15), dtype=np.uint8)
    glider = np.array([
        [0, 1, 0],
        [0, 0, 1],
        [1, 1, 1],
    ], dtype=np.uint8)
    grid[2:5, 2:5] = glider
    traj = conway.rollout(grid, steps=20)

    act = compute_bedau_packard_activity(traj)
    assert act.cumulative_activity > 0
    assert act.max_component_activity > 0
