"""Unit tests for 1D Elementary, 2D Outer-Totalistic, and Multi-State CA substrates."""
from __future__ import annotations

import numpy as np
import pytest

from lifeforge.substrates.ca import (
    ElementaryCA,
    OuterTotalisticCA,
    MultiStateCA,
)


def test_elementary_rule_90_sierpinski():
    # Rule 90 is XOR of left and right neighbors: left ^ right
    eca = ElementaryCA.rule_90()
    assert eca.rule_number == 90

    state = np.array([0, 0, 1, 0, 0], dtype=np.uint8)
    next_s = eca.step(state)
    # 0 1 0 1 0
    np.testing.assert_array_equal(next_s, [0, 1, 0, 1, 0])


def test_elementary_rule_110():
    eca = ElementaryCA.rule_110()
    # 110 = 01101110 in binary
    # Input 000 -> 0; 001 -> 1; 010 -> 1; 011 -> 1; 100 -> 0; 101 -> 1; 110 -> 1; 111 -> 0
    state = np.array([0, 1, 1, 0], dtype=np.uint8)
    next_s = eca.step(state)
    assert next_s.shape == (4,)


def test_conway_blinker_oscillation():
    # Standard period-2 blinker
    conway = OuterTotalisticCA.conway()
    grid = np.zeros((5, 5), dtype=np.uint8)
    # Horizontal bar
    grid[2, 1:4] = 1

    gen1 = conway.step(grid)
    # Vertical bar
    expected_gen1 = np.zeros((5, 5), dtype=np.uint8)
    expected_gen1[1:4, 2] = 1
    np.testing.assert_array_equal(gen1, expected_gen1)

    # Return to horizontal
    gen2 = conway.step(gen1)
    np.testing.assert_array_equal(gen2, grid)


def test_conway_glider_translation():
    # Glider moves 1 cell diagonally every 4 steps
    conway = OuterTotalisticCA.conway()
    grid = np.zeros((10, 10), dtype=np.uint8)
    glider = np.array([
        [0, 1, 0],
        [0, 0, 1],
        [1, 1, 1],
    ], dtype=np.uint8)
    grid[1:4, 1:4] = glider

    curr = grid
    for _ in range(4):
        curr = conway.step(curr)

    # In periodic grid, glider shifted +1 row, +1 col
    expected = np.zeros((10, 10), dtype=np.uint8)
    expected[2:5, 2:5] = glider
    np.testing.assert_array_equal(curr, expected)


def test_multi_state_brian_brain():
    bb = MultiStateCA.brian_brain()
    grid = np.zeros((4, 4), dtype=np.uint8)
    # Place two firing cells (1) adjacent to cell (1, 1)
    grid[0, 1] = 1  # North of (1, 1)
    grid[2, 1] = 1  # South of (1, 1)

    next_g = bb.step(grid)
    # (1, 1) was 0 with 2 firing neighbors -> becomes 1 (firing)
    assert next_g[1, 1] == 1
    # Firing cells become 2 (dying)
    assert next_g[0, 1] == 2
    assert next_g[2, 1] == 2
