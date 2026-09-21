import numpy as np

from lifeforge.rules import ConwayRule
from lifeforge.world import World


def make_world(pattern: list[list[int]]) -> World:
    state = np.array(pattern, dtype=np.uint8)

    return World(
        width=state.shape[1],
        height=state.shape[0],
        state=state,
    )


def test_block_is_stable():
    world = make_world(
        [
            [0, 0, 0, 0],
            [0, 1, 1, 0],
            [0, 1, 1, 0],
            [0, 0, 0, 0],
        ]
    )

    next_world = ConwayRule().apply(world)

    assert np.array_equal(next_world.state, world.state)


def test_blinker_oscillates():
    world = make_world(
        [
            [0, 0, 0, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0],
        ]
    )

    expected = make_world(
        [
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 1, 1, 1, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ]
    )

    next_world = ConwayRule().apply(world)

    assert np.array_equal(next_world.state, expected.state)


def test_dead_cell_with_three_neighbors_is_born():
    world = make_world(
        [
            [0, 1, 0],
            [1, 0, 1],
            [0, 0, 0],
        ]
    )

    next_world = ConwayRule().apply(world)

    assert next_world.state[1, 1] == 1