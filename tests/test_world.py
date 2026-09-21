import numpy as np

from lifeforge.world import World


def test_empty_world():
    world = World.empty(10, 20)

    assert world.width == 10
    assert world.height == 20
    assert world.state.shape == (20, 10)
    assert world.population == 0


def test_random_world_reproducible():
    world_a = World.random(20, 20, density=0.2, seed=42)
    world_b = World.random(20, 20, density=0.2, seed=42)

    assert np.array_equal(world_a.state, world_b.state)


def test_copy_is_independent():
    world = World.empty(10, 10)
    copied = world.copy()

    copied.state[0, 0] = 1

    assert world.state[0, 0] == 0
    assert copied.state[0, 0] == 1