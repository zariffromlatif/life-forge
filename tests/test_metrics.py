import pytest

from lifeforge.metrics import activity, density, population
from lifeforge.world import World


def test_population():
    world = World.empty(10, 10)

    world.state[2, 2] = 1
    world.state[3, 3] = 1
    world.state[4, 4] = 1

    assert population(world) == 3


def test_density():
    world = World.empty(10, 10)

    world.state[0, 0] = 1
    world.state[0, 1] = 1
    world.state[0, 2] = 1
    world.state[0, 3] = 1

    assert density(world) == pytest.approx(0.04)


def test_activity():
    previous = World.empty(4, 4)
    current = World.empty(4, 4)

    current.state[1, 1] = 1
    current.state[1, 2] = 1

    assert activity(previous, current) == pytest.approx(2 / 16)


def test_activity_rejects_different_dimensions():
    previous = World.empty(4, 4)
    current = World.empty(5, 5)

    with pytest.raises(ValueError):
        activity(previous, current)