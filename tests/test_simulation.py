from lifeforge.rules import ConwayRule
from lifeforge.simulation import Simulation
from lifeforge.world import World


def make_block() -> World:
    world = World.empty(4, 4)

    world.state[1, 1] = 1
    world.state[1, 2] = 1
    world.state[2, 1] = 1
    world.state[2, 2] = 1

    return world


def test_simulation_starts_at_generation_zero():
    simulation = Simulation(
        world=make_block(),
        rule=ConwayRule(),
    )

    assert simulation.generation == 0
    assert len(simulation.history) == 1


def test_step_advances_generation():
    simulation = Simulation(
        world=make_block(),
        rule=ConwayRule(),
    )

    simulation.step()

    assert simulation.generation == 1
    assert len(simulation.history) == 2


def test_block_remains_stable():
    simulation = Simulation(
        world=make_block(),
        rule=ConwayRule(),
    )

    original = simulation.world.state.copy()

    simulation.run(10)

    assert simulation.generation == 10
    assert len(simulation.history) == 11
    assert (simulation.world.state == original).all()