import numpy as np
import pytest

from lifeforge.experiment import (
    ExperimentConfig,
    run_experiment,
)
from lifeforge.rules import ConwayRule
from lifeforge.temporal import (
    analyze_temporal_dynamics,
    find_exact_recurrence_period,
    find_extinction_time,
    lag_autocorrelation,
    persistence_ratio,
)
from lifeforge.world import World


def make_block() -> World:
    world = World.empty(5, 5)

    world.state[2, 2] = 1
    world.state[2, 3] = 1
    world.state[3, 2] = 1
    world.state[3, 3] = 1

    return world


def test_find_extinction_time():
    assert find_extinction_time([5, 4, 2, 0, 0]) == 3


def test_no_extinction():
    assert find_extinction_time([5, 4, 2, 1]) is None


def test_persistence_ratio():
    assert persistence_ratio([1, 2, 0, 0, 3]) == pytest.approx(0.6)


def test_lag_autocorrelation():
    result = lag_autocorrelation(
        [1, 2, 3, 4, 5],
        lag=1,
    )

    assert result == pytest.approx(1.0)


def test_constant_series_has_no_autocorrelation():
    assert lag_autocorrelation(
        [5, 5, 5, 5],
        lag=1,
    ) is None


def test_static_world_has_period_one():
    world = make_block()

    states = [
        world.state.copy(),
        world.state.copy(),
        world.state.copy(),
    ]

    assert find_exact_recurrence_period(states) == 1


def test_blinker_has_period_two():
    config = ExperimentConfig(
        name="blinker",
        width=5,
        height=5,
        density=0.0,
        steps=2,
        seed=42,
    )

    world = World.empty(5, 5)

    world.state[1, 2] = 1
    world.state[2, 2] = 1
    world.state[3, 2] = 1

    from lifeforge.simulation import Simulation

    simulation = Simulation(
        world=world,
        rule=ConwayRule(),
    )

    simulation.run(2)

    assert find_exact_recurrence_period(
        [
            item.state
            for item in simulation.history
        ]
    ) == 2


def test_temporal_analysis():
    world = make_block()

    from lifeforge.simulation import Simulation

    simulation = Simulation(
        world=world,
        rule=ConwayRule(),
    )

    simulation.run(20)

    result = type(
        "Result",
        (),
        {
            "generations": list(range(21)),
            "populations": [
                item.population
                for item in simulation.history
            ],
            "activities": [
                0.0
                for _ in simulation.history
            ],
            "states": [
                item.state.copy()
                for item in simulation.history
            ],
        },
    )()

    summary = analyze_temporal_dynamics(
        result,
        burn_in_fraction=0.25,
    )

    assert summary.persistence_ratio == 1.0
    assert summary.population_mean == pytest.approx(4.0)
    assert summary.population_std == pytest.approx(0.0)
    assert summary.exact_recurrence_period == 1