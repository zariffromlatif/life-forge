import numpy as np

from lifeforge.experiment import (
    ExperimentConfig,
    run_experiment,
)
from lifeforge.rules import ConwayRule


def test_experiment_is_reproducible():
    config = ExperimentConfig(
        name="test",
        width=20,
        height=20,
        density=0.2,
        steps=10,
        seed=42,
    )

    result_a = run_experiment(config, ConwayRule())
    result_b = run_experiment(config, ConwayRule())

    assert result_a.generations == result_b.generations
    assert result_a.populations == result_b.populations
    assert result_a.densities == result_b.densities
    assert result_a.activities == result_b.activities

    for state_a, state_b in zip(
        result_a.states,
        result_b.states,
    ):
        assert np.array_equal(state_a, state_b)


def test_experiment_has_expected_number_of_generations():
    config = ExperimentConfig(
        name="test",
        width=10,
        height=10,
        density=0.2,
        steps=5,
        seed=1,
    )

    result = run_experiment(config, ConwayRule())

    assert len(result.generations) == 6
    assert len(result.populations) == 6
    assert len(result.densities) == 6
    assert len(result.activities) == 6
    assert len(result.states) == 6


def test_first_generation_activity_is_zero():
    config = ExperimentConfig(
        name="test",
        width=10,
        height=10,
        density=0.2,
        steps=5,
        seed=1,
    )

    result = run_experiment(config, ConwayRule())

    assert result.activities[0] == 0.0