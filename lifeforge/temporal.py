from __future__ import annotations

import hashlib
from dataclasses import dataclass

import numpy as np

from .experiment import ExperimentResult


@dataclass(frozen=True)
class TemporalSummary:
    """Summary of the temporal behavior of a simulation."""

    extinction_time: int | None

    persistence_ratio: float

    population_mean: float
    population_std: float

    activity_mean: float
    activity_std: float

    lag1_autocorrelation: float | None

    exact_recurrence_period: int | None

    final_activity: float


def find_extinction_time(
    populations: list[int],
) -> int | None:
    """
    Return the first generation at which the population
    reaches zero.

    Return None if extinction never occurs.
    """

    for generation, value in enumerate(populations):
        if value == 0:
            return generation

    return None


def persistence_ratio(
    populations: list[int],
    start_generation: int = 0,
) -> float:
    """
    Fraction of generations with nonzero population
    after start_generation.
    """

    values = np.asarray(
        populations[start_generation:],
        dtype=np.float64,
    )

    if len(values) == 0:
        return 0.0

    return float(np.mean(values > 0))


def lag_autocorrelation(
    values: list[float],
    lag: int = 1,
) -> float | None:
    """
    Compute Pearson autocorrelation at a specified lag.
    """

    series = np.asarray(values, dtype=np.float64)

    if lag <= 0:
        raise ValueError("lag must be positive.")

    if lag >= len(series):
        return None

    x = series[:-lag]
    y = series[lag:]

    x_std = np.std(x)
    y_std = np.std(y)

    if x_std == 0.0 or y_std == 0.0:
        return None

    correlation = np.corrcoef(x, y)[0, 1]

    return float(correlation)


def find_exact_recurrence_period(
    states: list[np.ndarray],
) -> int | None:
    """
    Detect the first exact repeated state.

    For a deterministic cellular automaton, revisiting an
    exact state implies that the subsequent trajectory will
    repeat with that period.
    """

    seen: dict[bytes, int] = {}

    for generation, state in enumerate(states):
        contiguous_state = np.ascontiguousarray(state)

        digest = hashlib.blake2b(
            contiguous_state.tobytes(),
            digest_size=16,
        ).digest()

        if digest in seen:
            return generation - seen[digest]

        seen[digest] = generation

    return None


def analyze_temporal_dynamics(
    result: ExperimentResult,
    burn_in_fraction: float = 0.25,
) -> TemporalSummary:
    """
    Calculate a temporal summary for an experiment.

    The initial portion of the simulation is treated as
    transient and excluded from long-run statistics.
    """

    if not 0.0 <= burn_in_fraction < 1.0:
        raise ValueError(
            "burn_in_fraction must be in [0, 1)."
        )

    burn_in = int(
        len(result.generations) * burn_in_fraction
    )

    populations = result.populations[burn_in:]
    activities = result.activities[burn_in:]

    population_array = np.asarray(
        populations,
        dtype=np.float64,
    )

    activity_array = np.asarray(
        activities,
        dtype=np.float64,
    )

    return TemporalSummary(
        extinction_time=find_extinction_time(
            result.populations
        ),
        persistence_ratio=persistence_ratio(
            result.populations,
            start_generation=burn_in,
        ),
        population_mean=float(
            np.mean(population_array)
        ),
        population_std=float(
            np.std(population_array)
        ),
        activity_mean=float(
            np.mean(activity_array)
        ),
        activity_std=float(
            np.std(activity_array)
        ),
        lag1_autocorrelation=lag_autocorrelation(
            populations,
            lag=1,
        ),
        exact_recurrence_period=find_exact_recurrence_period(
            result.states
        ),
        final_activity=float(
            result.activities[-1]
        ),
    )