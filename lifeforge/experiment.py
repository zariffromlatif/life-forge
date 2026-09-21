from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

from .metrics import activity, density, population
from .rules import Rule
from .simulation import Simulation
from .world import World


@dataclass(frozen=True)
class ExperimentConfig:
    """Configuration for a reproducible LIFE FORGE experiment."""

    name: str
    width: int
    height: int
    density: float
    steps: int
    seed: int


@dataclass
class ExperimentResult:
    """Results produced by running an experiment."""

    config: ExperimentConfig
    generations: list[int]
    populations: list[int]
    densities: list[float]
    activities: list[float]
    states: list[np.ndarray]


def run_experiment(
    config: ExperimentConfig,
    rule: Rule,
) -> ExperimentResult:
    """Run a reproducible cellular-automaton experiment."""

    if config.steps < 0:
        raise ValueError("steps must be non-negative.")

    world = World.random(
        width=config.width,
        height=config.height,
        density=config.density,
        seed=config.seed,
    )

    simulation = Simulation(
        world=world,
        rule=rule,
    )

    simulation.run(config.steps)

    generations = list(range(len(simulation.history)))

    populations = [
        population(world)
        for world in simulation.history
    ]

    densities = [
        density(world)
        for world in simulation.history
    ]

    activities = [0.0]

    for previous, current in zip(
        simulation.history,
        simulation.history[1:],
    ):
        activities.append(
            activity(previous, current)
        )

    states = [
        world.state.copy()
        for world in simulation.history
    ]

    return ExperimentResult(
        config=config,
        generations=generations,
        populations=populations,
        densities=densities,
        activities=activities,
        states=states,
    )


def save_result(
    result: ExperimentResult,
    output_dir: str | Path,
) -> Path:
    """Save experiment configuration, metrics and states."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Save configuration.
    config_path = output_path / "config.json"

    with config_path.open("w", encoding="utf-8") as file:
        json.dump(
            asdict(result.config),
            file,
            indent=2,
        )

    # Save metrics.
    metrics_path = output_path / "metrics.csv"

    with metrics_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "generation",
                "population",
                "density",
                "activity",
            ]
        )

        for row in zip(
            result.generations,
            result.populations,
            result.densities,
            result.activities,
        ):
            writer.writerow(row)

    # Save complete state history.
    states_path = output_path / "states.npz"

    np.savez_compressed(
        states_path,
        states=np.stack(result.states),
    )

    return output_path