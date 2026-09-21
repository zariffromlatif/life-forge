from pathlib import Path

from lifeforge import (
    ConwayRule,
    ExperimentConfig,
    run_experiment,
    save_result,
)


def main() -> None:
    config = ExperimentConfig(
        name="001_game_of_life",
        width=100,
        height=100,
        density=0.20,
        steps=1000,
        seed=42,
    )

    result = run_experiment(
        config=config,
        rule=ConwayRule(),
    )

    output_dir = Path("results/001_game_of_life")

    save_result(
        result=result,
        output_dir=output_dir,
    )

    print(f"Experiment: {config.name}")
    print(f"Generations: {len(result.generations) - 1}")
    print(f"Initial population: {result.populations[0]}")
    print(f"Final population: {result.populations[-1]}")
    print(f"Results saved to: {output_dir}")


if __name__ == "__main__":
    main()