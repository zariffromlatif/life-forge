from pathlib import Path
from lifeforge import plot_metrics
from lifeforge import animate_world

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

    plot_metrics(
    result=result,
    output_dir=output_dir,
    )

    animate_world(
    result=result,
    output_path=output_dir / "world.mp4",
    frame_step=5,
    interval=40,
    )

    print(f"Experiment: {config.name}")
    print(f"Generations: {len(result.generations) - 1}")
    print(f"Initial population: {result.populations[0]}")
    print(f"Final population: {result.populations[-1]}")
    print(f"Results saved to: {output_dir}")


if __name__ == "__main__":
    main()