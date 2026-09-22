from __future__ import annotations

import csv
from pathlib import Path

from lifeforge import (
    ExperimentConfig,
    random_outer_totalistic_rule,
    run_experiment,
)


def main() -> None:
    output_dir = Path("results/002_rule_space")
    output_dir.mkdir(parents=True, exist_ok=True)

    number_of_rules = 1000

    config = ExperimentConfig(
        name="002_rule_space",
        width=50,
        height=50,
        density=0.20,
        steps=200,
        seed=42,
    )

    rows = []

    for rule_seed in range(number_of_rules):
        rule = random_outer_totalistic_rule(
            seed=rule_seed
        )

        result = run_experiment(
            config=config,
            rule=rule,
        )

        rows.append(
            {
                "rule_id": rule.rule_id,
                "notation": rule.notation,
                "seed": rule_seed,
                "initial_population": result.populations[0],
                "final_population": result.populations[-1],
                "final_density": result.densities[-1],
                "mean_activity": sum(result.activities) / len(
                    result.activities
                ),
                "max_population": max(result.populations),
            }
        )

    output_file = output_dir / "rule_survey.csv"

    with output_file.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys(),
        )

        writer.writeheader()
        writer.writerows(rows)

    print("LIFE FORGE — Experiment 002")
    print("────────────────────────────")
    print(f"Rules sampled: {number_of_rules}")
    print(f"Grid:           {config.width} × {config.height}")
    print(f"Generations:    {config.steps}")
    print(f"Initial density:{config.density}")
    print(f"World seed:     {config.seed}")
    print()
    print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()