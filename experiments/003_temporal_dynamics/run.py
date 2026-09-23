from __future__ import annotations

import csv
from pathlib import Path

import numpy as np

from lifeforge import (
    ConwayRule,
    ExperimentConfig,
    analyze_temporal_dynamics,
    random_outer_totalistic_rule,
    run_experiment,
)


INPUT_FILE = Path(
    "results/002_rule_space/rule_survey.csv"
)

OUTPUT_DIR = Path(
    "results/003_temporal_dynamics"
)


def load_rules(path: Path) -> list[dict]:
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def select_representative_rules(
    rows: list[dict],
) -> list[dict]:
    """
    Select rules distributed across density/activity space.

    We use a 4 x 4 target grid over the observed
    [density, activity] space.
    """

    densities = np.array(
        [float(row["final_density"]) for row in rows]
    )

    activities = np.array(
        [float(row["mean_activity"]) for row in rows]
    )

    density_targets = np.linspace(
        densities.min(),
        densities.max(),
        4,
    )

    activity_targets = np.linspace(
        activities.min(),
        activities.max(),
        4,
    )

    selected: list[dict] = []
    used_rule_ids: set[int] = set()

    for target_density in density_targets:
        for target_activity in activity_targets:

            distances = (
                (densities - target_density) ** 2
                + (activities - target_activity) ** 2
            )

            candidate_indices = np.argsort(distances)

            for index in candidate_indices:

                rule_id = int(
                    rows[index]["rule_id"]
                )

                if rule_id not in used_rule_ids:
                    selected.append(rows[index])
                    used_rule_ids.add(rule_id)
                    break

    return selected


def main() -> None:
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = load_rules(INPUT_FILE)

    candidates = select_representative_rules(rows)

    # Save which rules were selected.
    selected_file = OUTPUT_DIR / "selected_rules.csv"

    with selected_file.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "rule_id",
                "notation",
                "seed",
                "final_density",
                "mean_activity",
            ],
        )

        writer.writeheader()

        for row in candidates:
            writer.writerow(
                {
                    "rule_id": row["rule_id"],
                    "notation": row["notation"],
                    "seed": row["seed"],
                    "final_density": row["final_density"],
                    "mean_activity": row["mean_activity"],
                }
            )

    config = ExperimentConfig(
        name="003_temporal_dynamics",
        width=50,
        height=50,
        density=0.20,
        steps=2000,
        seed=42,
    )

    results = []

    for candidate in candidates:

        rule_seed = int(candidate["seed"])

        rule = random_outer_totalistic_rule(
            seed=rule_seed
        )

        experiment_result = run_experiment(
            config=config,
            rule=rule,
        )

        summary = analyze_temporal_dynamics(
            experiment_result
        )

        results.append(
            {
                "rule_id": rule.rule_id,
                "notation": rule.notation,
                "source_seed": rule_seed,
                "extinction_time": summary.extinction_time,
                "persistence_ratio": summary.persistence_ratio,
                "population_mean": summary.population_mean,
                "population_std": summary.population_std,
                "activity_mean": summary.activity_mean,
                "activity_std": summary.activity_std,
                "lag1_autocorrelation": (
                    summary.lag1_autocorrelation
                ),
                "exact_recurrence_period": (
                    summary.exact_recurrence_period
                ),
                "final_activity": summary.final_activity,
            }
        )

    # Add Conway as a known control.
    conway_result = run_experiment(
        config=config,
        rule=ConwayRule(),
    )

    conway_summary = analyze_temporal_dynamics(
        conway_result
    )

    results.append(
        {
            "rule_id": ConwayRule().rule_id,
            "notation": ConwayRule().notation,
            "source_seed": "control",
            "extinction_time": conway_summary.extinction_time,
            "persistence_ratio": conway_summary.persistence_ratio,
            "population_mean": conway_summary.population_mean,
            "population_std": conway_summary.population_std,
            "activity_mean": conway_summary.activity_mean,
            "activity_std": conway_summary.activity_std,
            "lag1_autocorrelation": (
                conway_summary.lag1_autocorrelation
            ),
            "exact_recurrence_period": (
                conway_summary.exact_recurrence_period
            ),
            "final_activity": conway_summary.final_activity,
        }
    )

    output_file = OUTPUT_DIR / "temporal_analysis.csv"

    with output_file.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=results[0].keys(),
        )

        writer.writeheader()
        writer.writerows(results)

    print("LIFE FORGE -- Experiment 003")
    print("----------------------------")
    print(f"Rules selected: {len(candidates)}")
    print("Control:        Conway B3/S23")
    print("Grid:           50 x 50")
    print("Generations:    2000")
    print("World seed:     42")
    print()
    print(
        f"Results saved to: {output_file}"
    )


if __name__ == "__main__":
    main()