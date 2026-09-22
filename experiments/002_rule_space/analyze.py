from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


INPUT_FILE = Path("results/002_rule_space/rule_survey.csv")
OUTPUT_DIR = Path("results/002_rule_space")


def load_data(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def percentile(values: list[float], q: float) -> float:
    return float(np.percentile(np.array(values), q))


def main() -> None:
    rows = load_data(INPUT_FILE)

    if not rows:
        raise RuntimeError("No experiment data found.")

    final_populations = [
        int(row["final_population"])
        for row in rows
    ]

    final_densities = [
        float(row["final_density"])
        for row in rows
    ]

    mean_activities = [
        float(row["mean_activity"])
        for row in rows
    ]

    max_populations = [
        int(row["max_population"])
        for row in rows
    ]

    rule_ids = [
        int(row["rule_id"])
        for row in rows
    ]

    unique_rule_count = len(set(rule_ids))

    # Basic categories for exploratory analysis only.
    extinct = sum(
        population == 0
        for population in final_populations
    )

    highly_dense = sum(
        density >= 0.80
        for density in final_densities
    )

    highly_active = sum(
        activity >= 0.40
        for activity in mean_activities
    )

    nearly_static = sum(
        activity <= 0.01
        for activity in mean_activities
    )

    report = OUTPUT_DIR / "analysis_summary.txt"

    with report.open("w", encoding="utf-8") as file:
        file.write("LIFE FORGE — Experiment 002 Analysis\n")
        file.write("=" * 45 + "\n\n")

        file.write(f"Rules sampled: {len(rows)}\n")
        file.write(f"Unique rules: {unique_rule_count}\n")
        file.write(
            f"Duplicate rules: "
            f"{len(rows) - unique_rule_count}\n\n"
        )

        file.write("Final population\n")
        file.write("-" * 20 + "\n")
        file.write(
            f"Minimum: {min(final_populations)}\n"
        )
        file.write(
            f"Maximum: {max(final_populations)}\n"
        )
        file.write(
            f"Median: {percentile(final_populations, 50)}\n"
        )
        file.write(
            f"P25: {percentile(final_populations, 25)}\n"
        )
        file.write(
            f"P75: {percentile(final_populations, 75)}\n\n"
        )

        file.write("Final density\n")
        file.write("-" * 20 + "\n")
        file.write(
            f"Minimum: {min(final_densities):.6f}\n"
        )
        file.write(
            f"Maximum: {max(final_densities):.6f}\n"
        )
        file.write(
            f"Median: {percentile(final_densities, 50):.6f}\n"
        )
        file.write(
            f"P25: {percentile(final_densities, 25):.6f}\n"
        )
        file.write(
            f"P75: {percentile(final_densities, 75):.6f}\n\n"
        )

        file.write("Mean activity\n")
        file.write("-" * 20 + "\n")
        file.write(
            f"Minimum: {min(mean_activities):.6f}\n"
        )
        file.write(
            f"Maximum: {max(mean_activities):.6f}\n"
        )
        file.write(
            f"Median: {percentile(mean_activities, 50):.6f}\n"
        )
        file.write(
            f"P25: {percentile(mean_activities, 25):.6f}\n"
        )
        file.write(
            f"P75: {percentile(mean_activities, 75):.6f}\n\n"
        )

        file.write("Exploratory counts\n")
        file.write("-" * 20 + "\n")
        file.write(f"Extinct: {extinct}\n")
        file.write(f"Density >= 0.80: {highly_dense}\n")
        file.write(f"Mean activity >= 0.40: {highly_active}\n")
        file.write(f"Mean activity <= 0.01: {nearly_static}\n")

    # 1. Final density distribution
    plt.figure(figsize=(10, 5))
    plt.hist(final_densities, bins=30)
    plt.xlabel("Final Density")
    plt.ylabel("Number of Rules")
    plt.title("Rule-Space Distribution: Final Density")
    plt.tight_layout()
    plt.savefig(
        OUTPUT_DIR / "final_density_distribution.png",
        dpi=150,
    )
    plt.close()

    # 2. Mean activity distribution
    plt.figure(figsize=(10, 5))
    plt.hist(mean_activities, bins=30)
    plt.xlabel("Mean Activity")
    plt.ylabel("Number of Rules")
    plt.title("Rule-Space Distribution: Mean Activity")
    plt.tight_layout()
    plt.savefig(
        OUTPUT_DIR / "mean_activity_distribution.png",
        dpi=150,
    )
    plt.close()

    # 3. Density vs activity landscape
    plt.figure(figsize=(8, 6))
    plt.scatter(
        final_densities,
        mean_activities,
        s=14,
        alpha=0.7,
    )
    plt.xlabel("Final Density")
    plt.ylabel("Mean Activity")
    plt.title("LIFE FORGE Rule-Space Landscape")
    plt.tight_layout()
    plt.savefig(
        OUTPUT_DIR / "density_vs_activity.png",
        dpi=150,
    )
    plt.close()

    # 4. Final population distribution
    plt.figure(figsize=(10, 5))
    plt.hist(final_populations, bins=30)
    plt.xlabel("Final Population")
    plt.ylabel("Number of Rules")
    plt.title("Rule-Space Distribution: Final Population")
    plt.tight_layout()
    plt.savefig(
        OUTPUT_DIR / "final_population_distribution.png",
        dpi=150,
    )
    plt.close()

    # 5. Maximum population distribution
    plt.figure(figsize=(10, 5))
    plt.hist(max_populations, bins=30)
    plt.xlabel("Maximum Population")
    plt.ylabel("Number of Rules")
    plt.title("Rule-Space Distribution: Maximum Population")
    plt.tight_layout()
    plt.savefig(
        OUTPUT_DIR / "max_population_distribution.png",
        dpi=150,
    )
    plt.close()

    print("LIFE FORGE — Experiment 002 Analysis")
    print("────────────────────────────────────")
    print(f"Rules analyzed: {len(rows)}")
    print(f"Unique rules:   {unique_rule_count}")
    print(f"Extinct:        {extinct}")
    print(f"Dense (>=80%):  {highly_dense}")
    print(f"Highly active:  {highly_active}")
    print(f"Nearly static:  {nearly_static}")
    print()
    print(f"Analysis saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()