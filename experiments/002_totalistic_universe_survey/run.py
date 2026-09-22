"""Experiment 002: High-Throughput Universe Survey & Discovery.

Surveys 100 candidate 2D Outer-Totalistic universe rules (plus canonical ALife controls:
Conway, HighLife, Seeds, Day & Night), measuring:
1. Activity (Bedau-Packard evolutionary activity)
2. Complexity (Entropy-Compressibility gap)
3. Novelty (Local pattern vocabulary growth)
4. Ecology (Connected-component cluster tracking & persistence)

Records all simulation runs into the persistent Experiment Database and SQLite catalog.
"""
from __future__ import annotations

from pathlib import Path
import numpy as np

from lifeforge import (
    ExperimentDatabase,
    OuterTotalisticCA,
)

OUTPUT_DIR = Path("results/002_totalistic_universe_survey")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = OUTPUT_DIR / "universe_database.jsonl"
    sqlite_path = OUTPUT_DIR / "universe_database.db"

    # Reset/initialize database
    if jsonl_path.exists():
        jsonl_path.unlink()
    db = ExperimentDatabase(jsonl_path)

    width = 40
    height = 40
    steps = 100
    density = 0.20
    survey_count = 100

    print("=" * 80)
    print(" LIFE FORGE — Experiment 002: High-Throughput Universe Survey & Discovery")
    print("=" * 80)
    print(f"Substrate: 2D Outer-Totalistic Cellular Automata (Moore Neighborhood)")
    print(f"Grid: {height}x{width} | Steps: {steps} | Initial Density: {density * 100:.0f}%\n")

    # 1. Run canonical control universes
    controls = [
        ("Conway B3/S23 (Control)", OuterTotalisticCA.conway()),
        ("HighLife B36/S23 (Control)", OuterTotalisticCA.highlife()),
        ("Seeds B2/S (Control)", OuterTotalisticCA.seeds()),
        ("Day & Night B3678/S34678 (Control)", OuterTotalisticCA.day_and_night()),
    ]

    print("--- [1] Logging Reference Control Universes ---")
    for name, ca in controls:
        init_state = OuterTotalisticCA.random_state(height, width, density=density, seed=42)
        rec = db.log_simulation(ca, init_state, steps=steps, seed=42, metadata={"is_control": True})
        m = rec.modes
        print(f"  • {name:<35}: {m['wolfram_class']} | Gap: {m['complexity_gap']:.4f} | Act: {m['cumulative_activity']:,.0f}")

    # 2. Run random universe candidate search
    print(f"\n--- [2] Scanning {survey_count} Candidate Universe Rules ---")
    class_distribution: dict[str, int] = {}
    class_iv_discoveries: list[dict] = []

    for idx in range(survey_count):
        seed = 1000 + idx
        ca = OuterTotalisticCA.random(seed=seed)
        init_state = OuterTotalisticCA.random_state(height, width, density=density, seed=seed)

        record = db.log_simulation(ca, init_state, steps=steps, seed=seed, metadata={"is_control": False})
        m = record.modes
        w_class = m["wolfram_class"]
        class_distribution[w_class] = class_distribution.get(w_class, 0) + 1

        if m["is_class_iv_candidate"]:
            class_iv_discoveries.append({
                "rule": record.rule_notation,
                "gap": m["complexity_gap"],
                "activity": m["cumulative_activity"],
                "clusters": m["cluster_count"],
            })

        if (idx + 1) % 20 == 0 or (idx + 1) == survey_count:
            print(f"  Processed {idx + 1:>3}/{survey_count} candidate universes...")

    # 3. Export to SQLite
    db.export_sqlite(sqlite_path)

    # 4. Display Scientific Summary
    print("\n" + "=" * 80)
    print(" SCIENTIFIC SURVEY SUMMARY")
    print("=" * 80)
    print(f"Total Universes Simulated: {db.count()}")
    print(f"Database File (JSONL):     {jsonl_path}")
    print(f"Relational Catalog (DB):   {sqlite_path}")
    print("-" * 80)
    print("Dynamical Regime Distribution:")
    for wc, count in sorted(class_distribution.items(), key=lambda x: x[1], reverse=True):
        pct = (count / survey_count) * 100
        print(f"  • {wc:<42}: {count:>3} ({pct:.1f}%)")

    print("-" * 80)
    print(f"Class IV Candidates Discovered: {len(class_iv_discoveries)}")
    for d in class_iv_discoveries[:5]:
        print(f"  -> Rule {d['rule']:<15} | Gap: {d['gap']:.4f} | Activity: {d['activity']:,.0f} | Clusters: {d['clusters']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
