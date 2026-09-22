"""Experiment 001: Quantitative Classification of Wolfram Dynamical Classes via MODES.

Investigates canonical 1D Elementary Cellular Automata:
- Class I  (Homogeneous):  Rule 0
- Class II (Periodic):     Rule 184 (Traffic solitons / periodic structures)
- Class III (Chaotic):      Rule 30  (Deterministic pseudorandom noise)
- Class IV (Complex):      Rule 110 (Turing-complete localized computational structures)

Demonstrates how the MODES framework (Complexity Gap, Bedau-Packard Activity, Novelty, Ecology)
objectively distinguishes Class IV from chaotic 'beautiful garbage' without human visual subjectivity.
"""
from __future__ import annotations

from pathlib import Path
import numpy as np

from lifeforge import (
    ElementaryCA,
    ExperimentDatabase,
    analyze_modes,
)

OUTPUT_DIR = Path("results/001_wolfram_classes")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    db = ExperimentDatabase(OUTPUT_DIR / "wolfram_experiments.jsonl")

    canonical_rules = [
        ("Rule 0 (Class I)", ElementaryCA(0)),
        ("Rule 184 (Class II)", ElementaryCA.rule_184()),
        ("Rule 30 (Class III)", ElementaryCA.rule_30()),
        ("Rule 110 (Class IV)", ElementaryCA.rule_110()),
    ]

    width = 101
    steps = 150
    seed = 42

    print("=" * 80)
    print(" LIFE FORGE — Experiment 001: MODES Classification of Wolfram Classes")
    print("=" * 80)

    results = []

    for name, ca in canonical_rules:
        # Use single central seed to observe natural localized propagation
        init_state = ElementaryCA.seed_center(width)
        record = db.log_simulation(ca, init_state, steps=steps, seed=seed, metadata={"rule_label": name})
        results.append((name, record))

    print(f"\n{'Rule':<22} | {'Wolfram Class':<28} | {'Entropy H':<10} | {'Compress C':<10} | {'Gap (H-C)':<10} | {'Activity':<10}")
    print("-" * 105)

    for name, r in results:
        m = r.modes
        w_class = m["wolfram_class"]
        h = m["shannon_entropy"]
        c = m["compressibility_ratio"]
        gap = m["complexity_gap"]
        act = m["cumulative_activity"]

        print(f"{name:<22} | {w_class:<28} | {h:<10.4f} | {c:<10.4f} | {gap:<10.4f} | {act:<10,.0f}")

    print("=" * 105)
    print(f"Results recorded to: {OUTPUT_DIR / 'wolfram_experiments.jsonl'}\n")


if __name__ == "__main__":
    main()
