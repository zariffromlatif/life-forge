# LIFE FORGE

> **A computational framework for discovering and evaluating artificial worlds capable of sustained self-organization, self-reproduction, adaptation, and open-ended evolutionary dynamics.**

```
                     LIFE FORGE
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
      WORLDS          EVOLUTION        MEASUREMENT
        │                │                │
        ▼                ▼                ▼
   CA / Lenia /      mutation /       novelty /
   NCA / ecosystems  selection /      complexity /
                     competition      ecology (MODES)
                         │
                         └───────┬────────┘
                                 ▼
                         DISCOVERY ENGINE
                                 │
                                 ▼
                        NEW LIFE MECHANISMS
```

---

## The Scientific Core: The MODES Framework

A central challenge in Artificial Life is beating the **"Beautiful Garbage" trap**: confusing high-entropy visual noise (Wolfram Class III) with true computational, adaptive organization (Wolfram Class IV).

LIFE FORGE incorporates the quantitative **MODES** measurement suite:
1. **Activity**: Bedau-Packard evolutionary activity waves ($A_{cum}$, component persistence, excess activity over neutral shadow models).
2. **Complexity**: Shannon entropy ($H$), bit-packed LZW algorithmic compressibility ($C$), and the **Complexity Gap** ($H \cdot (1 - C)$) which mathematically collapses on white noise while peaking sharply on Class IV systems.
3. **Novelty**: Cumulative vocabulary growth of local neighborhood micro-states and macroscopic behavioral trajectory divergence.
4. **Ecology**: 8-connected spatial cluster tracking ("organisms"), cluster size diversity, and persistence ratios.

---

## Architecture

```
lifeforge/
├── substrates/             # Cellular Automata and universe physics
│   ├── base.py             # Substrate & State ABCs
│   └── ca/
│       ├── elementary.py   # 1D Elementary CA (Rule 30, 90, 110, 184)
│       ├── totalistic.py   # 2D Vectorized Outer-Totalistic CA (Conway, HighLife, Seeds)
│       └── multi_state.py  # Multi-State 2D CA (Langton loops & Evoloops foundations)
│
├── metrics/                # Quantitative measurement suite
│   ├── evolutionary_activity.py  # Bedau-Packard evolutionary activity & shadow baseline
│   ├── complexity.py       # Shannon entropy, LZW compressibility, complexity gap
│   ├── novelty.py          # State vocabulary growth & innovation rates
│   ├── ecology.py          # Spatial entity clustering & Shannon diversity
│   └── modes.py            # Unified 4-pillar MODES research summary
│
├── experiments/
│   └── database.py         # Structured, queryable Experiment Database (JSONL & SQLite)
│
└── cli/
    └── main.py             # CLI for simulation runs and universe surveys
```

---

## Quick Start

### 1. Run a Universe Simulation
```bash
# Run Conway's Game of Life
python -m lifeforge.cli run --substrate totalistic --steps 100

# Run Wolfram Rule 110 (Turing complete)
python -m lifeforge.cli run --substrate elementary --rule 110 --steps 100
```

### 2. High-Throughput Universe Survey
Survey 100 candidate universe rules and export to the experiment database:
```bash
python experiments/002_totalistic_universe_survey/run.py
```

### 3. Run Automated Tests
```bash
pytest
# 55 passed in 0.88s
```

---

## Structured Experiment Database

Every simulation run records a reproducible scientific record:
```json
{
  "experiment_id": "a1b2c3d4",
  "substrate": "outer_totalistic_ca",
  "rule_name": "B3/S23 (moore)",
  "rule_hash": "a4f8e91c...",
  "seed": 42,
  "steps": 100,
  "modes": {
    "wolfram_class": "Class IV (Complex / Open-Ended)",
    "complexity_gap": 0.1666,
    "cumulative_activity": 73647.0,
    "cluster_count": 30,
    "persistence_ratio": 1.0,
    "is_class_iv_candidate": true
  }
}
```
All records are queryable in-memory, stored in append-only JSONL, and exportable to relational SQLite (`.db`).
