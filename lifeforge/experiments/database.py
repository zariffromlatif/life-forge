"""Structured, reproducible Experiment Database for LIFE FORGE universe discovery."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from lifeforge.metrics.modes import MODESSummary, analyze_modes
from lifeforge.substrates.base import Substrate


@dataclass(frozen=True)
class ExperimentRecord:
    """Scientific experiment record documenting a single universe simulation and its MODES profile."""

    experiment_id: str
    timestamp: float
    substrate: str
    rule_name: str
    rule_notation: str
    rule_hash: str
    seed: int
    steps: int
    grid_shape: list[int]
    initial_density: float
    modes: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExperimentRecord:
        return cls(
            experiment_id=data["experiment_id"],
            timestamp=data["timestamp"],
            substrate=data["substrate"],
            rule_name=data["rule_name"],
            rule_notation=data["rule_notation"],
            rule_hash=data["rule_hash"],
            seed=data["seed"],
            steps=data["steps"],
            grid_shape=list(data["grid_shape"]),
            initial_density=float(data["initial_density"]),
            modes=data["modes"],
            metadata=data.get("metadata", {}),
        )


class ExperimentDatabase:
    """
    Persistent, queryable scientific database for artificial life universe experiments.
    Stores records in append-only JSONL format with optional SQLite querying.
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: list[ExperimentRecord] = []
        self._load_cache()

    def _load_cache(self) -> None:
        """Load existing records from JSONL file into memory."""
        self._cache.clear()
        if self.db_path.exists():
            with self.db_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._cache.append(ExperimentRecord.from_dict(json.loads(line)))

    def insert(self, record: ExperimentRecord) -> None:
        """Append an experiment record to the database and memory cache."""
        self._cache.append(record)
        with self.db_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict()) + "\n")

    def log_simulation(
        self,
        substrate: Substrate,
        initial_state: np.ndarray,
        steps: int,
        seed: int = 42,
        metadata: dict[str, Any] | None = None,
    ) -> ExperimentRecord:
        """Run a simulation, compute MODES metrics, log the record to the database, and return it."""
        trajectory = substrate.rollout(initial_state, steps=steps)
        modes = analyze_modes(trajectory)

        initial_density = float(np.mean(initial_state > 0)) if initial_state.size > 0 else 0.0

        record = ExperimentRecord(
            experiment_id=str(uuid.uuid4())[:8],
            timestamp=time.time(),
            substrate=substrate.name,
            rule_name=getattr(substrate, "description", substrate.name),
            rule_notation=getattr(substrate, "notation", getattr(substrate, "description", substrate.name)),
            rule_hash=substrate.rule_hash,
            seed=seed,
            steps=steps,
            grid_shape=list(initial_state.shape),
            initial_density=initial_density,
            modes=modes.to_dict(),
            metadata=metadata or {},
        )

        self.insert(record)
        return record

    def query(
        self,
        substrate: str | None = None,
        wolfram_class: str | None = None,
        is_class_iv: bool | None = None,
        min_complexity_gap: float | None = None,
        min_activity: float | None = None,
    ) -> list[ExperimentRecord]:
        """Query experiment records by scientific criteria."""
        results: list[ExperimentRecord] = []
        for r in self._cache:
            if substrate and r.substrate != substrate:
                continue
            if wolfram_class and r.modes.get("wolfram_class") != wolfram_class:
                continue
            if is_class_iv is not None and r.modes.get("is_class_iv_candidate") != is_class_iv:
                continue
            if min_complexity_gap is not None and r.modes.get("complexity_gap", 0.0) < min_complexity_gap:
                continue
            if min_activity is not None and r.modes.get("cumulative_activity", 0.0) < min_activity:
                continue
            results.append(r)
        return results

    def count(self) -> int:
        """Total number of logged experiments."""
        return len(self._cache)

    def export_sqlite(self, sqlite_path: Path | str) -> None:
        """Export all JSONL records into a portable SQLite relational database."""
        conn = sqlite3.connect(sqlite_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS experiments (
                experiment_id TEXT PRIMARY KEY,
                timestamp REAL,
                substrate TEXT,
                rule_name TEXT,
                rule_notation TEXT,
                rule_hash TEXT,
                seed INTEGER,
                steps INTEGER,
                shannon_entropy REAL,
                compressibility_ratio REAL,
                complexity_gap REAL,
                cumulative_activity REAL,
                cluster_count INTEGER,
                persistence_ratio REAL,
                wolfram_class TEXT,
                is_class_iv INTEGER
            )
        """)

        for r in self._cache:
            m = r.modes
            cur.execute("""
                INSERT OR REPLACE INTO experiments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.experiment_id,
                r.timestamp,
                r.substrate,
                r.rule_name,
                r.rule_notation,
                r.rule_hash,
                r.seed,
                r.steps,
                m.get("shannon_entropy", 0.0),
                m.get("compressibility_ratio", 0.0),
                m.get("complexity_gap", 0.0),
                m.get("cumulative_activity", 0.0),
                m.get("cluster_count", 0),
                m.get("persistence_ratio", 0.0),
                m.get("wolfram_class", ""),
                1 if m.get("is_class_iv_candidate") else 0,
            ))

        conn.commit()
        conn.close()
