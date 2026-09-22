"""Unit tests for the reproducible Experiment Database and SQLite export."""
from __future__ import annotations

import sqlite3
from pathlib import Path
import numpy as np
import pytest

from lifeforge.experiments.database import ExperimentDatabase, ExperimentRecord
from lifeforge.substrates.ca import OuterTotalisticCA


def test_database_log_and_query(tmp_path: Path):
    db_file = tmp_path / "test_experiments.jsonl"
    db = ExperimentDatabase(db_file)

    conway = OuterTotalisticCA.conway()
    init_state = OuterTotalisticCA.random_state(20, 20, density=0.25, seed=42)

    rec = db.log_simulation(conway, init_state, steps=30, seed=42)

    assert db.count() == 1
    assert rec.rule_notation == "B3/S23"
    assert rec.substrate == "outer_totalistic_ca"
    assert "modes" in rec.to_dict()

    # Query tests
    results = db.query(substrate="outer_totalistic_ca")
    assert len(results) == 1

    empty_results = db.query(substrate="non_existent")
    assert len(empty_results) == 0


def test_sqlite_export(tmp_path: Path):
    db_file = tmp_path / "test_experiments.jsonl"
    sqlite_file = tmp_path / "experiments.db"

    db = ExperimentDatabase(db_file)
    ca = OuterTotalisticCA.seeds()
    init_state = OuterTotalisticCA.random_state(20, 20, density=0.25, seed=1)

    db.log_simulation(ca, init_state, steps=20, seed=1)
    db.export_sqlite(sqlite_file)

    assert sqlite_file.exists()

    conn = sqlite3.connect(sqlite_file)
    cur = conn.cursor()
    cur.execute("SELECT rule_notation, substrate FROM experiments")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 1
    assert rows[0][0] == "B2/S"
    assert rows[0][1] == "outer_totalistic_ca"
