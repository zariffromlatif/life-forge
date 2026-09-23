"""Tests for the LIFE FORGE Web Dashboard and REST backend."""
import json
import threading
import urllib.request
from pathlib import Path

import pytest

from lifeforge.dashboard.server import (
    create_server,
    get_aggregate_summary,
    get_all_reports,
    get_map_elites_grid_data,
)


def test_get_all_reports():
    reports = get_all_reports("results")
    assert isinstance(reports, list)
    assert len(reports) >= 2  # qwen and llama benchmark reports
    agent_names = [r["agent_name"] for r in reports]
    assert any("qwen" in name.lower() for name in agent_names)
    assert any("llama" in name.lower() for name in agent_names)


def test_get_aggregate_summary():
    reports = get_all_reports("results")
    summary = get_aggregate_summary(reports)

    assert "total_models_audited" in summary
    assert summary["total_models_audited"] >= 2
    assert "total_evaluations" in summary
    assert summary["total_evaluations"] > 0
    assert "total_critical_vulnerabilities" in summary
    assert "average_adversarial_failure_rate" in summary
    assert "failure_categories" in summary


def test_get_map_elites_grid_data():
    reports = get_all_reports("results")
    grid = get_map_elites_grid_data(reports)

    assert len(grid) == 25  # 5x5 grid
    cell_statuses = {c["status"] for c in grid}
    assert "pass" in cell_statuses or "critical" in cell_statuses


def test_dashboard_server_endpoints():
    # Bind server to localhost port 0 (ephemeral OS assigned port)
    server = create_server(port=0, host="127.0.0.1", results_dir="results")
    assigned_port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{assigned_port}"

    try:
        # 1. Test index.html
        with urllib.request.urlopen(f"{base_url}/") as res:
            assert res.status == 200
            content = res.read().decode("utf-8")
            assert "LIFE FORGE" in content
            assert "Agent Flight Simulator" in content

        # 2. Test /api/reports
        with urllib.request.urlopen(f"{base_url}/api/reports") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert isinstance(data, list)
            assert len(data) >= 2

        # 3. Test /api/summary
        with urllib.request.urlopen(f"{base_url}/api/summary") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["total_models_audited"] >= 2

        # 4. Test /api/map_elites
        with urllib.request.urlopen(f"{base_url}/api/map_elites") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert len(data) == 25

        # 5. Test /api/modes/simulate
        with urllib.request.urlopen(f"{base_url}/api/modes/simulate?rule=110&steps=20") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["rule"] == 110
            assert "complexity_gap" in data
            assert "wolfram_class" in data
            assert len(data["grid"]) == 21

    finally:
        server.shutdown()
        server.server_close()
