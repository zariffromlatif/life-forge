"""Tests for the dashboard's security-report endpoints (surfaces + MCP scans)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from lifeforge.dashboard.server import list_mcp_scans, list_surfaces


SURFACE = {
    "schema": "lifeforge.failure_surface",
    "schema_version": 1,
    "agent_name": "dashboard-probe",
    "domain": None,
    "seed": 42,
    "generations": 5,
    "total_evaluations": 6,
    "coverage": 0.05,
    "elites_count": 2,
    "critical_failures_count": 1,
    "failure_mode_breakdown": {"UNAUTHORIZED_TOOL_EXECUTION": 1},
    "cells": {
        "0,0,0": {"cell": "0,0,0", "coords": [0.0, 0.0, 0.0], "fitness": 5.0, "failed": False,
                   "critical": False, "category": None, "severity": None, "steps": 3,
                   "mutations": ["seed_baseline"], "generation": 0},
        "1,0,0": {"cell": "1,0,0", "coords": [0.2, 0.0, 0.0], "fitness": 150.0, "failed": True,
                   "critical": True, "category": "UNAUTHORIZED_TOOL_EXECUTION",
                   "severity": "CRITICAL", "steps": 4, "mutations": ["indirect_prompt_injection"],
                   "generation": 2},
    },
}

MCP_SCAN = {
    "target": "fixture-server",
    "target_kind": "manifest",
    "generated_utc": "2026-10-03 00:00:00 UTC",
    "ruleset_version": "1.0.0",
    "tool_count": 3,
    "servers": ["fixture"],
    "server_info": {},
    "protocol_version": "",
    "drift_observations": 0,
    "risk_score": 80,
    "risk_band": "CRITICAL",
    "counts_by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 2, "LOW": 0},
    "findings": [
        {"rule_id": "MCP_SCHEMA_POISONING", "severity": "CRITICAL", "title": "t",
         "tool": "x", "server": "fixture", "description": "d", "evidence": {}, "remediation": "r"}
    ],
    "probe_result": None,
}


@pytest.fixture()
def dashboard(tmp_path: Path):
    """A dashboard server rooted at a temp results dir with one of each artifact."""
    (tmp_path / "agent_surface.json").write_text(json.dumps(SURFACE), encoding="utf-8")
    (tmp_path / "mcp_scan.json").write_text(json.dumps(MCP_SCAN), encoding="utf-8")

    from lifeforge.dashboard.server import create_server

    server = create_server(port=0, host="127.0.0.1", results_dir=tmp_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def _get(url: str):
    with urllib.request.urlopen(url) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


class TestSurfaceEndpoints:
    def test_listing_finds_the_snapshot(self, dashboard):
        _, surfaces = _get(f"{dashboard}/api/surfaces")
        assert len(surfaces) == 1
        assert surfaces[0]["file"] == "agent_surface.json"
        assert surfaces[0]["critical_failures_count"] == 1
        assert surfaces[0]["failure_modes"] == ["UNAUTHORIZED_TOOL_EXECUTION"]

    def test_single_snapshot_endpoint(self, dashboard):
        _, data = _get(f"{dashboard}/api/surface?file=agent_surface.json")
        assert data["snapshot"]["agent_name"] == "dashboard-probe"
        assert "diff" not in data

    def test_diff_against_itself_is_unchanged(self, dashboard):
        _, data = _get(f"{dashboard}/api/surface?file=agent_surface.json&against=agent_surface.json")
        assert data["diff"]["verdict"] == "UNCHANGED"
        assert "Failure Surface Diff" in data["diff_markdown"]

    def test_missing_file_is_404(self, dashboard):
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _get(f"{dashboard}/api/surface?file=nope.json")
        assert excinfo.value.code == 404

    def test_missing_file_parameter_is_400(self, dashboard):
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _get(f"{dashboard}/api/surface")
        assert excinfo.value.code == 400

    def test_path_traversal_is_rejected(self, dashboard, tmp_path: Path):
        """A snapshot outside the results dir must not be reachable."""
        secret = tmp_path / "secret.json"
        secret.write_text(json.dumps(SURFACE), encoding="utf-8")
        with pytest.raises(urllib.error.HTTPError):
            _get(f"{dashboard}/api/surface?file=../secret.json")

    def test_non_surface_json_is_rejected(self, dashboard, tmp_path: Path):
        (tmp_path / "random.json").write_text(json.dumps({"hello": 1}), encoding="utf-8")
        with pytest.raises(urllib.error.HTTPError):
            _get(f"{dashboard}/api/surface?file=random.json")


class TestMcpScanEndpoints:
    def test_listing_finds_the_scan(self, dashboard):
        _, scans = _get(f"{dashboard}/api/mcp_scans")
        assert len(scans) == 1
        assert scans[0]["risk_band"] == "CRITICAL"
        assert scans[0]["critical"] == 1

    def test_single_scan_endpoint(self, dashboard):
        _, data = _get(f"{dashboard}/api/mcp_scan?file=mcp_scan.json")
        assert data["target"] == "fixture-server"
        assert data["findings"][0]["rule_id"] == "MCP_SCHEMA_POISONING"

    def test_missing_scan_is_404(self, dashboard):
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _get(f"{dashboard}/api/mcp_scan?file=nope.json")
        assert excinfo.value.code == 404


class TestHelperFunctions:
    def test_list_surfaces_ignores_non_surface_json(self, tmp_path: Path):
        (tmp_path / "benchmark.json").write_text(json.dumps({"agent_name": "x"}), encoding="utf-8")
        assert list_surfaces(tmp_path) == []

    def test_list_mcp_scans_requires_scan_markers(self, tmp_path: Path):
        (tmp_path / "benchmark.json").write_text(json.dumps({"agent_name": "x"}), encoding="utf-8")
        assert list_mcp_scans(tmp_path) == []
