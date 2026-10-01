"""Tests for failure-surface capture, diffing, and rendering.

Covers synthetic snapshot diffs (all verdicts), engine-level determinism
(identical campaigns diff to zero), and the regress/improve semantics of the
reference agents.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.failure_surface import (
    VERDICT_IMPROVED,
    VERDICT_REGRESSED,
    VERDICT_UNCHANGED,
    capture_surface,
    diff_surfaces,
    load_surface,
    render_diff_markdown,
    save_surface,
)
from lifeforge.sandbox.agent import RuleBasedPurchasingAgent
from lifeforge.sandbox.world_state import WorldState


# ---------------------------------------------------------------------------
# Snapshot factories for synthetic diffs
# ---------------------------------------------------------------------------


def _cell(cell: str, *, failed: bool, critical: bool = False, category: str | None = None, fitness: float = 40.0) -> dict:
    from lifeforge.hardening import _VIOLATION_SEVERITY

    return {
        "cell": cell,
        "coords": [0.1, 0.2, 0.3],
        "fitness": fitness,
        "failed": failed,
        "critical": critical,
        "category": category if failed else None,
        "severity": _VIOLATION_SEVERITY.get(category, "MEDIUM") if failed else None,
        "steps": 6,
        "mutations": ["price_volatility"],
        "generation": 3,
    }


def _snapshot(cells: dict[str, dict], *, coverage: float = 0.5, criticals: int = 0, agent: str = "agent") -> dict:
    breakdown: dict[str, int] = {}
    for record in cells.values():
        if record["failed"] and record["category"]:
            breakdown[record["category"]] = breakdown.get(record["category"], 0) + 1
    return {
        "schema": "lifeforge.failure_surface",
        "schema_version": 1,
        "agent_name": agent,
        "domain": None,
        "seed": 42,
        "generations": 10,
        "total_evaluations": 11,
        "coverage": coverage,
        "elites_count": len(cells),
        "critical_failures_count": criticals,
        "failure_mode_breakdown": breakdown,
        "cells": cells,
    }


# ---------------------------------------------------------------------------
# Diff logic
# ---------------------------------------------------------------------------


class TestDiffLogic:
    def test_identical_surfaces_are_unchanged(self):
        surface = _snapshot({"0,0,0": _cell("0,0,0", failed=False), "1,1,1": _cell("1,1,1", failed=True, category="RECURSIVE_LOOP_TRAP")})
        diff = diff_surfaces(surface, surface)
        assert diff.verdict == VERDICT_UNCHANGED
        assert not diff.has_regressions
        assert diff.mode_deltas == {}

    def test_new_failure_cell_regresses(self):
        baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=False)})
        current = _snapshot(
            {
                "0,0,0": _cell("0,0,0", failed=False),
                "1,0,0": _cell("1,0,0", failed=True, category="RECURSIVE_LOOP_TRAP"),
            }
        )
        diff = diff_surfaces(baseline, current)
        assert diff.verdict == VERDICT_REGRESSED
        assert len(diff.new_failures) == 1
        assert diff.new_failures[0]["cell"] == "1,0,0"
        assert diff.mode_deltas == {"RECURSIVE_LOOP_TRAP": 1}

    def test_new_critical_is_flagged_for_ci_gate(self):
        baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=False)})
        current = _snapshot(
            {
                "0,0,0": _cell("0,0,0", failed=False),
                "2,0,0": _cell("2,0,0", failed=True, critical=True, category="UNAUTHORIZED_TOOL_EXECUTION"),
            },
            criticals=1,
        )
        diff = diff_surfaces(baseline, current)
        assert diff.verdict == VERDICT_REGRESSED
        assert len(diff.new_criticals) == 1
        assert diff.new_criticals[0]["category"] == "UNAUTHORIZED_TOOL_EXECUTION"

    def test_success_flipping_to_critical_regresses(self):
        baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=False)})
        current = _snapshot(
            {"0,0,0": _cell("0,0,0", failed=True, critical=True, category="UNAUTHORIZED_FINANCIAL_DRAIN")},
            criticals=1,
        )
        diff = diff_surfaces(baseline, current)
        assert diff.verdict == VERDICT_REGRESSED
        assert diff.critical_count_delta == 1

    def test_resolved_failure_improves(self):
        baseline = _snapshot(
            {
                "0,0,0": _cell("0,0,0", failed=True, category="GOAL_INVENTORY_DEFICIT"),
                "1,1,1": _cell("1,1,1", failed=True, critical=True, category="UNAUTHORIZED_TOOL_EXECUTION"),
            },
            criticals=1,
        )
        current = _snapshot(
            {
                "0,0,0": _cell("0,0,0", failed=False),
                "1,1,1": _cell("1,1,1", failed=False),
            }
        )
        diff = diff_surfaces(baseline, current)
        assert diff.verdict == VERDICT_IMPROVED
        assert len(diff.resolved_failures) == 2
        assert len(diff.resolved_criticals) == 1
        assert diff.critical_count_delta == -1

    def test_mixed_change_regresses(self):
        """One resolved and one new failure: the verdict must be REGRESSED."""
        baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=True, category="BUDGET_EXCEEDED")})
        current = _snapshot(
            {
                "0,0,0": _cell("0,0,0", failed=False),
                "1,1,1": _cell("1,1,1", failed=True, category="UNAUTHORIZED_TOOL_EXECUTION"),
            }
        )
        diff = diff_surfaces(baseline, current)
        assert diff.verdict == VERDICT_REGRESSED
        assert len(diff.resolved_failures) == 1

    def test_mode_mix_shift_is_visible_without_cell_changes(self):
        """A failure that changes category in the same cell shows in the mode deltas."""
        baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=True, category="RECURSIVE_LOOP_TRAP")})
        current = _snapshot({"0,0,0": _cell("0,0,0", failed=True, category="UNAUTHORIZED_TOOL_EXECUTION")})
        diff = diff_surfaces(baseline, current)
        # The cell is still failing, so it is not a new failure cell...
        assert diff.new_failures == []
        # ...but the failure MIX shifted, which the deltas expose.
        assert diff.mode_deltas == {"RECURSIVE_LOOP_TRAP": -1, "UNAUTHORIZED_TOOL_EXECUTION": 1}

    def test_summary_metadata_is_carried(self):
        baseline = _snapshot({}, agent="before")
        current = _snapshot({}, agent="after")
        diff = diff_surfaces(baseline, current)
        assert diff.baseline_summary["agent_name"] == "before"
        assert diff.current_summary["agent_name"] == "after"


# ---------------------------------------------------------------------------
# Capture from the engine
# ---------------------------------------------------------------------------


class TestCapture:
    def test_capture_is_deterministic_for_fixed_run(self):
        def run() -> dict:
            agent = RuleBasedPurchasingAgent(name="cap-probe", vulnerable_to_injection=True)
            summary = EvolutionEngine(seed=13).run(agent, WorldState.default_purchasing_world(), generations=8)
            return capture_surface(summary, agent_name="cap-probe", seed=13, generations=8)

        first = run()
        second = run()
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_capture_shape(self):
        agent = RuleBasedPurchasingAgent(name="shape-probe", vulnerable_to_injection=True)
        summary = EvolutionEngine(seed=5).run(agent, WorldState.default_purchasing_world(), generations=5)
        snapshot = capture_surface(summary, agent_name="shape-probe", seed=5, generations=5)

        assert snapshot["schema"] == "lifeforge.failure_surface"
        assert snapshot["agent_name"] == "shape-probe"
        assert snapshot["elites_count"] == len(snapshot["cells"])
        assert snapshot["critical_failures_count"] == sum(1 for c in snapshot["cells"].values() if c["critical"])
        for record in snapshot["cells"].values():
            assert set(record) == {"cell", "coords", "fitness", "failed", "critical", "category", "severity", "steps", "mutations", "generation"}
            assert len(record["coords"]) == 3

    def test_round_trip_through_disk(self, tmp_path: Path):
        agent = RuleBasedPurchasingAgent(name="disk-probe", vulnerable_to_injection=True)
        summary = EvolutionEngine(seed=7).run(agent, WorldState.default_purchasing_world(), generations=5)
        snapshot = capture_surface(summary, agent_name="disk-probe", seed=7, generations=5)

        path = save_surface(snapshot, tmp_path / "surfaces" / "s.json")
        loaded = load_surface(path)
        assert loaded == snapshot

    def test_load_rejects_non_surface_json(self, tmp_path: Path):
        path = tmp_path / "not_a_surface.json"
        path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
        with pytest.raises(ValueError):
            load_surface(path)


# ---------------------------------------------------------------------------
# Agent-level semantics
# ---------------------------------------------------------------------------


class TestAgentSemantics:
    def test_identical_campaign_diffs_to_unchanged(self):
        """Determinism at the semantics level: same agent, seed, and generations
        produce a byte-identical surface, so CI diffs of unchanged agents are zero."""
        def campaign() -> dict:
            agent = RuleBasedPurchasingAgent(name="probe", vulnerable_to_injection=True)
            summary = EvolutionEngine(seed=21).run(agent, WorldState.default_purchasing_world(), generations=8)
            return capture_surface(summary, agent_name="probe", seed=21, generations=8)

        diff = diff_surfaces(campaign(), campaign())
        assert diff.verdict == VERDICT_UNCHANGED
        assert not diff.has_regressions

    def test_different_agents_produce_a_well_formed_diff(self):
        """The vulnerable and hardened reference agents occupy different cells;
        whatever the direction, the diff must carry complete, consistent fields."""
        def campaign(vulnerable: bool) -> dict:
            agent = RuleBasedPurchasingAgent(name=f"probe-{vulnerable}", vulnerable_to_injection=vulnerable)
            summary = EvolutionEngine(seed=21).run(agent, WorldState.default_purchasing_world(), generations=10)
            return capture_surface(summary, agent_name=f"probe-{vulnerable}", seed=21, generations=10)

        diff = diff_surfaces(campaign(True), campaign(False))
        assert diff.verdict in (VERDICT_REGRESSED, VERDICT_IMPROVED, VERDICT_UNCHANGED)
        assert isinstance(diff.has_regressions, bool)
        assert len(diff.baseline_summary) == len(diff.current_summary) == 6
        assert all("cell" in item for item in diff.new_failures + diff.resolved_failures)
        # Every delta entry is a genuine integer shift.
        assert all(isinstance(delta, int) for delta in diff.mode_deltas.values())


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class TestRendering:
    def test_markdown_renders_every_verdict(self):
        for verdict, new, resolved in (
            (VERDICT_REGRESSED, 1, 0),
            (VERDICT_IMPROVED, 0, 1),
            (VERDICT_UNCHANGED, 0, 0),
        ):
            baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=False)})
            current_cells = {"0,0,0": _cell("0,0,0", failed=False)}
            if new:
                current_cells["1,1,1"] = _cell("1,1,1", failed=True, category="BUDGET_EXCEEDED")
            current = _snapshot(current_cells)
            if resolved:
                baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=True, category="BUDGET_EXCEEDED")})
                current = _snapshot({"0,0,0": _cell("0,0,0", failed=False)})

            diff = diff_surfaces(baseline, current)
            assert diff.verdict == verdict
            markdown = render_diff_markdown(diff)
            assert f"**Verdict: {verdict}**" in markdown
            assert markdown.startswith("# Failure Surface Diff")

    def test_regressed_markdown_lists_critical_gate_section(self):
        baseline = _snapshot({"0,0,0": _cell("0,0,0", failed=False)})
        current = _snapshot(
            {"0,0,0": _cell("0,0,0", failed=True, critical=True, category="UNAUTHORIZED_TOOL_EXECUTION")},
            criticals=1,
        )
        markdown = render_diff_markdown(diff_surfaces(baseline, current), title="PR #12")
        assert "# PR #12" in markdown
        assert "New Critical Cells (CI gate)" in markdown
        assert "UNAUTHORIZED_TOOL_EXECUTION" in markdown
