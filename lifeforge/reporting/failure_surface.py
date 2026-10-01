"""Failure-surface snapshots and diffs.

A *failure surface* is the shape of everything the evolutionary search
discovered about an agent in one campaign: which MAP-Elites cells are
occupied, which of them are failures, how severe each failure is, and which
failure categories dominate. Captured to a small JSON file, it becomes a
regressable artifact - diff it commit-over-commit and a CI job can answer:

* did this change introduce a *new* failure mode or a new critical cell?
* did a previously failing behavior get fixed?
* did the failure mix shift (loops -> exfiltration)?

This is the artifact that turns a one-shot benchmark into continuous agent
red-teaming: the surface, not a pass/fail bit, is what changes over time.

Snapshots are deterministic for a fixed agent, seed, and generation count, so
identical campaigns diff to zero.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lifeforge.evolution.engine import EvolutionaryRunSummary
from lifeforge.hardening import _VIOLATION_SEVERITY

#: Coordinate precision stored in snapshots; keeps JSON diffs stable.
_COORD_PRECISION = 9

#: Severity ranking for report ordering.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _severity_of(category: str | None) -> str:
    """Severity for a failure category, MEDIUM when unknown."""
    if not category:
        return "MEDIUM"
    return _VIOLATION_SEVERITY.get(str(category).upper(), "MEDIUM")


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


def capture_surface(
    summary: EvolutionaryRunSummary,
    *,
    agent_name: str,
    seed: int,
    generations: int,
    domain: str | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-serializable failure-surface snapshot from a run summary.

    The snapshot contains one record per occupied MAP-Elites cell plus the
    aggregate campaign statistics. Deterministic for a fixed run.
    """
    cells: dict[str, dict[str, Any]] = {}
    mode_breakdown: dict[str, int] = {}

    for elite in summary.elites:
        trace = elite.trace
        category = trace.failure_category
        coords = [round(float(value), _COORD_PRECISION) for value in elite.coords]
        record = {
            "cell": "{},{},{}".format(*elite.cell_index),
            "coords": coords,
            "fitness": round(float(elite.fitness), 6),
            "failed": not trace.success,
            "critical": bool(trace.critical_failure),
            "category": category,
            "severity": _severity_of(category) if not trace.success else None,
            "steps": trace.total_steps,
            "mutations": sorted(set(elite.mutations_applied)),
            "generation": elite.generation,
        }
        cells[record["cell"]] = record
        if not trace.success and category:
            mode_breakdown[category] = mode_breakdown.get(category, 0) + 1

    return {
        "schema": "lifeforge.failure_surface",
        "schema_version": 1,
        "label": label,
        "agent_name": agent_name,
        "domain": domain,
        "seed": seed,
        "generations": generations,
        "total_evaluations": summary.total_evaluations,
        "coverage": round(float(summary.archive_coverage), 9),
        "elites_count": summary.elites_count,
        "critical_failures_count": summary.critical_failures_count,
        "failure_mode_breakdown": dict(sorted(mode_breakdown.items())),
        "cells": dict(sorted(cells.items())),
    }


def load_surface(path: Path | str) -> dict[str, Any]:
    """Load a snapshot from disk, validating the schema marker."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != "lifeforge.failure_surface":
        raise ValueError(
            f"{path} is not a LIFE FORGE failure-surface snapshot "
            "(missing schema marker 'lifeforge.failure_surface')."
        )
    return data


def save_surface(snapshot: dict[str, Any], path: Path | str) -> Path:
    """Write a snapshot as pretty JSON, creating parent directories."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

VERDICT_REGRESSED = "REGRESSED"
VERDICT_IMPROVED = "IMPROVED"
VERDICT_UNCHANGED = "UNCHANGED"


@dataclass
class SurfaceDiff:
    """Everything that changed between two failure surfaces."""

    verdict: str
    new_failures: list[dict[str, Any]] = field(default_factory=list)
    resolved_failures: list[dict[str, Any]] = field(default_factory=list)
    new_criticals: list[dict[str, Any]] = field(default_factory=list)
    resolved_criticals: list[dict[str, Any]] = field(default_factory=list)
    mode_deltas: dict[str, int] = field(default_factory=dict)
    coverage_delta: float = 0.0
    critical_count_delta: int = 0
    baseline_summary: dict[str, Any] = field(default_factory=dict)
    current_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def has_regressions(self) -> bool:
        """True when the current run failed somewhere the baseline did not."""
        return bool(self.new_failures or self.new_criticals)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the diff."""
        return {
            "verdict": self.verdict,
            "has_regressions": self.has_regressions,
            "new_failures": self.new_failures,
            "resolved_failures": self.resolved_failures,
            "new_criticals": self.new_criticals,
            "resolved_criticals": self.resolved_criticals,
            "mode_deltas": self.mode_deltas,
            "coverage_delta": self.coverage_delta,
            "critical_count_delta": self.critical_count_delta,
        }


def diff_surfaces(baseline: dict[str, Any], current: dict[str, Any]) -> SurfaceDiff:
    """Diff two snapshots and classify the change.

    A cell that fails now but succeeded (or did not exist) in the baseline is a
    *new failure*; the reverse is a *resolved failure*. Critical cells are
    tracked as the subset that gates CI.
    """
    base_cells: dict[str, dict[str, Any]] = baseline.get("cells", {}) or {}
    curr_cells: dict[str, dict[str, Any]] = current.get("cells", {}) or {}

    def _brief(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "cell": record.get("cell"),
            "category": record.get("category"),
            "severity": record.get("severity"),
            "fitness": record.get("fitness"),
            "mutations": record.get("mutations", []),
            "coords": record.get("coords"),
        }

    new_failures: list[dict[str, Any]] = []
    resolved_failures: list[dict[str, Any]] = []
    new_criticals: list[dict[str, Any]] = []
    resolved_criticals: list[dict[str, Any]] = []

    for cell, record in curr_cells.items():
        if not record.get("failed"):
            continue
        base_record = base_cells.get(cell)
        if base_record is None or not base_record.get("failed"):
            new_failures.append(_brief(record))
            if record.get("critical"):
                new_criticals.append(_brief(record))

    for cell, record in base_cells.items():
        if not record.get("failed"):
            continue
        curr_record = curr_cells.get(cell)
        if curr_record is None or not curr_record.get("failed"):
            resolved_failures.append(_brief(record))
            if record.get("critical"):
                resolved_criticals.append(_brief(record))

    base_modes: dict[str, int] = baseline.get("failure_mode_breakdown", {}) or {}
    curr_modes: dict[str, int] = current.get("failure_mode_breakdown", {}) or {}
    mode_deltas = {
        category: curr_modes.get(category, 0) - base_modes.get(category, 0)
        for category in sorted(set(base_modes) | set(curr_modes))
    }
    mode_deltas = {category: delta for category, delta in mode_deltas.items() if delta != 0}

    coverage_delta = round(float(current.get("coverage", 0.0)) - float(baseline.get("coverage", 0.0)), 9)
    critical_delta = int(current.get("critical_failures_count", 0)) - int(baseline.get("critical_failures_count", 0))

    if new_failures:
        verdict = VERDICT_REGRESSED
    elif resolved_failures:
        verdict = VERDICT_IMPROVED
    else:
        verdict = VERDICT_UNCHANGED

    return SurfaceDiff(
        verdict=verdict,
        new_failures=sorted(new_failures, key=lambda item: (item["cell"] or "")),
        resolved_failures=sorted(resolved_failures, key=lambda item: (item["cell"] or "")),
        new_criticals=new_criticals,
        resolved_criticals=resolved_criticals,
        mode_deltas=mode_deltas,
        coverage_delta=coverage_delta,
        critical_count_delta=critical_delta,
        baseline_summary={key: baseline.get(key) for key in ("agent_name", "domain", "seed", "generations", "coverage", "critical_failures_count")},
        current_summary={key: current.get(key) for key in ("agent_name", "domain", "seed", "generations", "coverage", "critical_failures_count")},
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_diff_markdown(diff: SurfaceDiff, *, title: str = "Failure Surface Diff") -> str:
    """Render a diff as a CI-friendly Markdown artifact."""
    verdict_banner = {
        VERDICT_REGRESSED: "[REGRESSED] New agent failures were discovered in this change.",
        VERDICT_IMPROVED: "[IMPROVED] Previously failing behaviors were fixed; no new failures.",
        VERDICT_UNCHANGED: "[UNCHANGED] The failure surface is identical to the baseline.",
    }
    lines: list[str] = [
        f"# {title}",
        "",
    ]

    if diff.verdict == VERDICT_REGRESSED:
        lines.append(f"**Verdict: {VERDICT_REGRESSED}**")
    elif diff.verdict == VERDICT_IMPROVED:
        lines.append(f"**Verdict: {VERDICT_IMPROVED}**")
    else:
        lines.append(f"**Verdict: {VERDICT_UNCHANGED}**")
    lines.append("")

    lines.append(f"> {verdict_banner[diff.verdict]}")
    lines.extend(["", "---", "", "## Summary", ""])

    base = diff.baseline_summary
    curr = diff.current_summary
    lines.extend(
        [
            "| Measure | Baseline | Current | Delta |",
            "| :--- | :--- | :--- | :--- |",
            f"| Agent | `{base.get('agent_name', 'n/a')}` | `{curr.get('agent_name', 'n/a')}` | - |",
            f"| Domain | {base.get('domain') or 'default'} | {curr.get('domain') or 'default'} | - |",
            f"| Seed / generations | {base.get('seed', 'n/a')} / {base.get('generations', 'n/a')} "
            f"| {curr.get('seed', 'n/a')} / {curr.get('generations', 'n/a')} | - |",
            f"| Archive coverage | {base.get('coverage', 0.0):.4f} | {curr.get('coverage', 0.0):.4f} "
            f"| {diff.coverage_delta:+.4f} |",
            f"| Critical cells | {base.get('critical_failures_count', 0)} "
            f"| {curr.get('critical_failures_count', 0)} | {diff.critical_count_delta:+d} |",
            "",
            "---",
            "",
            "## Failure Mode Shifts",
            "",
        ]
    )

    if diff.mode_deltas:
        lines.extend(["| Failure category | Baseline -> Current | Delta |", "| :--- | :--- | :--- |"])
        for category, delta in sorted(diff.mode_deltas.items(), key=lambda item: (_SEVERITY_RANK.get(_severity_of(item[0]), 4), item[0])):
            lines.append(f"| `{category}` | {delta:+d} | {delta:+d} |")
    else:
        lines.append("No category-level shifts.")

    lines.extend(["", "---", "", "## New Failures", ""])
    if diff.new_failures:
        for item in diff.new_failures:
            lines.append(
                f"- **Cell `{item['cell']}`** - `{item.get('category', 'unknown')}` "
                f"(severity `{item.get('severity')}`, fitness {item.get('fitness')})"
            )
            if item.get("mutations"):
                lines.append(f"  - mutations: {', '.join(item['mutations'])}")
    else:
        lines.append("None.")

    lines.extend(["", "## Resolved Failures", ""])
    if diff.resolved_failures:
        for item in diff.resolved_failures:
            lines.append(
                f"- **Cell `{item['cell']}`** - `{item.get('category', 'unknown')}` "
                f"(was severity `{item.get('severity')}`)"
            )
    else:
        lines.append("None.")

    if diff.new_criticals:
        lines.extend(
            [
                "",
                "---",
                "",
                "## New Critical Cells (CI gate)",
                "",
            ]
        )
        for item in diff.new_criticals:
            lines.append(f"- Cell `{item['cell']}`: `{item.get('category', 'unknown')}`")

    lines.extend(
        [
            "",
            "---",
            "",
            "*Deterministic artifact: identical campaigns diff to zero. Generated by "
            "LIFE FORGE - The Autonomous Flight Simulator for AI Agents*",
            "",
        ]
    )
    return "\n".join(lines)
