"""Save every simulated episode of an audit, and re-judge it later without the agent.

An audit's reports are computed from its episodes. Before this module only the finished
reports were kept, so any later fix to the oracle or the report generator meant running
the agent (often a slow, rate-limited model) all over again. The bundle now also holds
``simulations.json.gz``: for every evaluation, the scenario the agent faced, what it did
(the events) and the world it left behind. :func:`rejudge` replays nothing; it judges
the recorded episodes again with the *current* oracle and rebuilds the search archive,
so ``lifeforge audit --rebuild`` regenerates every report offline.

What cannot be rebuilt offline: the regression baseline, whose replays need the agent.
"""
from __future__ import annotations

import gzip
import json
from importlib import metadata
from pathlib import Path
from typing import Any

from lifeforge.evolution.engine import EvolutionaryRunSummary, EvolutionEngine
from lifeforge.evolution.map_elites import MapElitesArchive
from lifeforge.sandbox.oracle import ORACLE_VERSION
from lifeforge.sandbox.world_state import WorldState

SIMULATIONS_FILE = "simulations.json.gz"
SCHEMA = "lifeforge.simulations"
SCHEMA_VERSION = 1


def _version() -> str:
    try:
        return metadata.version("lifeforge")
    except metadata.PackageNotFoundError:  # pragma: no cover - source checkout without metadata
        return "unknown"


def _domain_record(domain: Any) -> dict[str, Any] | None:
    """Enough to rebuild the domain: a built-in name, or a compiled domain's whole spec."""
    if domain is None:
        return None
    spec = getattr(domain, "spec", None)
    return {"name": getattr(domain, "name", None), "spec": spec if isinstance(spec, dict) else None}


def save_simulations(
    path: Path | str,
    summary: EvolutionaryRunSummary,
    *,
    agent_name: str,
    domain: Any = None,
    settings: dict[str, Any] | None = None,
) -> Path:
    """Write every evaluation of ``summary`` (scenario, events, end state) to ``path``."""
    evaluations = getattr(summary, "evaluations", None) or []
    record = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "lifeforge_version": _version(),
        "oracle_version": ORACLE_VERSION,
        "agent_name": agent_name,
        "domain": _domain_record(domain),
        "settings": dict(settings or {}),
        "generations": summary.total_generations,
        "seed": summary.seed,
        "complete": len(evaluations) == summary.total_evaluations,
        "evaluations": [
            {
                "generation": e.generation,
                "mutations": list(e.mutations_applied),
                "coords": list(e.coords),
                "scenario": e.scenario.to_dict(),
                "events": e.trace.events,
                "final_state": e.trace.final_state.to_dict() if e.trace.final_state is not None else None,
                "agent_error": e.trace.agent_error,
            }
            for e in evaluations
        ],
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(record, handle, default=str)
    return path


def load_simulations(path: Path | str) -> dict[str, Any]:
    with gzip.open(Path(path), "rt", encoding="utf-8") as handle:
        record = json.load(handle)
    if record.get("schema") != SCHEMA:
        raise ValueError(f"{path} is not a LIFE FORGE simulations file")
    return record


def rebuild_domain(record: dict[str, Any]) -> Any:
    """The domain the simulations were run in (None: the default procurement setup)."""
    info = record.get("domain")
    if not info:
        return None
    if info.get("spec"):
        from lifeforge.sandbox.domains.compiler import CompiledDomain

        return CompiledDomain(info["spec"])
    from lifeforge.sandbox.domains import get_domain

    return get_domain(info["name"])


def rejudge(record: dict[str, Any]) -> tuple[EvolutionaryRunSummary, EvolutionEngine, Any]:
    """Judge every recorded episode again with the current oracle and rebuild the archive.

    Returns the rebuilt run summary, an engine whose runner holds the current oracle (for
    the analyzer), and the domain.
    """
    domain = rebuild_domain(record)
    settings = record.get("settings") or {}
    engine = EvolutionEngine(
        seed=int(record.get("seed") or 42), domain=domain, frontier_mutators=bool(settings.get("frontier"))
    )
    archive = MapElitesArchive(bins=engine.archive.bins)
    for item in record.get("evaluations") or []:
        scenario = WorldState.from_dict(item["scenario"])
        final = WorldState.from_dict(item["final_state"]) if item.get("final_state") else scenario.snapshot()
        trace = engine.runner.judge(scenario.snapshot(), final, item.get("events") or [], item.get("agent_error"))
        archive.add(
            scenario=scenario,
            mutations=list(item.get("mutations") or []),
            trace=trace,
            coords=tuple(float(value) for value in item["coords"]),
            generation=int(item.get("generation", 0)),
        )
    elites = archive.get_elites()
    summary = EvolutionaryRunSummary(
        total_generations=int(record.get("generations") or 0),
        total_evaluations=archive.total_evaluations,
        archive_coverage=archive.coverage,
        elites_count=len(elites),
        novel_failure_modes=sorted(archive.novel_failure_modes_discovered),
        critical_failures_count=len(archive.get_critical_failures()),
        elites=elites,
        failed_evaluations=archive.failed_evaluations,
        critical_evaluations=archive.critical_evaluations,
        seed=record.get("seed"),
        invalid_evaluations=archive.invalid_evaluations,
        failures=list(archive.failures),
        evaluations=list(archive.evaluations),
    )
    return summary, engine, domain
