"""Regression corpus: every scenario the search kept, replayable against the next build.

Diffing two failure *surfaces* compares MAP-Elites cells, and which scenario
lands in which cell depends on the search path - which depends on the agent.
Change the agent and the archive explores differently, so a cell can look
"resolved" only because it was not visited this time.  That is a weak basis
for a CI gate.

A corpus fixes this the way fuzzers do: keep the concrete inputs and re-run
them.  Each entry stores the exact scenario (a serialized
:class:`~lifeforge.sandbox.world_state.WorldState`) and the verdict the
baseline agent got on it.  Replaying the corpus against a new agent compares
like with like, scenario by scenario:

* **regressed** - a scenario the baseline handled now fails, a failure became
  critical, or a new violation type appeared;
* **fixed** - a failing scenario now passes;
* **unchanged** - same verdict.

LLM agents are stochastic, so each scenario can be replayed ``repeats``
times.  Verdicts are then rates, and ``tolerance`` sets how much a rate may
rise before it counts as a regression.  With a deterministic agent and
``repeats=1`` the comparison is exact.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from lifeforge.sandbox.agent import AgentInterface
from lifeforge.sandbox.oracle import ORACLE_VERSION, SandboxRunner, SimulationTrace
from lifeforge.sandbox.world_state import WorldState

CORPUS_SCHEMA = "lifeforge.regression_corpus"
CORPUS_SCHEMA_VERSION = 1

VERDICT_REGRESSED = "REGRESSED"
VERDICT_IMPROVED = "IMPROVED"
VERDICT_UNCHANGED = "UNCHANGED"

#: Violation types that describe the run, not the agent's behaviour.
_NON_BEHAVIOURAL = {"AGENT_INFRA_ERROR", "ORACLE_POLICY_ERROR"}


def _canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def scenario_id(scenario: WorldState | dict[str, Any]) -> str:
    """Stable content hash of a scenario (first 16 hex chars of SHA-256)."""
    payload = scenario.to_dict() if isinstance(scenario, WorldState) else scenario
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:16]


@dataclass
class ScenarioOutcome:
    """Aggregated verdict of one scenario over ``runs`` replays."""

    runs: int = 0
    failures: int = 0
    criticals: int = 0
    agent_errors: int = 0
    violation_counts: dict[str, int] = field(default_factory=dict)

    @property
    def valid_runs(self) -> int:
        return self.runs - self.agent_errors

    @property
    def failure_rate(self) -> float:
        return self.failures / self.valid_runs if self.valid_runs else 0.0

    @property
    def critical_rate(self) -> float:
        return self.criticals / self.valid_runs if self.valid_runs else 0.0

    def violation_rates(self) -> dict[str, float]:
        if not self.valid_runs:
            return {}
        return {name: count / self.valid_runs for name, count in sorted(self.violation_counts.items())}

    def add(self, trace: SimulationTrace) -> None:
        self.runs += 1
        if trace.agent_error is not None:
            self.agent_errors += 1
            return
        behavioural = [v for v in trace.violations if v.violation_type not in _NON_BEHAVIOURAL]
        if behavioural:
            self.failures += 1
        if any(v.severity == "CRITICAL" for v in behavioural):
            self.criticals += 1
        for name in sorted({v.violation_type for v in behavioural}):
            self.violation_counts[name] = self.violation_counts.get(name, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "runs": self.runs,
            "agent_errors": self.agent_errors,
            "failure_rate": round(self.failure_rate, 6),
            "critical_rate": round(self.critical_rate, 6),
            "violation_rates": {name: round(rate, 6) for name, rate in self.violation_rates().items()},
        }


def _replay(agent: AgentInterface, runner: SandboxRunner, scenario: WorldState, repeats: int) -> ScenarioOutcome:
    outcome = ScenarioOutcome()
    for _ in range(max(1, repeats)):
        outcome.add(runner.run(agent, scenario))
    return outcome


def build_corpus(
    elites: Iterable[Any],
    agent: AgentInterface,
    runner: SandboxRunner,
    *,
    repeats: int = 1,
    agent_name: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    """Record every archived scenario together with the baseline agent's verdict.

    ``elites`` are :class:`~lifeforge.evolution.map_elites.EliteScenario`
    objects from a campaign.  Passing *and* failing scenarios are kept: a
    scenario the baseline handled is exactly where a regression shows up.
    Each scenario is replayed ``repeats`` times so the baseline verdict of a
    stochastic agent is a rate, not a single draw.
    """
    entries: dict[str, dict[str, Any]] = {}
    for elite in elites:
        scenario = elite.scenario
        sid = scenario_id(scenario)
        if sid in entries:
            continue
        outcome = _replay(agent, runner, scenario, repeats)
        entries[sid] = {
            "id": sid,
            "cell": "{},{},{}".format(*elite.cell_index),
            "mutations": [m for m in elite.mutations_applied if m != "seed_baseline"],
            "scenario": scenario.to_dict(),
            "baseline": outcome.to_dict(),
        }
    return {
        "schema": CORPUS_SCHEMA,
        "schema_version": CORPUS_SCHEMA_VERSION,
        "oracle_version": ORACLE_VERSION,
        "agent_name": agent_name or getattr(agent, "name", type(agent).__name__),
        "domain": domain,
        "repeats": max(1, repeats),
        "entries": [entries[key] for key in sorted(entries)],
    }


@dataclass
class ReplayResult:
    """Scenario-by-scenario comparison of a replay against the corpus baseline."""

    verdict: str
    regressed: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0
    invalid: list[dict[str, Any]] = field(default_factory=list)
    oracle_mismatch: bool = False
    repeats: int = 1
    tolerance: float = 0.0
    total: int = 0

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "total": self.total,
            "regressed": self.regressed,
            "fixed": self.fixed,
            "unchanged": self.unchanged,
            "invalid": self.invalid,
            "oracle_mismatch": self.oracle_mismatch,
            "repeats": self.repeats,
            "tolerance": self.tolerance,
        }


def _compare(entry: dict[str, Any], current: ScenarioOutcome, tolerance: float) -> tuple[str, list[str]]:
    """Classify one scenario as regressed / fixed / unchanged, with reasons."""
    base = entry.get("baseline") or {}
    base_failure = float(base.get("failure_rate", 0.0))
    base_critical = float(base.get("critical_rate", 0.0))
    base_types = base.get("violation_rates") or {}

    reasons: list[str] = []
    if current.critical_rate > base_critical + tolerance:
        reasons.append(f"critical rate {base_critical:.2f} -> {current.critical_rate:.2f}")
    if current.failure_rate > base_failure + tolerance:
        reasons.append(f"failure rate {base_failure:.2f} -> {current.failure_rate:.2f}")
    for name, rate in current.violation_rates().items():
        if rate > float(base_types.get(name, 0.0)) + tolerance and float(base_types.get(name, 0.0)) == 0.0:
            reasons.append(f"new violation {name} ({rate:.2f})")
    if reasons:
        return "regressed", reasons

    if base_failure > 0.0 and current.failure_rate + tolerance < base_failure:
        return "fixed", [f"failure rate {base_failure:.2f} -> {current.failure_rate:.2f}"]
    return "unchanged", []


def replay_corpus(
    corpus: dict[str, Any],
    agent: AgentInterface,
    runner: SandboxRunner,
    *,
    repeats: int | None = None,
    tolerance: float = 0.0,
) -> ReplayResult:
    """Re-run every corpus scenario against ``agent`` and compare verdicts.

    ``tolerance`` is the rate increase allowed before a scenario counts as
    regressed (use 0 for deterministic agents; e.g. 0.2 with ``repeats=5``
    for a sampled LLM agent).  Scenarios where the agent failed to respond on
    every replay are reported as ``invalid`` and never counted as fixed.
    """
    if corpus.get("schema") != CORPUS_SCHEMA:
        raise ValueError("Not a LIFE FORGE regression corpus (missing schema marker).")
    repeats = max(1, int(repeats if repeats is not None else corpus.get("repeats", 1)))
    result = ReplayResult(
        verdict=VERDICT_UNCHANGED,
        repeats=repeats,
        tolerance=tolerance,
        oracle_mismatch=corpus.get("oracle_version") != ORACLE_VERSION,
    )

    for entry in corpus.get("entries", []):
        scenario = WorldState.from_dict(entry["scenario"])
        current = _replay(agent, runner, scenario, repeats)
        result.total += 1
        brief = {
            "id": entry.get("id"),
            "cell": entry.get("cell"),
            "mutations": entry.get("mutations", []),
            "baseline": entry.get("baseline"),
            "current": current.to_dict(),
        }
        if current.valid_runs == 0:
            result.invalid.append(brief)
            continue
        status, reasons = _compare(entry, current, tolerance)
        if status == "regressed":
            result.regressed.append({**brief, "reasons": reasons})
        elif status == "fixed":
            result.fixed.append({**brief, "reasons": reasons})
        else:
            result.unchanged += 1

    if result.regressed:
        result.verdict = VERDICT_REGRESSED
    elif result.fixed:
        result.verdict = VERDICT_IMPROVED
    return result


def render_replay_markdown(result: ReplayResult, *, title: str = "Regression Corpus Replay") -> str:
    """CI-friendly Markdown for a replay result."""
    lines = [
        f"# {title}",
        "",
        f"**Verdict: {result.verdict}**",
        "",
        f"Replayed **{result.total}** recorded scenarios x {result.repeats} run(s) "
        f"(tolerance {result.tolerance:.2f}): **{len(result.regressed)}** regressed, "
        f"**{len(result.fixed)}** fixed, {result.unchanged} unchanged, {len(result.invalid)} invalid.",
        "",
    ]
    if result.oracle_mismatch:
        lines += [
            "> The corpus was recorded with a different oracle version; some verdict changes may come "
            "from the oracle, not the agent. Re-record the baseline to compare like with like.",
            "",
        ]
    if result.invalid:
        lines += [
            f"> {len(result.invalid)} scenario(s) produced no valid run (the agent errored every time). "
            "They are excluded from the verdict and are not evidence of safety.",
            "",
        ]

    def section(name: str, items: list[dict[str, Any]]) -> None:
        lines.extend([f"## {name}", ""])
        if not items:
            lines.extend(["None.", ""])
            return
        lines.extend(["| Scenario | Cell | Mutations | Change |", "| :--- | :--- | :--- | :--- |"])
        for item in items:
            mutations = ", ".join(item.get("mutations") or []) or "baseline"
            change = "; ".join(item.get("reasons") or [])
            lines.append(f"| `{item['id']}` | {item.get('cell')} | {mutations} | {change} |")
        lines.append("")

    section("Regressed", result.regressed)
    section("Fixed", result.fixed)
    lines.append(
        "*Each scenario is replayed exactly as recorded, so these are like-for-like comparisons, "
        "not differences in what the search happened to explore.*"
    )
    return "\n".join(lines) + "\n"
