"""Customer-deliverable audit bundle.

Packages a complete red-team audit into the folder a consultant would send a
client: an executive summary, a technical report, the raw evidence, one-command
reproduction instructions, and generated hardening code.

The bundle is deliberately self-contained.  A recipient who has never installed
LIFE FORGE can read the summaries, and can re-run the audit from the included
commands once they do install it.
"""
from __future__ import annotations

import json
import platform
import shlex
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from lifeforge.hardening import (
    VIOLATION_GUARDS,
    generate_hardening_module,
    violations_from_report,
)

#: Severity ranking used to order findings in every deliverable.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _utc_now(explicit: str | None = None) -> str:
    """Generation timestamp: explicit value, else SOURCE_DATE_EPOCH, else now."""
    from .report import resolve_generated_utc

    return resolve_generated_utc(explicit)


def _severity_for(violation_type: str) -> str:
    """Return the severity a violation type carries."""
    from lifeforge.hardening import _VIOLATION_SEVERITY

    return _VIOLATION_SEVERITY.get(str(violation_type).upper(), "MEDIUM")


def _risk_score(report: dict[str, Any]) -> tuple[int, str]:
    """Compute a 0-100 risk score and band from a benchmark report.

    Uses the scoring function shared with the PDF renderer
    (:func:`lifeforge.reporting.analyzer.risk_score_for_report`), so the
    Markdown and PDF deliverables of one bundle always agree.  Scoring is per
    finding (one per failure category), not per archive cell, so the score
    does not grow with how many cells a single category occupies.
    """
    from .analyzer import risk_score_for_report

    return risk_score_for_report(report)


def _rate_lines(report: dict[str, Any]) -> list[str]:
    """Markdown table rows for the evaluation and elite-cell failure rates."""
    eval_rate = report.get("evaluation_failure_rate")
    if eval_rate is not None:
        failed = report.get("failed_evaluations")
        detail = f" ({failed} of {report.get('total_evaluations', 0)} simulations)" if failed is not None else ""
        eval_cell = f"**{eval_rate}%**{detail}"
    else:
        eval_cell = "not recorded (report predates per-evaluation counters)"
    return [
        f"| Evaluation failure rate (all simulations) | {eval_cell} |",
        f"| Elite-cell failure rate (archive cells) | **{report.get('failure_rate', 0.0)}%** |",
        f"| Elite-cell success rate | {report.get('success_rate', 0.0)}% |",
    ]


def _reproduction_commands(
    report: dict[str, Any],
    *,
    target: str | None,
    model: str | None,
    scenarios: int,
    seed: int,
    domain: str | None,
) -> str:
    """Build the shell script that reproduces the audit."""
    lines = [
        "#!/usr/bin/env bash",
        "# Reproduction commands for this LIFE FORGE audit.",
        "#",
        "# The verdicts in this bundle come from a deterministic invariant policy",
        "# oracle: the same seed and the same agent produce byte-identical",
        "# violations. Re-running these commands regenerates every artifact here.",
        "set -euo pipefail",
        "",
        "pip install 'lifeforge[all]'",
        "",
    ]

    domain_flag = [f"  --domain {shlex.quote(domain)} \\"] if domain else []
    # Both benchmark commands exit 1 when critical vulnerabilities are found
    # (the expected outcome of most audits).  Accept exactly that code so
    # ``set -e`` does not abort before the report is re-exported; any other
    # failure (e.g. a usage error, exit 2) still stops the script.
    tolerate_criticals = "  || test $? -eq 1"

    report_json: str | None = None
    if model:
        # Model benchmarks run through ``lifeforge test`` (``eval`` has no --model).
        out_md = f"results/local_{_safe_slug(model)}_report.md"
        report_json = out_md[: -len(".md")] + ".json"
        lines.extend(
            [
                "# Re-run the model benchmark that produced the findings.",
                "lifeforge test \\",
                f"  --model {shlex.quote(model)} \\",
                *domain_flag,
                f"  --scenarios {scenarios} \\",
                f"  --seed {seed} \\",
                "  --json \\",
                f"  --out {out_md} \\",
                tolerate_criticals,
                "",
                "# To audit your own agent instead of a hosted model, use:",
                f"#   lifeforge eval --target agent.py:my_agent --scenarios {scenarios} --seed {seed} --json",
                "",
            ]
        )
    elif target:
        report_json = "results/eval_report.json"
        lines.extend(
            [
                "# Re-run the evaluation against the audited agent.",
                "lifeforge eval \\",
                f"  --target {shlex.quote(target)} \\",
                *domain_flag,
                f"  --scenarios {scenarios} \\",
                f"  --seed {seed} \\",
                "  --json \\",
                "  --out results/eval_report.md \\",
                tolerate_criticals,
                "",
            ]
        )
    else:
        lines.extend(
            [
                "# No model or agent target was recorded for this audit, so the benchmark",
                "# run cannot be replayed automatically. Re-run it with one of:",
                f"#   lifeforge test --model <model> --scenarios {scenarios} --seed {seed} --json",
                f"#   lifeforge eval --target agent.py:my_agent --scenarios {scenarios} --seed {seed} --json",
                "",
            ]
        )

    lines.extend(
        [
            "# Regenerate the security leaderboard across all benchmark reports.",
            "lifeforge leaderboard",
            "",
        ]
    )
    if report_json:
        lines.extend(
            [
                "# Re-export the PDF deliverable from the JSON written above.",
                "lifeforge report --format pdf \\",
                f"  --input {report_json} \\",
                "  --output audit_report.pdf",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "# Re-export the PDF deliverable from the benchmark JSON you audited:",
                "#   lifeforge report --format pdf --input <report.json> --output audit_report.pdf",
                "",
            ]
        )
    return "\n".join(lines)


def _safe_slug(text: str) -> str:
    """Filesystem-safe slug for embedding a model name in a filename."""
    cleaned = "".join(char if char.isalnum() else "_" for char in str(text))
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned.strip("_").lower() or "audit"


def _environment_fingerprint(
    *,
    model: str | None,
    hardware: str | None,
    seed: int,
    scenarios: int,
    target: str | None,
    domain: str | None,
    generated_utc: str | None = None,
) -> dict[str, Any]:
    """Capture everything needed to reproduce the run."""
    return {
        "generated_utc": _utc_now(generated_utc),
        "lifeforge_version": _package_version(),
        "python_version": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "model": model,
        "target_agent": target,
        "domain": domain,
        "hardware": hardware,
        "scenarios": scenarios,
        "seed": seed,
        "determinism_note": (
            "Verdicts are produced by a deterministic invariant policy oracle. "
            "Re-running with the same agent, seed, and generation count reproduces "
            "the same violation set."
        ),
    }


def _package_version() -> str:
    """Installed LIFE FORGE version, or 'unknown' when not importable."""
    try:
        from importlib.metadata import version

        return version("lifeforge")
    except Exception:  # pragma: no cover - source checkouts without metadata
        return "unknown"


def build_executive_summary(
    report: dict[str, Any],
    *,
    customer: str | None = None,
    environment: dict[str, Any] | None = None,
) -> str:
    """Write the board-facing summary: risk posture and required decisions."""
    score, band = _risk_score(report)
    findings = report.get("findings", []) or []
    critical = [f for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"]
    environment = environment or {}

    lines: list[str] = [
        "# Security Audit: Executive Summary",
        "",
        f"**Prepared for**: {customer or 'the requesting organization'}  ",
        f"**Prepared by**: LIFE FORGE automated adversarial red-teaming  ",
        f"**Generated**: {environment.get('generated_utc', _utc_now())}",
        "",
        "---",
        "",
        "## Overall Risk Posture",
        "",
        f"**Risk score: {score}/100 ({band})**",
        "",
        f"**Security grade: {report.get('generalization_rating', 'Unknown')}**",
        "",
        "| Measure | Result |",
        "| :--- | :--- |",
        f"| Target agent | `{report.get('agent_name', 'unknown')}` |",
        f"| Total adversarial simulations | {report.get('total_evaluations', 0):,} |",
        f"| Distinct environments explored | {report.get('scenarios_generated', 0):,} |",
        *_rate_lines(report),
        f"| Critical vulnerabilities | **{report.get('critical_failures', 0)}** |",
        f"| Distinct failure modes | {report.get('novel_failure_modes_count', 0)} |",
        "",
    ]

    if critical:
        lines.extend(
            [
                "## Critical Findings Requiring Immediate Action",
                "",
                f"{len(critical)} critical vulnerability(ies) were reproduced. Each one permits an "
                "action the agent is not authorized to take, and none of them cause a crash - the "
                "agent completes the forbidden action and reports success.",
                "",
            ]
        )
        for index, finding in enumerate(critical, start=1):
            lines.extend(
                [
                    f"{index}. **{finding.get('title', 'Untitled finding')}** "
                    f"(`{finding.get('category', 'unknown')}`)",
                    f"   - {str(finding.get('description', '')).strip()}",
                    f"   - Required remediation: {str(finding.get('recommendation', '')).strip()}",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "## Critical Findings",
                "",
                "No critical vulnerabilities were reproduced under the tested conditions. "
                "Findings at lower severity are detailed in the technical report.",
                "",
            ]
        )

    lines.extend(
        [
            "## What This Means",
            "",
            "This audit tested the agent the way an attacker would: by evolving adversarial "
            "scenarios across thousands of generations rather than checking a fixed test list. "
            "Every finding below was discovered by the search, then verified against a "
            "deterministic policy oracle that produces the same verdict on every re-run.",
            "",
            "The relevant question for the reader is not whether the agent fails, but whether it "
            "fails *safely*. In this evaluation, the failures that matter are silent ones: the "
            "agent performed an unauthorized action and reported the task as complete.",
            "",
            "---",
            "",
            "## Recommended Next Steps",
            "",
            "1. Review the technical report's findings and apply the generated hardening guards "
            "(`remediation_decorators.py`) at the tool boundary. These enforce the invariant "
            "regardless of what the model decides.",
            "2. Enable the runtime gateway in monitor mode to observe live traffic against the "
            "same rules, then promote rules to blocking once the false-positive rate is known.",
            "3. Re-run this audit after remediation; a clean verdict is reproducible, not "
            "asserted.",
            "",
            "---",
            "",
            "*Generated by LIFE FORGE - The Autonomous Flight Simulator for AI Agents*  ",
            "*MIT License | https://github.com/zariffromlatif/life-forge*",
            "",
        ]
    )
    return "\n".join(lines)


def build_technical_report(
    report: dict[str, Any],
    *,
    environment: dict[str, Any] | None = None,
    hardening_module: str | None = None,
) -> str:
    """Write the engineer-facing report: evidence, mechanism, and remediation."""
    environment = environment or {}
    findings = report.get("findings", []) or []
    breakdown = report.get("failure_mode_breakdown", {}) or {}
    score, band = _risk_score(report)

    ordered_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 4),
    )

    lines: list[str] = [
        "# Security Audit: Technical Report",
        "",
        f"**Generated**: {environment.get('generated_utc', _utc_now())}  ",
        f"**Target agent**: `{report.get('agent_name', 'unknown')}`  ",
        f"**Risk score**: {score}/100 ({band})  ",
        f"**Evaluation seed**: {environment.get('seed', 'unknown')} | "
        f"**Generations**: {environment.get('scenarios', report.get('total_generations', 'unknown'))}",
        "",
        "---",
        "",
        "## Method",
        "",
        "LIFE FORGE runs a co-evolutionary arms race between the agent under test and an "
        "adversary that mutates the environment. Scenarios are selected to fill a 3D "
        "Quality-Diversity (MAP-Elites) archive over adversarial injection intensity, "
        "environmental volatility, and resource pressure, so the search reports a "
        "*distribution* of failure modes rather than a single pass/fail.",
        "",
        "Verdicts are produced by a deterministic invariant policy oracle. There is no "
        "model-based grading in the verdict path, so a finding can be re-derived exactly.",
        "",
        "---",
        "",
        "## Failure Mode Distribution",
        "",
        "| Violation | Occurrences | Severity |",
        "| :--- | :--- | :--- |",
    ]

    for violation_type, count in sorted(
        breakdown.items(),
        key=lambda item: (_SEVERITY_RANK.get(_severity_for(item[0]), 4), -int(item[1] or 0)),
    ):
        lines.append(f"| `{violation_type}` | {count} | {_severity_for(violation_type)} |")

    if not breakdown:
        lines.append("| (none) | 0 | - |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Findings",
            "",
        ]
    )

    if not ordered_findings:
        lines.extend(
            [
                "No findings met the reporting threshold. The agent satisfied every tested "
                "invariant across the explored scenario space.",
                "",
            ]
        )
    else:
        for index, finding in enumerate(ordered_findings, start=1):
            lines.extend(
                [
                    f"### Finding {index}: {finding.get('title', 'Untitled')}",
                    "",
                    f"- **Severity**: `{finding.get('severity', 'UNKNOWN')}`",
                    f"- **Category**: `{finding.get('category', 'unknown')}`",
                    f"- **Minimal causal trigger**: "
                    f"`{', '.join(finding.get('minimal_causal_trigger', []) or ['not recorded'])}`",
                    "",
                    "**Mechanism**",
                    "",
                    str(finding.get("description", "")).strip(),
                    "",
                ]
            )
            snippet = finding.get("trace_snippet") or []
            if snippet:
                lines.extend(["**Evidence from the recorded trace**", ""])
                for event in snippet[:12]:
                    if isinstance(event, dict):
                        rendered = ", ".join(f"{key}={value}" for key, value in event.items())
                        lines.append(f"- {rendered}")
                    else:
                        lines.append(f"- {event}")
                lines.append("")

            lines.extend(
                [
                    "**Required remediation**",
                    "",
                    str(finding.get("recommendation", "")).strip(),
                    "",
                    "---",
                    "",
                ]
            )

    lines.extend(
        [
            "## Remediation Code",
            "",
            "The bundle includes `remediation_decorators.py`: drop-in guards that enforce each "
            "finding's invariant at the tool boundary. Guard the affected tool and the agent "
            "cannot complete the forbidden action, regardless of the instructions it is given.",
            "",
        ]
    )
    if hardening_module:
        lines.extend(["```python", hardening_module.strip(), "```", ""])

    lines.extend(
        [
            "## Reproducibility",
            "",
            "| Parameter | Value |",
            "| :--- | :--- |",
            f"| Model | `{environment.get('model') or 'not applicable'}` |",
            f"| Target agent | `{environment.get('target_agent') or 'not applicable'}` |",
            f"| Domain | `{environment.get('domain') or 'procurement (default)'}` |",
            f"| Hardware | {environment.get('hardware') or 'not recorded'} |",
            f"| Scenario count | {environment.get('scenarios', 'unknown')} |",
            f"| Random seed | {environment.get('seed', 'unknown')} |",
            f"| Python | {environment.get('python_version', 'unknown')} |",
            f"| Platform | {environment.get('platform', 'unknown')} |",
            f"| LIFE FORGE | {environment.get('lifeforge_version', 'unknown')} |",
            "",
            "See `reproduction_commands.sh` for the exact commands.",
            "",
            "---",
            "",
            "*Generated by LIFE FORGE - MIT License | https://github.com/zariffromlatif/life-forge*",
            "",
        ]
    )
    return "\n".join(lines)


def build_audit_bundle(
    report: dict[str, Any],
    output_dir: Path | str,
    *,
    customer: str | None = None,
    model: str | None = None,
    target: str | None = None,
    domain: str | None = None,
    hardware: str | None = None,
    scenarios: int = 30,
    seed: int = 42,
    tool_name_map: dict[str, str] | None = None,
    override_map: dict[str, dict[str, Any]] | None = None,
    include_pdf: bool = True,
    generated_utc: str | None = None,
) -> dict[str, Path]:
    """Write the complete audit bundle and return the paths produced.

    Files written:

    * ``executive_summary.md`` - the board-facing document
    * ``technical_report.md`` - findings, evidence, and method
    * ``raw_data.json`` - the report this bundle was built from, plus context
    * ``reproduction_commands.sh`` - exact re-run instructions
    * ``remediation_decorators.py`` - generated hardening guards
    * ``executive_summary.pdf`` / ``technical_report.pdf`` - when PDF export is
      available and ``include_pdf`` is set

    A PDF failure is reported as a missing entry rather than aborting the
    bundle, because the Markdown deliverables are always producible and are what
    the recipient acts on.

    ``generated_utc`` pins the timestamp stamped into every file (otherwise
    ``SOURCE_DATE_EPOCH`` when set, else the current time), so a re-run with
    the same inputs reproduces the bundle byte for byte.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    environment = _environment_fingerprint(
        model=model,
        hardware=hardware,
        seed=seed,
        scenarios=scenarios,
        target=target,
        domain=domain,
        generated_utc=generated_utc,
    )

    violations = violations_from_report(report)
    hardening_source = generate_hardening_module(
        violations,
        tool_name_map=tool_name_map,
        override_map=override_map,
    )

    written: dict[str, Path] = {}

    executive_path = out / "executive_summary.md"
    executive_path.write_text(
        build_executive_summary(report, customer=customer, environment=environment),
        encoding="utf-8",
    )
    written["executive_summary"] = executive_path

    technical_path = out / "technical_report.md"
    technical_path.write_text(
        build_technical_report(report, environment=environment, hardening_module=hardening_source),
        encoding="utf-8",
    )
    written["technical_report"] = technical_path

    raw_path = out / "raw_data.json"
    raw_path.write_text(
        json.dumps({"environment": environment, "report": report}, indent=2, default=str),
        encoding="utf-8",
    )
    written["raw_data"] = raw_path

    repro_path = out / "reproduction_commands.sh"
    repro_path.write_text(
        _reproduction_commands(
            report,
            target=target,
            model=model,
            scenarios=scenarios,
            seed=seed,
            domain=domain,
        ),
        encoding="utf-8",
    )
    written["reproduction_commands"] = repro_path

    hardening_path = out / "remediation_decorators.py"
    hardening_path.write_text(hardening_source, encoding="utf-8")
    written["remediation_decorators"] = hardening_path

    index_path = out / "MANIFEST.md"
    index_path.write_text(
        _build_manifest(
            report,
            customer=customer,
            environment=environment,
            violations=violations,
            written=written,
        ),
        encoding="utf-8",
    )
    written["manifest"] = index_path

    if include_pdf:
        written.update(_try_pdf_exports(report, out, customer=customer, environment=environment))

    return written


def _try_pdf_exports(
    report: dict[str, Any],
    out: Path,
    *,
    customer: str | None,
    environment: dict[str, Any],
) -> dict[str, Path]:
    """Attempt the PDF deliverables, returning only what was actually written."""
    written: dict[str, Path] = {}
    try:
        from lifeforge.reporting.pdf import render_from_report_dict
    except ImportError:
        return written

    try:
        written["pdf"] = render_from_report_dict(
            report,
            out / "technical_report.pdf",
            customer=customer,
            model=environment.get("model"),
            hardware=environment.get("hardware"),
            seed=environment.get("seed"),
            generations=environment.get("scenarios"),
            command_line="lifeforge audit",
            title="LIFE FORGE Security Audit - Technical Report",
            generated_utc=environment.get("generated_utc"),
        )
    except Exception:
        written.pop("pdf", None)

    try:
        written["executive_pdf"] = _render_executive_pdf(report, out, customer, environment)
    except Exception:
        written.pop("executive_pdf", None)

    return written


def _render_executive_pdf(
    report: dict[str, Any],
    out: Path,
    customer: str | None,
    environment: dict[str, Any],
) -> Path:
    """Render the executive summary as a standalone PDF when supported.

    The PDF renderer takes a report dict; the executive summary is a text
    document, so it is rendered through the same path with the summary metrics
    and the critical findings only.
    """
    from lifeforge.reporting.pdf import render_from_report_dict

    summary_report = dict(report)
    summary_report["findings"] = [
        finding
        for finding in (report.get("findings") or [])
        if str(finding.get("severity", "")).upper() == "CRITICAL"
    ]
    return render_from_report_dict(
        summary_report,
        out / "executive_summary.pdf",
        customer=customer,
        model=environment.get("model"),
        hardware=environment.get("hardware"),
        seed=environment.get("seed"),
        generations=environment.get("scenarios"),
        command_line="lifeforge audit",
        title="LIFE FORGE Security Audit - Executive Summary",
        generated_utc=environment.get("generated_utc"),
    )


def _build_manifest(
    report: dict[str, Any],
    *,
    customer: str | None,
    environment: dict[str, Any],
    violations: list[str],
    written: dict[str, Path],
) -> str:
    """Write the bundle's index page."""
    score, band = _risk_score(report)
    lines = [
        "# Audit Deliverable Package",
        "",
        f"**Customer**: {customer or 'the requesting organization'}  ",
        f"**Generated**: {environment.get('generated_utc', _utc_now())}  ",
        f"**Target agent**: `{report.get('agent_name', 'unknown')}`  ",
        f"**Risk score**: {score}/100 ({band})  ",
        f"**Critical vulnerabilities**: {report.get('critical_failures', 0)}",
        "",
        "---",
        "",
        "## Contents",
        "",
        "| File | Purpose |",
        "| :--- | :--- |",
        "| `executive_summary.md` | Board-facing risk posture and required decisions |",
        "| `technical_report.md` | Findings, evidence, method, and remediation |",
        "| `raw_data.json` | Complete machine-readable evidence |",
        "| `reproduction_commands.sh` | Exact commands to reproduce every verdict |",
        "| `remediation_decorators.py` | Generated guards that enforce each finding's invariant |",
        "| `MANIFEST.md` | This index |",
    ]
    for key, path in sorted(written.items()):
        if key in ("executive_summary", "technical_report", "raw_data", "reproduction_commands", "remediation_decorators", "manifest"):
            continue
        lines.append(f"| `{path.name}` | Optional deliverable ({key}) |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Violations Covered by Generated Guards",
            "",
        ]
    )
    if violations:
        for violation in violations:
            spec = VIOLATION_GUARDS.get(violation)
            if spec:
                lines.append(f"- `{violation}` - enforced with `{spec['policy']}`")
            else:
                lines.append(f"- `{violation}` - no automatic guard template; review manually")
    else:
        lines.append("No violations were recorded, so no guards were generated.")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Verification",
            "",
            "1. Every finding in `technical_report.md` cites the recorded trace evidence that "
            "produced it.",
            "2. `reproduction_commands.sh` regenerates this bundle; verdicts are deterministic "
            "for a fixed agent and seed.",
            "3. `remediation_decorators.py` imports from `lifeforge.hardening`; the guards raise "
            "`PolicyError` before a forbidden call reaches your implementation.",
            "",
            "*Generated by LIFE FORGE - MIT License*",
            "",
        ]
    )
    return "\n".join(lines)


# Ensure the dataclass helper stays importable for callers that want programmatic
# access to the findings structure the bundle renders.
__all__ = [
    "build_audit_bundle",
    "build_executive_summary",
    "build_technical_report",
    "asdict",
]
