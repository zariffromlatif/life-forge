"""Compliance evidence mode: benchmark results become control assessments.

This module bridges the deterministic verdicts of the red-team engine and the
regulatory documentation obligations that increasingly apply to deployed AI
systems. The initial framework is the EU AI Act's obligations most relevant to
agentic systems: risk management (Art. 9), data governance (Art. 10),
record-keeping (Art. 12), transparency (Art. 13), human oversight (Art. 14),
and robustness/cybersecurity (Art. 15).

What this module is, and is not
-------------------------------
It IS: an evidence pack. Every control assessment cites the concrete,
reproducible artifacts that justify it - the violation register from a
benchmark report, the hash-chain verification of a gateway audit trail, and
the reproduction commands that regenerate both. The assessments are
deterministic functions of those artifacts.

It is NOT: a legal opinion or a certification. The output states which
controls have documentary evidence and where the gaps are; it does not assert
that a system is compliant. The document says so on its face.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lifeforge.hardening import _VIOLATION_SEVERITY

#: Severity ranking for register ordering.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

FRAMEWORK_EU_AI_ACT = "eu-ai-act"

SUPPORTED_FRAMEWORKS = (FRAMEWORK_EU_AI_ACT,)


# ---------------------------------------------------------------------------
# Framework definition: violation classes -> regulatory control areas
# ---------------------------------------------------------------------------

#: Each control: id, article reference, title, obligation summary, and the
#: violation categories that constitute documented gaps against it.
EU_AI_ACT_CONTROLS: tuple[dict[str, Any], ...] = (
    {
        "id": "risk_management",
        "article": "Art. 9",
        "title": "Risk management system",
        "obligation": (
            "A continuous, documented risk-management process covering known and emergent "
            "risks of the system."
        ),
        "gap_categories": [
            "UNAUTHORIZED_TOOL_EXECUTION",
            "UNAUTHORIZED_FINANCIAL_DRAIN",
            "UNAUTHORIZED_DATA_EXFILTRATION",
            "PRIVILEGE_ESCALATION",
            "TOCTOU_RACE_CONDITION",
            "SELF_REPLICATING_WORM_PROPAGATION",
            "RAG_MEMORY_POISONING_ADOPTED",
        ],
        "evidence_sources": ["Adversarial benchmark report", "Violation register"],
        "remediation": (
            "Feed every critical finding into the risk register with a remediation owner and "
            "re-run the benchmark after each mitigation; the failure-surface diff documents "
            "the risk trajectory between versions."
        ),
    },
    {
        "id": "record_keeping",
        "article": "Art. 12",
        "title": "Record-keeping / logging",
        "obligation": (
            "Logs sufficient to reconstruct events and trace the system's operation, "
            "proportionate to the risk, and resistant to tampering."
        ),
        "gap_categories": [],
        "requires_trail": True,
        "evidence_sources": ["Gateway audit trail", "Chain verification"],
        "remediation": (
            "Deploy the runtime PolicyGateway with a persisted, hash-chained audit trail and "
            "verify the chain periodically; attach the verification output to the audit file."
        ),
    },
    {
        "id": "transparency",
        "article": "Art. 13",
        "title": "Transparency and provision of information",
        "obligation": (
            "Deployers can understand the system's capabilities, limitations, and the actions "
            "it takes."
        ),
        "gap_categories": [
            "CONFIRMATION_NOT_SENT",
            "UNAUTHORIZED_SCOPE_EXPANSION",
            "EXCESSIVE_DATA_QUERYING",
        ],
        "evidence_sources": ["Failure-mode distribution", "Audit bundle technical report"],
        "remediation": (
            "Publish the failure-mode distribution to stakeholders and document each "
            "capability boundary the search found the agent crossing."
        ),
    },
    {
        "id": "human_oversight",
        "article": "Art. 14",
        "title": "Human oversight",
        "obligation": (
            "The system must be designed so natural persons can oversee its operation, "
            "including the ability to intervene or stop it."
        ),
        "gap_categories": [
            "PRIVILEGE_ESCALATION",
            "UNAUTHORIZED_TOOL_EXECUTION",
            "UNAUTHORIZED_FINANCIAL_DRAIN",
        ],
        "evidence_sources": ["Approval-gate findings", "Hardening decorators"],
        "remediation": (
            "Enforce approval-gate invariants at the tool boundary (RequiredPredecessorPolicy "
            "guards / gateway sequence rules) so consequential actions cannot execute without "
            "a recorded human approval step."
        ),
    },
    {
        "id": "robustness",
        "article": "Art. 15",
        "title": "Robustness and cybersecurity",
        "obligation": (
            "The system must be resilient to errors, faults, inconsistencies, and attempts to "
            "alter its use or performance by malicious third parties."
        ),
        "gap_categories": [
            "UNAUTHORIZED_TOOL_EXECUTION",
            "SELF_REPLICATING_WORM_PROPAGATION",
            "RAG_MEMORY_POISONING_ADOPTED",
            "CONTEXT_FLOOD_ATTACK",
            "CASCADING_TOOL_FAILURE",
            "PARAMETER_BOUNDARY_VIOLATION",
            "RECURSIVE_LOOP_TRAP",
        ],
        "evidence_sources": ["Adversarial benchmark report", "MCP scan report", "Frontier attack coverage"],
        "remediation": (
            "Apply the generated hardening decorators for each injection-derived finding and "
            "re-run the campaign with --frontier until the propagation and poisoning verdicts "
            "no longer fire."
        ),
    },
    {
        "id": "data_governance",
        "article": "Art. 10",
        "title": "Data and data governance",
        "obligation": (
            "Training, validation, and operational data are subject to governance appropriate "
            "to the system's purpose, including examination for biases and provenance."
        ),
        "gap_categories": [
            "UNAUTHORIZED_DATA_EXFILTRATION",
            "EXCESSIVE_DATA_QUERYING",
            "RAG_MEMORY_POISONING_ADOPTED",
        ],
        "evidence_sources": ["Egress findings", "Reconnaissance findings"],
        "remediation": (
            "Whitelist egress recipients at the gateway and audit sensitive-table access "
            "patterns; the EXCESSIVE_DATA_QUERYING verdicts document the reconnaissance "
            "surface that governance must cover."
        ),
    },
)

_FRAMEWORKS = {FRAMEWORK_EU_AI_ACT: EU_AI_ACT_CONTROLS}


def classify_violation(violation_type: str, framework: str = FRAMEWORK_EU_AI_ACT) -> list[str]:
    """Return the control ids a violation category constitutes a gap against."""
    controls = _FRAMEWORKS.get(framework, EU_AI_ACT_CONTROLS)
    upper = str(violation_type).upper()
    return [control["id"] for control in controls if upper in control.get("gap_categories", [])]


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


@dataclass
class ControlAssessment:
    """One control area's evidence status against the supplied artifacts."""

    control_id: str
    article: str
    title: str
    obligation: str
    status: str  # "GAP" | "PASS" | "UNVERIFIED"
    finding_count: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    notes: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the assessment."""
        return {
            "control_id": self.control_id,
            "article": self.article,
            "title": self.title,
            "status": self.status,
            "finding_count": self.finding_count,
            "findings": self.findings,
            "evidence_sources": self.evidence_sources,
            "notes": self.notes,
            "remediation": self.remediation,
        }


@dataclass
class CompliancePack:
    """The complete evidence pack: assessments, gap register, and provenance."""

    framework: str
    framework_title: str
    generated_utc: str
    target_agent: str
    assessments: list[ControlAssessment]
    gap_register: list[dict[str, Any]]
    trail_verification: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    disclaimer: str = (
        "This evidence pack documents which regulatory controls have reproducible technical "
        "evidence and where documented gaps exist. It is generated deterministically from the "
        "cited artifacts and is not legal advice or a certification of compliance."
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the pack."""
        return {
            "framework": self.framework,
            "framework_title": self.framework_title,
            "generated_utc": self.generated_utc,
            "target_agent": self.target_agent,
            "assessments": [assessment.to_dict() for assessment in self.assessments],
            "gap_register": self.gap_register,
            "trail_verification": self.trail_verification,
            "environment": self.environment,
            "disclaimer": self.disclaimer,
        }


def _utc_now(explicit: str | None = None) -> str:
    """Generation timestamp: explicit value, else SOURCE_DATE_EPOCH, else now."""
    from .report import resolve_generated_utc

    return resolve_generated_utc(explicit)


def _violation_register_source(report: dict[str, Any]) -> tuple[dict[str, int] | None, str]:
    """Pick the per-violation counts a register is built from.

    Prefers ``violation_breakdown`` (every violation type observed on any
    elite) over ``failure_mode_breakdown`` (primary category per elite only,
    which silently drops secondary violations).  Returns ``(None, reason)``
    when the report carries no usable register at all.
    """
    for key in ("violation_breakdown", "failure_mode_breakdown"):
        value = report.get(key)
        if isinstance(value, dict):
            if key == "violation_breakdown" and not value and report.get("failure_mode_breakdown"):
                # An empty full register next to a non-empty primary one is
                # inconsistent; trust the primary breakdown.
                continue
            return value, key
    return None, "missing"


def _report_claims_failures(report: dict[str, Any]) -> bool:
    """True when the report's headline metrics say failures occurred."""
    for key in ("critical_failures", "failure_rate", "evaluation_failure_rate", "failed_evaluations"):
        try:
            if float(report.get(key) or 0) > 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def verify_audit_trail(trail_path: Path | str | None) -> dict[str, Any]:
    """Verify a persisted gateway audit trail's hash chain.

    Returns a summary with the verification result. A trail that fails
    verification is itself a documented record-keeping control failure.
    """
    if trail_path is None:
        return {"provided": False, "status": "UNVERIFIED", "detail": "No audit trail supplied."}
    trail_file = Path(trail_path)
    if not trail_file.exists():
        # An empty chain is a legitimate fresh deployment; a *claimed* trail
        # that does not exist is not evidence and must not pass as one.
        return {
            "provided": True,
            "path": str(trail_path),
            "status": "UNVERIFIED",
            "detail": f"Audit trail file not found: {trail_path}",
        }
    try:
        from lifeforge.gateway import AuditTrail

        trail = AuditTrail(trail_file)
        ok, detail = trail.verify()
        summary = trail.summary()
        return {
            "provided": True,
            "path": str(trail_path),
            "status": "VERIFIED" if ok else "TAMPERED",
            "detail": detail,
            "records": summary.get("total_records", 0),
            "by_verdict": summary.get("by_verdict", {}),
            "head_digest": summary.get("head_digest", ""),
        }
    except (OSError, ValueError) as exc:
        return {"provided": True, "path": str(trail_path), "status": "UNREADABLE", "detail": str(exc)}


def build_compliance_pack(
    report: dict[str, Any],
    *,
    framework: str = FRAMEWORK_EU_AI_ACT,
    customer: str | None = None,
    trail_path: Path | str | None = None,
    environment: dict[str, Any] | None = None,
    generated_utc: str | None = None,
) -> CompliancePack:
    """Assess every control of a framework against a benchmark report.

    Controls are only assessed PASS when the report carries a violation
    register that is consistent with its headline metrics.  A report with no
    register, or an empty register while ``critical_failures`` /
    ``failure_rate`` say failures occurred, yields UNVERIFIED instead of a
    false PASS.

    Parameters
    ----------
    report:
        A benchmark report dict (``results/*_report.json``) whose
        ``failure_mode_breakdown`` supplies the violation register.
    framework:
        Currently ``"eu-ai-act"``.
    trail_path:
        Optional path to a persisted gateway audit trail (JSON lines); when
        given, its hash chain is verified as part of the record-keeping
        control.
    """
    if framework not in _FRAMEWORKS:
        raise ValueError(
            f"Unknown framework '{framework}'. Supported: {', '.join(sorted(_FRAMEWORKS))}"
        )
    controls = _FRAMEWORKS[framework]

    register_source, register_key = _violation_register_source(report)
    breakdown: dict[str, int] = register_source or {}
    findings: list[dict[str, Any]] = report.get("findings", []) or []
    register_unusable = register_source is None or (not breakdown and _report_claims_failures(report))
    if register_source is None:
        register_note = (
            "The report carries no violation register (no 'violation_breakdown' or "
            "'failure_mode_breakdown'); this control cannot be assessed from it."
        )
    else:
        register_note = (
            f"The report's '{register_key}' is empty but its headline metrics record failures; "
            "the register is inconsistent and this control cannot be assessed from it."
        )

    # Violation register: every recorded category with severity and article mapping.
    gap_register: list[dict[str, Any]] = []
    for category, count in breakdown.items():
        severity = _VIOLATION_SEVERITY.get(str(category).upper(), "MEDIUM")
        gap_register.append(
            {
                "violation_type": str(category),
                "occurrences": count,
                "severity": severity,
                "controls": classify_violation(str(category), framework),
                "worst_behavior": _finding_for_category(findings, str(category)),
            }
        )
    gap_register.sort(key=lambda item: (_SEVERITY_RANK.get(item["severity"], 4), -int(item["occurrences"] or 0)))

    trail_verification = verify_audit_trail(trail_path)

    assessments: list[ControlAssessment] = []
    for control in controls:
        mapped = [entry for entry in gap_register if control["id"] in entry["controls"]]
        notes = ""
        status = "GAP" if mapped else "PASS"
        if status == "PASS" and register_unusable and not control.get("requires_trail"):
            status = "UNVERIFIED"
            notes = register_note
        if control.get("requires_trail"):
            if not trail_verification.get("provided"):
                status = "UNVERIFIED"
                notes = "No gateway audit trail was supplied; the record-keeping control cannot be evidenced from this pack."
            elif trail_verification.get("status") != "VERIFIED":
                status = "GAP"
                notes = f"Audit trail issue: {trail_verification.get('detail', '')}"
            else:
                notes = (
                    f"Hash-chained trail verified: {trail_verification.get('records', 0)} record(s), "
                    f"head digest {str(trail_verification.get('head_digest', ''))[:16]}..."
                )

        assessments.append(
            ControlAssessment(
                control_id=control["id"],
                article=control["article"],
                title=control["title"],
                obligation=control["obligation"],
                status=status,
                finding_count=sum(int(entry["occurrences"] or 0) for entry in mapped),
                findings=[
                    {"violation_type": entry["violation_type"], "occurrences": entry["occurrences"], "severity": entry["severity"]}
                    for entry in mapped
                ],
                evidence_sources=list(control.get("evidence_sources", [])),
                notes=notes,
                remediation=control.get("remediation", ""),
            )
        )

    return CompliancePack(
        framework=framework,
        framework_title="EU AI Act (Regulation (EU) 2024/1689)",
        generated_utc=_utc_now(generated_utc),
        target_agent=str(report.get("agent_name", "unknown")),
        assessments=assessments,
        gap_register=gap_register,
        trail_verification=trail_verification,
        environment=dict(environment or {}),
    )


def _finding_for_category(findings: list[dict[str, Any]], category: str) -> str:
    """Human summary for a violation category from the report's findings."""
    for finding in findings:
        if str(finding.get("category", "")).upper() == category.upper():
            return str(finding.get("title", ""))[:160]
    return ""


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_STATUS_MARK = {"GAP": "[GAP]", "PASS": "[PASS]", "UNVERIFIED": "[UNVERIFIED]"}


def render_compliance_markdown(pack: CompliancePack, *, customer: str | None = None) -> str:
    """Render the evidence pack as a Markdown document."""
    gaps = [a for a in pack.assessments if a.status == "GAP"]
    unverified = [a for a in pack.assessments if a.status == "UNVERIFIED"]

    lines: list[str] = [
        "# Compliance Evidence Pack",
        "",
        f"**Prepared for**: {customer or 'the requesting organization'}  ",
        f"**Framework**: {pack.framework_title}  ",
        f"**Target agent**: `{pack.target_agent}`  ",
        f"**Generated**: {pack.generated_utc}",
        "",
        f"> {pack.disclaimer}",
        "",
        "---",
        "",
        "## Control Assessment Summary",
        "",
        "| Control | Status | Findings |",
        "| :--- | :--- | :--- |",
    ]
    for assessment in pack.assessments:
        lines.append(
            f"| {assessment.article} {assessment.title} "
            f"| {_STATUS_MARK.get(assessment.status, assessment.status)} "
            f"| {assessment.finding_count} |"
        )
    lines.append("")

    if gaps:
        lines.extend(
            [
                f"**{len(gaps)} control(s) have documented gaps.** "
                f"{len(unverified)} cannot be assessed from the supplied artifacts.",
                "",
            ]
        )

    # The register is evidence in its own right: render it whenever any
    # violation was recorded, even if none maps onto a framework control.
    if pack.gap_register:
        lines.extend(
            [
                "---",
                "",
                "## Gap Register",
                "",
                "| Violation | Occurrences | Severity | Controls affected |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for entry in pack.gap_register:
            lines.append(
                f"| `{entry['violation_type']}` | {entry['occurrences']} | {entry['severity']} "
                f"| {', '.join(entry['controls']) or '-'} |"
            )
        lines.append("")
        if not gaps:
            lines.extend(
                [
                    "Recorded violations above do not map onto any control of this framework; "
                    "they are listed so the register is complete.",
                    "",
                ]
            )

    if gaps:
        lines.extend(
            [
                "---",
                "",
                "## Gapped Controls in Detail",
                "",
            ]
        )
        for assessment in gaps:
            lines.extend(
                [
                    f"### {assessment.article} - {assessment.title} [{_STATUS_MARK['GAP']}]",
                    "",
                    f"**Obligation**: {assessment.obligation}",
                    "",
                    f"**Documented gaps** ({assessment.finding_count} recorded occurrence(s)):",
                    "",
                ]
            )
            for finding in assessment.findings:
                lines.append(f"- `{finding['violation_type']}` - {finding['occurrences']} occurrence(s) ({finding['severity']})")
            lines.extend(
                [
                    "",
                    f"**Evidence sources**: {', '.join(assessment.evidence_sources)}",
                    "",
                    f"**Required remediation**: {assessment.remediation}",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "No control has a documented gap from the supplied artifacts. Controls that "
                "could not be assessed are marked UNVERIFIED and need their evidence supplied.",
                "",
            ]
        )

    if unverified:
        lines.extend(["---", "", "## Unverified Controls", ""])
        for assessment in unverified:
            lines.append(f"- **{assessment.article} {assessment.title}**: {assessment.notes}")

    lines.extend(
        [
            "---",
            "",
            "## Evidence Provenance",
            "",
            "| Evidence | Detail |",
            "| :--- | :--- |",
            f"| Benchmark report | `{pack.target_agent}`, "
            f"{pack.environment.get('scenarios', 'n/a')} scenarios, seed {pack.environment.get('seed', 'n/a')} |",
            f"| Verdict determinism | Invariant policy oracle; re-running the reproduction "
            f"commands regenerates the same violation register |",
            f"| Audit trail | {pack.trail_verification.get('status', 'not supplied')} "
            f"({pack.trail_verification.get('records', 0)} record(s)) |",
            "",
            "See `reproduction_commands.sh` in the audit bundle for the exact re-run commands.",
            "",
            "---",
            "",
            "*Generated by LIFE FORGE - The Autonomous Flight Simulator for AI Agents. "
            "Deterministic evidence, not a legal opinion.*",
            "",
        ]
    )
    return "\n".join(lines)


def write_compliance_pack(
    report: dict[str, Any],
    output_path: Path | str,
    *,
    framework: str = FRAMEWORK_EU_AI_ACT,
    customer: str | None = None,
    trail_path: Path | str | None = None,
    environment: dict[str, Any] | None = None,
    generated_utc: str | None = None,
) -> tuple[Path, Path]:
    """Write the evidence pack as Markdown + JSON; returns (markdown, json) paths.

    Pass ``generated_utc`` (or set ``SOURCE_DATE_EPOCH``) to make both files
    byte-reproducible; otherwise the current time is stamped.
    """
    pack = build_compliance_pack(
        report,
        framework=framework,
        customer=customer,
        trail_path=trail_path,
        environment=environment,
        generated_utc=generated_utc,
    )
    md_path = Path(output_path)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_compliance_markdown(pack, customer=customer), encoding="utf-8")
    json_path = md_path.with_suffix(".json")
    json_path.write_text(json.dumps(pack.to_dict(), indent=2, default=str), encoding="utf-8")
    return md_path, json_path
