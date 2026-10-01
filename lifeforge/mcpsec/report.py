"""Scan reports: risk scoring and Markdown/JSON rendering for MCP scans.

Scoring uses the same severity weights as the audit bundle so a scanner report
and an audit report produce comparable numbers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .detectors import McpFinding, RULESET_VERSION

#: Severity weights for the 0-100 risk score, matching lifeforge.reporting.audit.
_SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2}


def compute_scan_score(findings: list[McpFinding]) -> tuple[int, str]:
    """Return (score 0-100, band) for a set of scan findings.

    Weighted by severity, floored at 80 when any critical finding exists (a
    poisoned tool description cannot be averaged away), and banded LOW /
    MODERATE / HIGH / CRITICAL.
    """
    score = 0
    for finding in findings:
        score += _SEVERITY_WEIGHTS.get(finding.severity, 2)
    if any(finding.severity == "CRITICAL" for finding in findings):
        score = max(score, 80)
    score = max(0, min(100, score))

    if score >= 80:
        band = "CRITICAL"
    elif score >= 50:
        band = "HIGH"
    elif score >= 20:
        band = "MODERATE"
    else:
        band = "LOW"
    return score, band


@dataclass
class McpScanReport:
    """Complete result of one MCP security scan."""

    target: str
    target_kind: str  # "manifest" | "server"
    findings: list[McpFinding] = field(default_factory=list)
    tool_count: int = 0
    server_info: dict[str, Any] = field(default_factory=dict)
    protocol_version: str = ""
    servers: list[str] = field(default_factory=list)
    generated_utc: str = ""
    ruleset_version: str = RULESET_VERSION
    drift_observations: int = 0

    def __post_init__(self) -> None:
        if not self.generated_utc:
            self.generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.findings = sorted(self.findings, key=McpFinding.sort_key)

    @property
    def score(self) -> int:
        """Risk score in 0-100."""
        return compute_scan_score(self.findings)[0]

    @property
    def band(self) -> str:
        """Risk band: LOW / MODERATE / HIGH / CRITICAL."""
        return compute_scan_score(self.findings)[1]

    def counts_by_severity(self) -> dict[str, int]:
        """Finding counts per severity."""
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def has_critical(self) -> bool:
        """True when at least one CRITICAL finding exists (CI gate signal)."""
        return any(finding.severity == "CRITICAL" for finding in self.findings)

    def to_json(self) -> str:
        """Serialize the report as pretty-printed JSON."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Machine-readable report shape."""
        score, band = compute_scan_score(self.findings)
        return {
            "target": self.target,
            "target_kind": self.target_kind,
            "generated_utc": self.generated_utc,
            "ruleset_version": self.ruleset_version,
            "tool_count": self.tool_count,
            "servers": self.servers,
            "server_info": self.server_info,
            "protocol_version": self.protocol_version,
            "drift_observations": self.drift_observations,
            "risk_score": score,
            "risk_band": band,
            "counts_by_severity": self.counts_by_severity(),
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_markdown(self) -> str:
        """Human-readable Markdown report."""
        score, band = compute_scan_score(self.findings)
        counts = self.counts_by_severity()
        lines: list[str] = [
            "# MCP Security Scan Report",
            "",
            f"**Target**: `{self.target}` ({self.target_kind})  ",
            f"**Generated**: {self.generated_utc}  ",
            f"**Ruleset**: v{self.ruleset_version}",
            "",
            "---",
            "",
            "## Risk Posture",
            "",
            f"**Risk score: {score}/100 ({band})**",
            "",
            "| Measure | Result |",
            "| :--- | :--- |",
            f"| Tools scanned | {self.tool_count} |",
            f"| Servers | {', '.join(self.servers) or 'n/a'} |",
            f"| Protocol version | {self.protocol_version or 'n/a'} |",
            f"| Drift observations | {self.drift_observations} |",
            f"| Critical findings | {counts['CRITICAL']} |",
            f"| High findings | {counts['HIGH']} |",
            f"| Medium findings | {counts['MEDIUM']} |",
            f"| Low findings | {counts['LOW']} |",
            "",
        ]

        if self.server_info:
            lines.extend(
                [
                    "## Server Identity",
                    "",
                    "| Field | Value |",
                    "| :--- | :--- |",
                ]
            )
            for key in sorted(self.server_info):
                lines.append(f"| {key} | `{self.server_info.get(key)}` |")
            lines.append("")

        lines.extend(
            [
                "---",
                "",
                "## Findings",
                "",
            ]
        )

        if not self.findings:
            lines.append("No findings. The scanned definitions passed every rule in this ruleset.")
        else:
            lines.extend(
                [
                    "| Severity | Rule | Tool | Finding |",
                    "| :--- | :--- | :--- | :--- |",
                ]
            )
            for finding in self.findings:
                title = finding.title.replace("|", "\\|")
                lines.append(
                    f"| `{finding.severity}` | `{finding.rule_id}` | `{finding.tool}` | {title} |"
                )
            lines.append("")

            for index, finding in enumerate(self.findings, start=1):
                lines.extend(
                    [
                        f"### Finding {index}: {finding.title}",
                        "",
                        f"- **Severity**: `{finding.severity}`",
                        f"- **Rule**: `{finding.rule_id}`",
                        f"- **Tool**: `{finding.tool}` (server: `{finding.server}`)",
                        "",
                        finding.description,
                        "",
                    ]
                )
                if finding.evidence:
                    lines.extend(["**Evidence**", "", "```json", json.dumps(finding.evidence, indent=2, default=str)[:2000], "```", ""])
                if finding.remediation:
                    lines.extend(["**Remediation**", "", finding.remediation, ""])

        lines.extend(
            [
                "---",
                "",
                "## Method",
                "",
                "Findings are produced by deterministic, versioned detectors over the tool "
                "definitions exactly as an MCP client receives them. Re-running the scan against "
                "the same definitions reproduces the same findings byte for byte.",
                "",
                "*Generated by LIFE FORGE mcpsec - The Autonomous Flight Simulator for AI Agents*",
                "",
            ]
        )
        return "\n".join(lines)


def build_report(
    *,
    target: str,
    target_kind: str,
    findings: list[McpFinding],
    manifest: Any | None = None,
    drift_observations: int = 0,
) -> McpScanReport:
    """Assemble a report from scan outputs."""
    return McpScanReport(
        target=target,
        target_kind=target_kind,
        findings=findings,
        tool_count=len(manifest.tools) if manifest is not None else 0,
        server_info=dict(getattr(manifest, "server_info", {}) or {}),
        protocol_version=getattr(manifest, "protocol_version", "") or "",
        servers=manifest.server_names() if manifest is not None else [],
        drift_observations=drift_observations,
    )
