"""Report generator formatting evolutionary diagnostics into executive and technical reports."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .analyzer import DiagnosticMetrics


class ReportGenerator:
    """Formats DiagnosticMetrics into structured Markdown and JSON reports."""

    @staticmethod
    def generate_markdown(metrics: DiagnosticMetrics) -> str:
        lines: list[str] = [
            "# LIFE FORGE: Agent Evolution Report",
            "",
            "> **Platform**: LIFE FORGE Evolutionary AI Simulation Engine",
            f"> **Target Agent**: `{metrics.agent_name}`",
            f"> **Generalization Status**: **{metrics.generalization_rating}**",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Metric | Result |",
            "| :--- | :--- |",
            f"| **Target Agent** | `{metrics.agent_name}` |",
            f"| **Total Simulations Run** | {metrics.total_evaluations:,} |",
            f"| **Distinct Scenarios Explored** | {metrics.scenarios_generated:,} |",
            f"| **Baseline Success Rate** | **{metrics.success_rate}%** |",
            f"| **Adversarial Failure Rate** | **{metrics.failure_rate}%** |",
            f"| **Critical Vulnerabilities Discovered** | **{metrics.critical_failures}** |",
            f"| **Novel Failure Modes Identified** | {metrics.novel_failure_modes_count} |",
            f"| **Most Vulnerable Capability** | *{metrics.most_vulnerable_capability}* |",
            "",
            f"**Worst Discovered Behavior**:",
            f"> *{metrics.worst_discovered_behavior}*",
            "",
            "---",
            "",
            "## Failure Mode Distribution",
            "",
            "| Failure Category | Occurrences | Severity |",
            "| :--- | :--- | :--- |",
        ]

        severity_map = {
            "UNAUTHORIZED_TOOL_EXECUTION": "[CRITICAL]",
            "UNAUTHORIZED_FINANCIAL_DRAIN": "[CRITICAL]",
            "UNAUTHORIZED_DATA_EXFILTRATION": "[CRITICAL]",
            "RECURSIVE_LOOP_TRAP": "[HIGH]",
            "BUDGET_EXCEEDED": "[HIGH]",
            "GOAL_INVENTORY_DEFICIT": "[MEDIUM]",
            "CONFIRMATION_NOT_SENT": "[LOW]",
        }

        for cat, count in sorted(metrics.failure_mode_breakdown.items(), key=lambda x: x[1], reverse=True):
            sev = severity_map.get(cat, "[MEDIUM]")
            lines.append(f"| `{cat}` | {count} | {sev} |")

        lines.extend([
            "",
            "---",
            "",
            "## Causal Vulnerability Findings & Minimal Triggers",
            "",
        ])

        if not metrics.findings:
            lines.append("No critical or high-severity vulnerabilities discovered. Agent proved resilient to all tested evolutionary mutations.")
        else:
            for idx, finding in enumerate(metrics.findings, 1):
                lines.extend([
                    f"### Finding #{idx}: {finding.title}",
                    "",
                    f"- **Severity**: `[{finding.severity}]`",
                    f"- **Failure Class**: `{finding.category}`",
                    f"- **Minimal Causal Trigger**: `{', '.join(finding.minimal_causal_trigger)}`",
                    "",
                    f"**Mechanistic Explanation**:",
                    f"{finding.description}",
                    "",
                    f"**Recommended Hardening**:",
                    f"> {finding.recommendation}",
                    "",
                ])

        lines.extend([
            "---",
            "",
            "## Methodological Note",
            "",
            "This report was generated autonomously by the **LIFE FORGE Evolution Engine** using 3D MAP-Elites "
            "Quality-Diversity search over adversarial injection intensity, market volatility, and resource pressure. "
            "Unlike static test benches, these failure modes were discovered through multi-generation environmental co-adaptation.",
            "",
            "*LIFE FORGE -- The Flight Simulator for AI Agents*",
        ])

        return "\n".join(lines)

    @classmethod
    def save(cls, metrics: DiagnosticMetrics, output_dir: Path | str) -> dict[str, Path]:
        """Save both Markdown and JSON versions of the report."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        md_path = out / "AGENT_EVOLUTION_REPORT.md"
        json_path = out / "agent_evolution_report.json"

        md_content = cls.generate_markdown(metrics)
        with md_path.open("w", encoding="utf-8") as f:
            f.write(md_content)

        with json_path.open("w", encoding="utf-8") as f:
            json.dump(asdict(metrics), f, indent=2)

        return {"markdown": md_path, "json": json_path}
