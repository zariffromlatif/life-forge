"""MCP security scanner: static analysis, live probing, and rug-pull detection.

Public API
----------
- :func:`scan_manifest` - scan a JSON manifest file (static ruleset).
- :func:`scan_tools` - scan in-memory tool definitions.
- :func:`scan_server` - connect to a live MCP server (stdio command or HTTP
  URL), analyze its published definitions, and detect drift across fetches.
- :class:`McpFinding`, :class:`McpScanReport` - result types.

The scanner never executes tools on a live server; it observes definitions
and, optionally, exercises one named tool when explicitly requested.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .detectors import (
    McpFinding,
    RULESET_VERSION,
    detect_drift,
    scan_tools,
)
from .manifest import McpServerManifest, McpToolDefinition, manifest_from_file
from .probe import (
    DEFAULT_TIMEOUT,
    HttpMcpTransport,
    InProcessMcpTransport,
    McpClient,
    McpProbeError,
    McpTransport,
    StdioMcpTransport,
    probe_server_manifest,
)
from .report import McpScanReport, build_report, compute_scan_score

__all__ = [
    "scan_manifest",
    "scan_tools",
    "scan_server",
    "scan_tool_definitions",
    "McpFinding",
    "McpScanReport",
    "McpServerManifest",
    "McpToolDefinition",
    "McpProbeError",
    "McpTransport",
    "StdioMcpTransport",
    "HttpMcpTransport",
    "InProcessMcpTransport",
    "McpClient",
    "DEFAULT_TIMEOUT",
    "RULESET_VERSION",
    "compute_scan_score",
    "manifest_from_file",
]


def scan_manifest(path: Path | str, *, baseline_path: Path | str | None = None) -> McpScanReport:
    """Run the static ruleset against a manifest file.

    Multi-server manifests (``{"servers": {...}}``) additionally get
    cross-server tool-shadowing analysis. When ``baseline_path`` names an
    approved manifest, drift detection runs against it - the rug-pull check
    for definitions checked into source control.
    """
    manifest = manifest_from_file(path)
    findings = scan_tools(manifest.tools, include_shadowing=True)
    drift_observations = 0

    if baseline_path is not None:
        baseline = manifest_from_file(baseline_path)
        findings.extend(detect_drift(baseline.tools, manifest.tools))
        # Approved definitions can still carry poisoning that predates approval.
        findings.extend(scan_tools(baseline.tools, include_shadowing=True))
        drift_observations = 2
        findings = _dedupe_findings(findings)

    report = build_report(target=str(path), target_kind="manifest", findings=findings, manifest=manifest)
    report.drift_observations = drift_observations
    return report


def scan_tool_definitions(tools: list[McpToolDefinition], *, source: str = "in-memory") -> McpScanReport:
    """Run the static ruleset against already-loaded tool definitions."""
    findings = scan_tools(tools, include_shadowing=True)
    return build_report(
        target=source,
        target_kind="manifest",
        findings=findings,
        manifest=McpServerManifest(tools=tools, source=source),
    )


def _dedupe_findings(findings: list[McpFinding]) -> list[McpFinding]:
    """Drop findings that a second observation reproduced identically."""
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[McpFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.tool, finding.server, finding.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def scan_server(
    target: str,
    *,
    kind: str = "stdio",
    baseline_path: Path | str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    drift_delay_seconds: float = 0.0,
) -> McpScanReport:
    """Connect to a live MCP server, analyze its tools, and check for drift.

    Parameters
    ----------
    target:
        A command line to launch (``kind="stdio"``, e.g.
        ``"python my_mcp_server.py"``) or an HTTP URL (``kind="http"``).
    baseline_path:
        Optional approved manifest to diff against - the rug-pull check.
        Without it, drift is measured between two live fetches.
    timeout:
        Per-request timeout in seconds.
    drift_delay_seconds:
        Delay between the two live fetches, widening the drift window.

    Raises
    ------
    McpProbeError
        When the server cannot be reached or the handshake fails.
    """
    if kind == "stdio":
        transport: Any = StdioMcpTransport(target)
    elif kind == "http":
        transport = HttpMcpTransport(target)
    elif kind == "in-process":
        transport = target
    else:
        raise ValueError(f"Unknown server kind '{kind}': use stdio, http, or in-process.")

    manifest, tools_again = probe_server_manifest(
        transport,
        timeout=timeout,
        drift_delay_seconds=drift_delay_seconds,
    )

    findings = scan_tools(manifest.tools, include_shadowing=False)

    if baseline_path is not None:
        baseline = manifest_from_file(baseline_path)
        findings.extend(detect_drift(baseline.tools, manifest.tools))
        drift_observations = 2
        # The baseline definitions were approved, but scan them too: an
        # approved set can still carry poisoning that predates the approval.
        findings.extend(scan_tools(baseline.tools, include_shadowing=False))
    elif tools_again:
        # Rug-pull detection plus a full static pass over BOTH observations -
        # a server that mutates its definitions between fetches must have the
        # mutated definitions scanned, not merely diffed.
        findings.extend(scan_tools(tools_again, include_shadowing=False))
        findings.extend(detect_drift(tools_again, manifest.tools) + detect_drift(manifest.tools, tools_again))
        drift_observations = 2
    else:
        drift_observations = 1

    findings = _dedupe_findings(findings)

    return build_report(
        target=target if kind != "in-process" else getattr(manifest, "source", "in-process"),
        target_kind="server",
        findings=findings,
        manifest=manifest,
        drift_observations=drift_observations,
    )
