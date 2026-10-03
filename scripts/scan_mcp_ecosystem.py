"""Scan the public MCP server ecosystem with the LIFE FORGE mcpsec scanner.

Methodology (stated honestly in every artifact this produces):

* **live-stdio** targets are real published servers, launched exactly as a
  client launches them (npx/uvx) and probed over the MCP protocol. Their tool
  definitions are read straight off the wire - the strongest evidence.
* **static-source** targets are popular servers that refuse to launch without
  API credentials. Their definitions are extracted from source with
  ``lifeforge.mcpsec.extract`` (best-effort, counters recorded).

The scanner never executes tools on any target. Outputs:

* ``<results>/reports/<name>.json``  - per-server report or launch failure
* ``<results>/summary.json``         - aggregate dataset
* ``results/MCP_ECOSYSTEM_SCAN.md``  - the publishable report

Usage::

    python scripts/scan_mcp_ecosystem.py                # everything
    python scripts/scan_mcp_ecosystem.py --live-only
    python scripts/scan_mcp_ecosystem.py --targets everything,filesystem
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from lifeforge.mcpsec import (  # noqa: E402
    McpProbeError,
    scan_server,
    scan_tool_definitions,
)
from lifeforge.mcpsec.extract import extract_from_directory  # noqa: E402


def _npx() -> str:
    """Resolve the npx launcher (Windows needs the .cmd suffix)."""
    for candidate in ("npx", "npx.cmd"):
        try:
            subprocess.run([candidate, "--version"], capture_output=True, timeout=30)
            return candidate
        except (OSError, subprocess.TimeoutExpired):
            continue
    return "npx"


@dataclass
class Target:
    """One MCP server to scan, live or statically."""

    name: str
    method: str  # "live-stdio" | "static-source"
    source: str  # package spec or repository URL
    note: str = ""
    command: str = ""  # live-stdio launch command
    repo: str = ""  # static-source repository
    subdir: str = ""
    language: str | None = None  # static-source extractor hint


def build_targets() -> list[Target]:
    """The curated target list: official reference servers plus the popular
    community servers that recur across 2026 buyer guides and directories."""
    npx = _npx()
    scratch = Path(tempfile.gettempdir()) / "lf_mcp_ecosystem"
    scratch.mkdir(parents=True, exist_ok=True)
    empty_db = scratch / "scan.db"
    if not empty_db.exists():
        import sqlite3

        sqlite3.connect(empty_db).close()

    return [
        # --- Official reference servers (live) ---
        Target("everything", "live-stdio", "@modelcontextprotocol/server-everything",
               command=f"{npx} -y @modelcontextprotocol/server-everything",
               note="Official reference/test server."),
        Target("filesystem", "live-stdio", "@modelcontextprotocol/server-filesystem",
               command=f"{npx} -y @modelcontextprotocol/server-filesystem {scratch.as_posix()}",
               note="Official; among the most-installed MCP servers."),
        Target("memory", "live-stdio", "@modelcontextprotocol/server-memory",
               command=f"{npx} -y @modelcontextprotocol/server-memory",
               note="Official knowledge-graph memory server."),
        Target("sequential-thinking", "live-stdio", "@modelcontextprotocol/server-sequential-thinking",
               command=f"{npx} -y @modelcontextprotocol/server-sequential-thinking",
               note="Official dynamic reflective-thinking server."),
        Target("server-time", "live-stdio", "mcp-server-time (PyPI)",
               command="uvx mcp-server-time",
               note="Official Python time/timezone server."),
        Target("server-fetch", "live-stdio", "mcp-server-fetch (PyPI)",
               command="uvx mcp-server-fetch",
               note="Official Python web-fetch server."),
        Target("server-git", "live-stdio", "mcp-server-git (PyPI)",
               command=f"uvx mcp-server-git --repository {REPO_ROOT.as_posix()}",
               note="Official Python git server."),
        Target("server-sqlite", "live-stdio", "mcp-server-sqlite (PyPI)",
               command=f"uvx mcp-server-sqlite --db-path {empty_db.as_posix()}",
               note="Official Python SQLite server (archived reference)."),
        # --- Popular community servers (live, no credentials required) ---
        Target("context7", "live-stdio", "@upstash/context7-mcp",
               command=f"{npx} -y @upstash/context7-mcp",
               note="Upstash docs-retrieval server; a top-directory fixture."),
        Target("desktop-commander", "live-stdio", "@wonderwhy-er/desktop-commander",
               command=f"{npx} -y @wonderwhy-er/desktop-commander",
               note="File/terminal control server; top-directory fixture."),
        Target("playwright", "live-stdio", "@playwright/mcp",
               command=f"{npx} -y @playwright/mcp@latest",
               note="Microsoft browser-automation server."),
        # --- Popular credential-gated servers (static source) ---
        Target("github", "static-source", "modelcontextprotocol/servers-archived",
               repo="https://github.com/modelcontextprotocol/servers-archived.git",
               subdir="src/github", language="typescript",
               note="Official GitHub server; requires a token to launch."),
        Target("slack", "static-source", "modelcontextprotocol/servers-archived",
               repo="https://github.com/modelcontextprotocol/servers-archived.git",
               subdir="src/slack", language="typescript",
               note="Official Slack server; requires a bot token."),
        Target("brave-search", "static-source", "modelcontextprotocol/servers-archived",
               repo="https://github.com/modelcontextprotocol/servers-archived.git",
               subdir="src/brave-search", language="typescript",
               note="Official web-search server; requires an API key."),
        Target("google-maps", "static-source", "modelcontextprotocol/servers-archived",
               repo="https://github.com/modelcontextprotocol/servers-archived.git",
               subdir="src/google-maps", language="typescript",
               note="Official maps server; requires an API key."),
        Target("firecrawl", "static-source", "firecrawl/firecrawl-mcp-server",
               repo="https://github.com/firecrawl/firecrawl-mcp-server.git",
               subdir="src", language="typescript",
               note="Popular web-scraping server; requires an API key."),
    ]


def scan_live(target: Target, timeout: float) -> dict:
    """Probe one live server and return the report dict (or a launch failure)."""
    try:
        report = scan_server(target.command, kind="stdio", timeout=timeout)
        return {"target": target.__dict__, "status": "scanned", "report": report.to_dict()}
    except McpProbeError as exc:
        return {"target": target.__dict__, "status": "launch_failed", "error": str(exc)}
    except Exception as exc:  # unexpected scanner crash on one target must not kill the batch
        return {"target": target.__dict__, "status": "scan_error", "error": f"{type(exc).__name__}: {exc}"}


def clone_repo(repo: str, work_dir: Path) -> Path:
    """Shallow-clone a repository once into the work directory."""
    dest = work_dir / repo.rstrip(".git").split("/")[-1].replace(".git", "")
    dest = work_dir / repo.split("/")[-1].removesuffix(".git")
    if dest.exists():
        return dest
    subprocess.run(
        ["git", "clone", "--depth", "1", repo, str(dest)],
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return dest


def scan_static(target: Target, work_dir: Path) -> dict:
    """Extract definitions from source and scan them."""
    try:
        repo_dir = clone_repo(target.repo, work_dir)
        tools, stats = extract_from_directory(repo_dir, subdir=target.subdir, language=target.language)
        report = scan_tool_definitions(tools, source=f"{target.repo}#{target.subdir}")
        data = report.to_dict()
        data["extraction"] = {
            **stats.to_dict(),
            "tools_extracted": len(tools),
            "language": target.language or "auto",
        }
        return {"target": target.__dict__, "status": "scanned", "report": data}
    except Exception as exc:
        return {"target": target.__dict__, "status": "scan_error", "error": f"{type(exc).__name__}: {exc}"}


def aggregate(records: list[dict]) -> dict:
    """Aggregate per-server records into the ecosystem dataset (pure function)."""
    scanned = [r for r in records if r.get("status") == "scanned"]
    failed = [r for r in records if r.get("status") != "scanned"]

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_rule: dict[str, int] = {}
    servers_with_critical_findings: list[str] = []
    servers_band_critical: list[str] = []
    total_tools = 0

    for record in scanned:
        report = record["report"]
        name = record["target"]["name"]
        counts = report.get("counts_by_severity", {}) or {}
        for severity, count in counts.items():
            by_severity[severity] = by_severity.get(severity, 0) + int(count or 0)
        for finding in report.get("findings", []):
            rule = finding.get("rule_id", "?")
            by_rule[rule] = by_rule.get(rule, 0) + 1
        if counts.get("CRITICAL", 0) > 0:
            servers_with_critical_findings.append(name)
        if report.get("risk_band") == "CRITICAL":
            servers_band_critical.append(name)
        total_tools += int(report.get("tool_count", 0) or 0)

    scanned_count = len(scanned)
    return {
        "targets_total": len(records),
        "servers_scanned": scanned_count,
        "launch_failed": [r["target"]["name"] for r in failed if r.get("status") == "launch_failed"],
        "scan_errors": [r["target"]["name"] for r in failed if r.get("status") == "scan_error"],
        "total_tools": total_tools,
        "findings_by_severity": by_severity,
        "findings_by_rule": dict(sorted(by_rule.items(), key=lambda item: -item[1])),
        "servers_with_critical_findings": servers_with_critical_findings,
        "servers_band_critical": servers_band_critical,
        "pct_servers_band_critical": round(100.0 * len(servers_band_critical) / scanned_count, 1) if scanned_count else 0.0,
        "pct_servers_with_findings": round(
            100.0 * sum(1 for r in scanned if sum((r["report"].get("counts_by_severity") or {}).values()) > 0) / scanned_count,
            1,
        ) if scanned_count else 0.0,
    }


def render_markdown(summary: dict, records: list[dict], generated_utc: str) -> str:
    """Render the publishable ecosystem report."""
    lines = [
        "# MCP Ecosystem Security Scan",
        "",
        f"**Generated**: {generated_utc}  ",
        f"**Scanner**: LIFE FORGE mcpsec v{__import__('lifeforge.mcpsec', fromlist=['RULESET_VERSION']).RULESET_VERSION} "
        "(deterministic ruleset; findings reproduce byte for byte)",
        f"**Method**: live protocol probes (stdio, definitions read off the wire) for servers "
        f"launchable without credentials; static source extraction for popular credential-gated "
        f"servers. The scanner observes definitions only - it never executes tools.",
        "",
        "---",
        "",
        "## Headline Numbers",
        "",
        f"- **{summary['servers_scanned']}** of {summary['targets_total']} targeted servers scanned "
        f"({len(summary['launch_failed'])} not launchable without credentials, "
        f"{len(summary['scan_errors'])} scan errors)",
        f"- **{summary['total_tools']}** tool definitions analyzed",
        f"- **{summary['pct_servers_with_findings']}%** of scanned servers carry at least one finding",
        f"- **{summary['pct_servers_band_critical']}%** of scanned servers score in the CRITICAL band "
        f"({', '.join('`' + name + '`' for name in summary['servers_band_critical']) or 'none'})",
        f"- Findings by severity: "
        f"**{summary['findings_by_severity']['CRITICAL']} CRITICAL** / "
        f"{summary['findings_by_severity']['HIGH']} HIGH / "
        f"{summary['findings_by_severity']['MEDIUM']} MEDIUM / "
        f"{summary['findings_by_severity']['LOW']} LOW",
        "",
        "Context: an industry scan reported 33% of MCP servers with critical vulnerabilities "
        "(Practical DevSecOps, 2026). This scan runs an independent, reproducible ruleset and "
        "publishes every raw report.",
        "",
        "---",
        "",
        "## Findings by Rule",
        "",
        "| Rule | Occurrences |",
        "| :--- | :--- |",
    ]
    for rule, count in summary["findings_by_rule"].items():
        lines.append(f"| `{rule}` | {count} |")
    if not summary["findings_by_rule"]:
        lines.append("| (none) | 0 |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Per-Server Results",
            "",
            "| Server | Source | Method | Tools | Score | Band | C/H/M/L |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for record in records:
        name = record["target"]["name"]
        if record["status"] != "scanned":
            status = "not launchable" if record["status"] == "launch_failed" else "scan error"
            lines.append(f"| `{name}` | {record['target']['source']} | {record['target']['method']} | - | - | {status} | - |")
            continue
        report = record["report"]
        counts = report.get("counts_by_severity", {}) or {}
        lines.append(
            f"| `{name}` | {record['target']['source']} | {record['target']['method']} "
            f"| {report.get('tool_count', 0)} | {report.get('risk_score')} | {report.get('risk_band')} "
            f"| {counts.get('CRITICAL', 0)}/{counts.get('HIGH', 0)}/{counts.get('MEDIUM', 0)}/{counts.get('LOW', 0)} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## Notable Findings",
            "",
        ]
    )
    notable = []
    for record in records:
        if record["status"] != "scanned":
            continue
        for finding in record["report"].get("findings", []):
            if finding.get("severity") in ("CRITICAL", "HIGH"):
                notable.append((record["target"]["name"], finding))
    notable.sort(key=lambda item: {"CRITICAL": 0, "HIGH": 1}.get(item[1]["severity"], 2))
    if not notable:
        lines.append("No critical or high findings were recorded.")
    else:
        for server, finding in notable[:25]:
            lines.append(
                f"- **`{server}`** `{finding['rule_id']}` ({finding['severity']}): "
                f"{finding['title']} - tool `{finding['tool']}`"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "## Methodology & Limitations",
            "",
            "1. Live probes launch each published package exactly as a client would "
            "(`npx -y <package>` / `uvx <package>`) and read `tools/list` off the wire after a "
            "full MCP handshake. Nothing is executed on the target beyond protocol-level "
            "requests.",
            "2. Static extraction recovers definitions from source with known registration "
            "patterns (`server.tool`, `registerTool`, FastMCP `@mcp.tool`); extraction "
            "counters are recorded per server, and servers where no pattern matched are "
            "reported as such rather than silently dropped.",
            "3. Findings are deterministic: re-running the scan against the same server "
            "versions reproduces every result. Per-server raw reports ship alongside this "
            "document in `results/mcp_ecosystem_scan/reports/`.",
            "4. Severity reflects *attack surface present in tool definitions*, not a proven "
            "exploit chain: a CRITICAL here means an attacker-controlled channel or an "
            "unconstrained destructive capability exists in the definition itself.",
            "5. The destructive-tool heuristic matches verbs in tool names and descriptions. "
            "It deliberately over-approximates: a read tool whose description mentions "
            "execution can be flagged HIGH. Every finding lists its evidence; maintainers "
            "reviewing their own tools should read the rule as 'this capability exists "
            "without an authorization surface', and open an issue if a flag is wrong.",
            "6. **Live probing executes the server's startup code.** The scanner never calls "
            "tools on a target, but launching a published package runs whatever its startup "
            "performs - observed directly during this scan, when Desktop Commander's "
            "first-run flow opened its onboarding page in the analyst's browser, attributing "
            "the visit via utm_source=lifeforge-mcpsec read from the MCP initialize "
            "handshake. Treat probe targets as untrusted and run them sandboxed.",
            "7. This scan covers a curated set of high-adoption servers, not the full "
            "ecosystem registry; percentages are for this cohort.",
            "---",
            "",
            "*Scan performed with [LIFE FORGE](https://github.com/zariffromlatif/life-forge) "
            "(`lifeforge mcp-scan`), MIT License. Run it on your own servers before someone "
            "else does.*",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan the public MCP server ecosystem.")
    parser.add_argument("--live-only", action="store_true")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--targets", type=str, default=None, help="Comma-separated target names")
    parser.add_argument("--timeout", type=float, default=90.0, help="Per-request probe timeout in seconds")
    parser.add_argument("--work-dir", type=str, default=None, help="Directory for static clones")
    parser.add_argument("--results-dir", type=str, default=str(REPO_ROOT / "results" / "mcp_ecosystem_scan"))
    args = parser.parse_args(argv)

    targets = build_targets()
    if args.targets:
        wanted = {name.strip() for name in args.targets.split(",")}
        targets = [target for target in targets if target.name in wanted]
    if args.live_only:
        targets = [target for target in targets if target.method == "live-stdio"]
    if args.static_only:
        targets = [target for target in targets if target.method == "static-source"]

    results_dir = Path(args.results_dir)
    reports_dir = results_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(args.work_dir) if args.work_dir else Path(tempfile.gettempdir()) / "lf_mcp_ecosystem" / "repos"
    work_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for index, target in enumerate(targets, start=1):
        print(f"[{index}/{len(targets)}] {target.name} ({target.method}) ...", flush=True)
        if target.method == "live-stdio":
            record = scan_live(target, args.timeout)
        else:
            record = scan_static(target, work_dir)
        status = record["status"]
        detail = ""
        if status == "scanned":
            report = record["report"]
            detail = f"score {report['risk_score']} ({report['risk_band']}), {report['tool_count']} tools"
        else:
            detail = record.get("error", "")[:100]
        print(f"    -> {status}: {detail}", flush=True)
        (reports_dir / f"{target.name}.json").write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        records.append(record)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = aggregate(records)
    (results_dir / "summary.json").write_text(
        json.dumps({"generated_utc": generated, "summary": summary, "records": records}, indent=2, default=str),
        encoding="utf-8",
    )

    report_path = REPO_ROOT / "results" / "MCP_ECOSYSTEM_SCAN.md"
    report_path.write_text(render_markdown(summary, records, generated), encoding="utf-8")
    print(f"\n[OK] Summary: {results_dir / 'summary.json'}")
    print(f"[OK] Report:  {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
