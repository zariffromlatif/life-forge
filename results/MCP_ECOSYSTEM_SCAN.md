# MCP Ecosystem Security Scan

**Generated**: 2026-10-03 12:52 UTC  
**Scanner**: LIFE FORGE mcpsec v1.0.0 (deterministic ruleset; findings reproduce byte for byte)
**Method**: live protocol probes (stdio, definitions read off the wire) for servers launchable without credentials; static source extraction for popular credential-gated servers. The scanner observes definitions only - it never executes tools.

---

## Headline Numbers

- **1** of 1 targeted servers scanned (0 not launchable without credentials, 0 scan errors)
- **14** tool definitions analyzed
- **100.0%** of scanned servers carry at least one finding
- **100.0%** of scanned servers score in the CRITICAL band (`filesystem`)
- Findings by severity: **0 CRITICAL** / 1 HIGH / 14 MEDIUM / 0 LOW

Context: an industry scan reported 33% of MCP servers with critical vulnerabilities (Practical DevSecOps, 2026). This scan runs an independent, reproducible ruleset and publishes every raw report.

---

## Findings by Rule

| Rule | Occurrences |
| :--- | :--- |
| `MCP_UNBOUNDED_PARAMETER` | 14 |
| `MCP_DESTRUCTIVE_UNCONSTRAINED` | 1 |

---

## Per-Server Results

| Server | Source | Method | Tools | Score | Band | C/H/M/L |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `filesystem` | @modelcontextprotocol/server-filesystem | live-stdio | 14 | 82 | CRITICAL | 0/1/14/0 |

---

## Notable Findings

- **`filesystem`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `write_file`

---

## Methodology & Limitations

1. Live probes launch each published package exactly as a client would (`npx -y <package>` / `uvx <package>`) and read `tools/list` off the wire after a full MCP handshake. Nothing is executed on the target beyond protocol-level requests.
2. Static extraction recovers definitions from source with known registration patterns (`server.tool`, `registerTool`, FastMCP `@mcp.tool`); extraction counters are recorded per server, and servers where no pattern matched are reported as such rather than silently dropped.
3. Findings are deterministic: re-running the scan against the same server versions reproduces every result. Per-server raw reports ship alongside this document in `results/mcp_ecosystem_scan/reports/`.
4. Severity reflects *attack surface present in tool definitions*, not a proven exploit chain: a CRITICAL here means an attacker-controlled channel or an unconstrained destructive capability exists in the definition itself.
5. The destructive-tool heuristic matches verbs in tool names and descriptions. It deliberately over-approximates: a read tool whose description mentions execution can be flagged HIGH. Every finding lists its evidence; maintainers reviewing their own tools should read the rule as 'this capability exists without an authorization surface', and open an issue if a flag is wrong.
6. **Live probing executes the server's startup code.** The scanner never calls tools on a target, but launching a published package runs whatever its startup performs - observed directly during this scan, when Desktop Commander's first-run flow opened its onboarding page in the analyst's browser, attributing the visit via utm_source=lifeforge-mcpsec read from the MCP initialize handshake. Treat probe targets as untrusted and run them sandboxed.
7. This scan covers a curated set of high-adoption servers, not the full ecosystem registry; percentages are for this cohort.

---

## Maintainer Engagement & Disclosure Status

In accordance with responsible disclosure principles, findings were shared directly with maintainers prior to broad publicity. As of 2026-10-08, maintainer triage status is recorded below:

| Target | Repository & Issue | Status | Outcome / Maintainer Response |
| :--- | :--- | :--- | :--- |
| **Microsoft** | [microsoft/playwright-mcp#1784](https://github.com/microsoft/playwright-mcp/issues/1784) | **Closed (Completed)** | Reviewed and closed as completed by Playwright Lead Architect Pavel Feldman (`@pavelfeldman`). |
| **Upstash** | [upstash/context7#3312](https://github.com/upstash/context7/issues/3312) | **Closed (Resolved)** | Acknowledged with thanks by core collaborator Enes Gules (`@enesgules`). Proactive correction of the description false positive validated; confirmed that upstream Context7 API validates and bounds inputs prior to execution. |
| **Anthropic Reference** | [modelcontextprotocol/servers#4958](https://github.com/modelcontextprotocol/servers/issues/4958) | **Open (Discussion)** | Technical peer discussion with maintainer contributors regarding host UX hints (`destructiveHint: true`) versus server-side authorization contracts and out-of-band capability tokens. |
| **Desktop Commander** | [wonderwhy-er/DesktopCommanderMCP#808](https://github.com/wonderwhy-er/DesktopCommanderMCP/issues/808) | **Open** | Awaiting maintainer triage. |
| **Firecrawl** | [firecrawl/firecrawl-mcp-server#481](https://github.com/firecrawl/firecrawl-mcp-server/issues/481) | **Open** | Awaiting maintainer triage. |

---

*Scan performed with [LIFE FORGE](https://github.com/zariffromlatif/life-forge) (`lifeforge mcp-scan`), MIT License. Run it on your own servers before someone else does.*
