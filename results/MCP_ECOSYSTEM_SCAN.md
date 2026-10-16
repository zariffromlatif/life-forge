# MCP Ecosystem Security Scan

**Generated**: 2026-10-03 12:52 UTC  
**Scanner**: findings from LIFE FORGE mcpsec ruleset 1.0.0; scores and bands re-computed with mcpsec 1.1.0 (see revision note)
**Method**: live protocol probes (stdio, definitions read off the wire) for servers launchable without credentials; static source extraction for popular credential-gated servers. The scanner observes definitions only - it never executes tools.


> **Revision 2026-10-10 - read first.** This report was first published (2026-10-03) with **40% of servers in the CRITICAL band**. That figure was wrong. The 1.0.0 scorer banded servers by raw finding *volume*, so a server with many MEDIUM "unbounded parameter" findings and **no CRITICAL finding** was labelled CRITICAL; the scan contained **zero CRITICAL-severity findings**. Bands are now anchored on the most severe finding (mcpsec 1.1.0), and the stored findings were re-scored without re-collecting them. Two further 1.0.0 defects mean the findings themselves need a fresh scan: (1) static extraction dropped every parameter of tools declared as JSON-schema constants, so **`brave-search`, `google-maps`, and `slack` were never actually scanned** (their 0-finding results are invalid); (2) live scans collapsed per-parameter findings, undercounting MEDIUM findings on live-probed servers. Original scores are preserved in each per-server JSON under `original_scoring`.

> **Revision 2026-10-16 (ruleset 1.2.0) - the destructive-tool findings below were overstated.** `MCP_DESTRUCTIVE_UNCONSTRAINED` produced false positives. It matched verbs anywhere in a description, including adjectives ("merged pull requests", "purchased credits") and usage notes ("do not send both fields"), and it ignored the MCP `readOnlyHint` / `destructiveHint` annotations. The static extractor also misread `//` comments containing an apostrophe, which hid tools and arguments. Ruleset 1.2.0 fixes all three:
>
> - `readOnlyHint: true` means the tool is not destructive.
> - A destructive tool that declares `destructiveHint: true` is **MEDIUM**, not HIGH: a host can ask the user first, and what remains is that the server enforces no limit of its own.
> - A read-named tool is judged by its name, and only a description's first sentence is matched.
>
> In the per-server findings below, these HIGH flags are false positives: desktop-commander `get_prompts`, `list_sessions`, `start_search`; firecrawl `firecrawl_search`, `firecrawl_developer_search`, `firecrawl_credit_usage`. The three servers with open disclosures were re-checked against current source (static extraction; no server was launched):
>
> | Server | Source checked | Tools | In this report (1.1.0) | Ruleset 1.2.0 |
> | :--- | :--- | ---: | :--- | :--- |
> | `desktop-commander` | DesktopCommanderMCP `f508e52` (2026-10-14) | 25 | HIGH, 8 HIGH findings | **MODERATE, no HIGH finding**. Every state-changing tool declares `destructiveHint: true` and every read tool `readOnlyHint: true`; 9 MEDIUM "host-side approval only" findings remain. |
> | `firecrawl` | firecrawl-mcp-server `e895e94` (2026-10-15) | 28 | HIGH, 7 HIGH findings | **HIGH, 3 HIGH findings**: `firecrawl_interact`, `firecrawl_agent`, `firecrawl_monitor_run` (see below). 61 parameters without bounds (MEDIUM). |
> | `filesystem` | modelcontextprotocol/servers `bbb701e` (2026-10-11), annotations read from source | 14 | HIGH (`write_file`) | **No HIGH finding**. `write_file`, `edit_file` and `move_file` declare `destructiveHint: true` (MEDIUM under 1.2.0); not fully re-scored, because the static extractor does not parse this server's registration pattern. |
>
> The firecrawl HIGH findings are tools that declare `destructiveHint: false` but start work or act outside the server. `firecrawl_interact`'s own description says form submissions "can create persistent external side effects", so a client that trusts the hint will not ask the user first. `firecrawl_agent` and `firecrawl_monitor_run` start credit-consuming jobs. The rest of this report (other servers, headline numbers) still reflects ruleset 1.1.0 until a full re-scan.

---

## Headline Numbers

- **15** of 16 targeted servers scanned (1 not launchable without credentials, 0 scan errors)
- **167** tool definitions analyzed
- **80.0%** of scanned servers carry at least one finding (a lower bound: three static extractions were invalid, see revision note)
- **0.0%** of scanned servers score in the CRITICAL band (none)
- Findings by severity: **0 CRITICAL** / 25 HIGH / 245 MEDIUM / 0 LOW

Context: an industry scan reported 33% of MCP servers with critical vulnerabilities (Practical DevSecOps, 2026). This scan runs an independent, reproducible ruleset and publishes every raw report.

---

## Findings by Rule

| Rule | Occurrences |
| :--- | :--- |
| `MCP_UNBOUNDED_PARAMETER` | 242 |
| `MCP_DESTRUCTIVE_UNCONSTRAINED` | 25 |
| `MCP_MUTATING_NO_REQUIRED` | 3 |

---

## Per-Server Results

| Server | Source | Method | Tools | Score | Band | C/H/M/L |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `brave-search` | modelcontextprotocol/servers-archived | static-source | 2 | 0 | LOW | 0/0/0/0 |
| `context7` | @upstash/context7-mcp | live-stdio | 2 | 20 | MODERATE | 0/0/2/0 |
| `desktop-commander` | @wonderwhy-er/desktop-commander | live-stdio | 26 | 57 | HIGH | 0/8/27/0 |
| `everything` | @modelcontextprotocol/server-everything | live-stdio | 13 | 50 | HIGH | 0/1/6/0 |
| `filesystem` | @modelcontextprotocol/server-filesystem | live-stdio | 14 | 50 | HIGH | 0/1/14/0 |
| `firecrawl` | firecrawl/firecrawl-mcp-server | static-source | 19 | 59 | HIGH | 0/7/58/0 |
| `github` | modelcontextprotocol/servers-archived | static-source | 26 | 50 | HIGH | 0/1/93/0 |
| `google-maps` | modelcontextprotocol/servers-archived | static-source | 7 | 0 | LOW | 0/0/0/0 |
| `memory` | @modelcontextprotocol/server-memory | live-stdio | 9 | 50 | HIGH | 0/3/1/0 |
| `playwright` | @playwright/mcp | live-stdio | 25 | 50 | HIGH | 0/3/24/0 |
| `sequential-thinking` | @modelcontextprotocol/server-sequential-thinking | live-stdio | 1 | 20 | MODERATE | 0/0/1/0 |
| `server-fetch` | mcp-server-fetch (PyPI) | live-stdio | 1 | 50 | HIGH | 0/1/1/0 |
| `server-git` | mcp-server-git (PyPI) | live-stdio | 12 | 20 | MODERATE | 0/0/16/0 |
| `server-sqlite` | mcp-server-sqlite (PyPI) | live-stdio | - | - | not launchable | - |
| `server-time` | mcp-server-time (PyPI) | live-stdio | 2 | 20 | MODERATE | 0/0/2/0 |
| `slack` | modelcontextprotocol/servers-archived | static-source | 8 | 0 | LOW | 0/0/0/0 |

---

## Notable Findings

- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `edit_block`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `get_prompts`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `interact_with_process`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `list_sessions`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `start_process`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `start_search`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `write_file`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `write_pdf`
- **`everything`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `simulate-research-query`
- **`filesystem`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `write_file`
- **`firecrawl`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `firecrawl_agent`
- **`firecrawl`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `firecrawl_credit_usage`
- **`firecrawl`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `firecrawl_developer_search`
- **`firecrawl`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `firecrawl_monitor_create`
- **`firecrawl`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `firecrawl_monitor_delete`
- **`firecrawl`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `firecrawl_monitor_run`
- **`firecrawl`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `firecrawl_search`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `merge_pull_request`
- **`memory`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `delete_entities`
- **`memory`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `delete_observations`
- **`memory`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `delete_relations`
- **`playwright`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `browser_drag`
- **`playwright`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `browser_drop`
- **`playwright`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `browser_run_code_unsafe`
- **`server-fetch`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `fetch`

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

In accordance with responsible disclosure principles, findings were shared directly with maintainers prior to broad publicity. As of 2026-10-16, maintainer triage status is recorded below. On 2026-10-16 a correction was posted on each open issue (see the revision note at the top):

| Target | Repository & Issue | Status | Outcome / Maintainer Response |
| :--- | :--- | :--- | :--- |
| **Microsoft** | [microsoft/playwright-mcp#1784](https://github.com/microsoft/playwright-mcp/issues/1784) | **Closed (Completed)** | Reviewed and closed as completed by Playwright Lead Architect Pavel Feldman (`@pavelfeldman`). |
| **Upstash** | [upstash/context7#3312](https://github.com/upstash/context7/issues/3312) | **Closed (Resolved)** | Acknowledged with thanks by core collaborator Enes Gules (`@enesgules`). Proactive correction of the description false positive validated; confirmed that upstream Context7 API validates and bounds inputs prior to execution. |
| **MCP reference servers** | [modelcontextprotocol/servers#4958](https://github.com/modelcontextprotocol/servers/issues/4958) | **Open (Discussion)** | A contributor review showed `write_file` already declares `destructiveHint: true` and is confined by `validatePath`, and that a `confirm` argument is self-attestation. Correction posted 2026-10-16: no HIGH finding under ruleset 1.2.0; the `confirm` suggestion withdrawn; only a documentation question remains. |
| **Desktop Commander** | [wonderwhy-er/DesktopCommanderMCP#808](https://github.com/wonderwhy-er/DesktopCommanderMCP/issues/808) | **Open** | Correction posted 2026-10-16: the HIGH findings were false positives (annotations ignored); no HIGH finding under ruleset 1.2.0. Awaiting maintainer response. |
| **Firecrawl** | [firecrawl/firecrawl-mcp-server#481](https://github.com/firecrawl/firecrawl-mcp-server/issues/481) | **Open** | Correction posted 2026-10-16: three false positives and the parameter count withdrawn. One point stands: `firecrawl_interact` declares `destructiveHint: false` although it can submit forms. Awaiting maintainer response. |

---

*Scan performed with [LIFE FORGE](https://github.com/zariffromlatif/life-forge) (`lifeforge mcp-scan`), MIT License. Run it on your own servers before someone else does.*
