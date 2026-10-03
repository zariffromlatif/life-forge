# MCP Ecosystem Security Scan

**Generated**: 2026-10-03 09:01 UTC  
**Scanner**: LIFE FORGE mcpsec v1.0.0 (deterministic ruleset; findings reproduce byte for byte)
**Method**: live protocol probes (stdio, definitions read off the wire) for servers launchable without credentials; static source extraction for popular credential-gated servers. The scanner observes definitions only - it never executes tools.

---

## Headline Numbers

- **15** of 16 targeted servers scanned (1 not launchable without credentials, 0 scan errors)
- **167** tool definitions analyzed
- **80.0%** of scanned servers carry at least one finding
- **40.0%** of scanned servers score in the CRITICAL band (`filesystem`, `server-git`, `desktop-commander`, `playwright`, `github`, `firecrawl`)
- Findings by severity: **0 CRITICAL** / 33 HIGH / 246 MEDIUM / 0 LOW

Context: an industry scan reported 33% of MCP servers with critical vulnerabilities (Practical DevSecOps, 2026). This scan runs an independent, reproducible ruleset and publishes every raw report.

---

## Findings by Rule

| Rule | Occurrences |
| :--- | :--- |
| `MCP_UNBOUNDED_PARAMETER` | 242 |
| `MCP_DESTRUCTIVE_UNCONSTRAINED` | 33 |
| `MCP_MUTATING_NO_REQUIRED` | 4 |

---

## Per-Server Results

| Server | Source | Method | Tools | Score | Band | C/H/M/L |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `everything` | @modelcontextprotocol/server-everything | live-stdio | 13 | 42 | MODERATE | 0/1/6/0 |
| `filesystem` | @modelcontextprotocol/server-filesystem | live-stdio | 14 | 82 | CRITICAL | 0/1/14/0 |
| `memory` | @modelcontextprotocol/server-memory | live-stdio | 9 | 41 | MODERATE | 0/3/1/0 |
| `sequential-thinking` | @modelcontextprotocol/server-sequential-thinking | live-stdio | 1 | 5 | LOW | 0/0/1/0 |
| `server-time` | mcp-server-time (PyPI) | live-stdio | 2 | 10 | LOW | 0/0/2/0 |
| `server-fetch` | mcp-server-fetch (PyPI) | live-stdio | 1 | 17 | LOW | 0/1/1/0 |
| `server-git` | mcp-server-git (PyPI) | live-stdio | 12 | 80 | CRITICAL | 0/0/16/0 |
| `server-sqlite` | mcp-server-sqlite (PyPI) | live-stdio | - | - | not launchable | - |
| `context7` | @upstash/context7-mcp | live-stdio | 2 | 10 | LOW | 0/0/2/0 |
| `desktop-commander` | @wonderwhy-er/desktop-commander | live-stdio | 26 | 100 | CRITICAL | 0/9/27/0 |
| `playwright` | @playwright/mcp | live-stdio | 25 | 100 | CRITICAL | 0/3/24/0 |
| `github` | modelcontextprotocol/servers-archived | static-source | 26 | 100 | CRITICAL | 0/7/94/0 |
| `slack` | modelcontextprotocol/servers-archived | static-source | 8 | 0 | LOW | 0/0/0/0 |
| `brave-search` | modelcontextprotocol/servers-archived | static-source | 2 | 0 | LOW | 0/0/0/0 |
| `google-maps` | modelcontextprotocol/servers-archived | static-source | 7 | 0 | LOW | 0/0/0/0 |
| `firecrawl` | firecrawl/firecrawl-mcp-server | static-source | 19 | 100 | CRITICAL | 0/8/58/0 |

---

## Notable Findings

- **`everything`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `simulate-research-query`
- **`filesystem`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `write_file`
- **`memory`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `delete_entities`
- **`memory`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `delete_observations`
- **`memory`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `delete_relations`
- **`server-fetch`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `fetch`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `edit_block`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `get_prompts`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `interact_with_process`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `list_sessions`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `set_config_value`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `start_process`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `start_search`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `write_file`
- **`desktop-commander`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `write_pdf`
- **`playwright`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `browser_drag`
- **`playwright`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `browser_drop`
- **`playwright`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `browser_run_code_unsafe`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `add_issue_comment`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `create_issue`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `get_issue`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `list_issues`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `merge_pull_request`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `search_issues`
- **`github`** `MCP_DESTRUCTIVE_UNCONSTRAINED` (HIGH): Destructive tool exposes no authorization surface - tool `update_issue`

---

## Methodology & Limitations

1. Live probes launch each published package exactly as a client would (`npx -y <package>` / `uvx <package>`) and read `tools/list` off the wire after a full MCP handshake. Nothing is executed on the target beyond protocol-level requests.
2. Static extraction recovers definitions from source with known registration patterns (`server.tool`, `registerTool`, FastMCP `@mcp.tool`); extraction counters are recorded per server, and servers where no pattern matched are reported as such rather than silently dropped.
3. Findings are deterministic: re-running the scan against the same server versions reproduces every result. Per-server raw reports ship alongside this document in `results/mcp_ecosystem_scan/reports/`.
4. Severity reflects *attack surface present in tool definitions*, not a proven exploit chain: a CRITICAL here means an attacker-controlled channel or an unconstrained destructive capability exists in the definition itself.
5. This scan covers a curated set of high-adoption servers, not the full ecosystem registry; percentages are for this cohort.

---

*Scan performed with [LIFE FORGE](https://github.com/zariffromlatif/life-forge) (`lifeforge mcp-scan`), MIT License. Run it on your own servers before someone else does.*
