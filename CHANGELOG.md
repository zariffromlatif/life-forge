# Changelog

All notable changes to LIFE FORGE are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-03

The agent-security release: a scanner for the MCP ecosystem, continuous
red-teaming primitives, a domain compiler, compliance evidence, and the
frameworks/CI surface to make all of it consumable.

### Added

- **MCP security scanner (`lifeforge mcpsec` / `lifeforge mcp-scan`)**: deterministic
  ruleset over MCP tool definitions - schema poisoning (incl. decoded Base64 payloads),
  invisible/bidi Unicode, homoglyph identifiers, destructive tools without an
  authorization surface, unbounded parameters, cross-server tool shadowing, and
  rug-pull (definition drift) detection. Live stdio/Streamable-HTTP probes with
  request-id-matched JSON-RPC; opt-in single-tool probing; `--fail-on-critical` CI gate.
- **MCP ecosystem scan** (`scripts/scan_mcp_ecosystem.py`, results in
  `results/MCP_ECOSYSTEM_SCAN.md`): 15 of the most-installed public MCP servers scanned
  (9 live protocol probes, 6 static source extractions; 167 tool definitions).
  40% score in the CRITICAL band, including the official `filesystem` and `git`
  reference servers, Microsoft's `playwright` MCP, `desktop-commander`, `context7`,
  and `firecrawl`.
- **Static extraction** (`lifeforge/mcpsec/extract.py`): tool definitions from
  TypeScript (`server.tool`, `registerTool`, `addTool`, the legacy
  `ListToolsRequestSchema` handler with cross-module `zodToJsonSchema` resolution,
  typed tool-constant and array-constant references) and Python FastMCP
  (`@mcp.tool`), with per-run coverage counters.
- **Failure-surface diffing (`lifeforge surface`)**: capture an agent's MAP-Elites
  failure topography to a JSON snapshot and diff it across commits; REGRESSED /
  IMPROVED / UNCHANGED verdict with a `--fail-on-regression` CI gate. Deterministic:
  identical campaigns diff to zero.
- **Domain compiler (`lifeforge compile-domain`, `--domain-spec`)**: declarative
  YAML/JSON specifications compile to working scenario domains - tools with schema
  validation and world effects (`spend`, `add_inventory`, `set_flag`, `record`),
  policies from the shared registry, compile-time validation with actionable errors.
- **Compliance evidence packs (`lifeforge compliance`)**: maps the deterministic
  violation register onto EU AI Act control areas (Art. 9-15) with GAP / PASS /
  UNVERIFIED assessments; verifies the gateway's hash-chained audit trail as
  record-keeping evidence. Evidence, not a legal opinion - stated on the document.
- **Multi-agent swarm runner (`lifeforge/sandbox/swarm.py`)**: agents run in
  sequence over one evolving world with orchestrator handoffs; attacks inject at
  the handoff boundary; `cross_agent_propagations()` attributes payload movement
  hop-to-hop - cross-agent findings a single-agent episode cannot produce.
- **Framework adapters**: AutoGen (step-mapped via `generate_reply`, native
  tool_calls shapes) and smolagents (run-to-completion, honestly documented), on a
  shared tolerant action-parsing layer (`adapters/_parsing.py`).
- **Dashboard security-reports panel**: surface snapshots, server-side surface
  diffs, and MCP scan reports over new REST endpoints with traversal rejection.
- **GitHub Action gate modes**: `mode: eval | surface | mcp-scan` with
  `--domain`/`--domain-spec`/`--frontier` passthroughs and a `surface-verdict`
  output; example workflows for the surface and mcp-scan gates.
- **Pluggable invariant policies** (`sandbox/policies.py`): nine composable policy
  objects incl. context-flood, cascading-failure, scope-expansion, reconnaissance,
  forbidden argument values, authority drains, required predecessors, worm
  propagation, and poisoned-memory adoption.
- **Frontier attack mutators (`--frontier`)**: self-replicating prompt worms,
  RAG/memory poisoning, cross-session propagation, context flood, and
  multilingual degradation (ZH/RU/AR/Base64/romanized arms with a control).
- **Revenue/delivery surface**: CISO-ready PDF reports (`lifeforge report`),
  tool-boundary hardening generator (`lifeforge harden`), customer audit bundles
  (`lifeforge audit`), and the runtime `PolicyGateway` with a tamper-evident
  hash-chained audit trail (`lifeforge gateway`).
- CrewAI adapter; `lifeforge quickstart` framework auto-detection; generalized
  multi-model benchmark runner (`scripts/run_model_benchmark.py --catalog`).

### Changed

- EU AI Act-mapped severity vocabulary across reports; analyzer names the worst
  capability per failure class.
- `requirements.txt` now installs `reportlab` (plain installs no longer break
  `lifeforge report`).
- Procurement scenario registered as a domain (`--domain procurement`) with
  byte-reproducible parity to the historical engine path.

### Fixed

- MCP probe client matches JSON-RPC responses by request id (a server reply to
  `notifications/initialized` previously poisoned the first `tools/list` fetch).
- Coercive-injection pattern requires a consequential action (benign sequencing
  text like "call the resolve tool first" no longer flags as poisoning).
- Destructive-verb matching drops "issue" (noun ambiguity: GitHub issues).
- Gateway rules derived from reports are enforceable (tool names extracted from
  findings; empty allow-lists fail loudly instead of silently allowing).
- Sandbox MCP server answers protocol-level `ping`.

### Provenance

- 559 tests passing (up from 111 at 0.2.0). Published seed=42 procurement results
  remain byte-reproducible through both the default and domain-based engine paths.

## [0.2.0] - 2026-09-26

- Turnkey composite GitHub Action, PR gatekeeper, PyPI publish workflow,
  multi-stage Dockerfile.
- Bring-your-own-agent CLI (`lifeforge eval`), Python spec loader, HTTP webhook
  adapter, exfiltration oracle, leaderboard CLI, DeepSeek-R1 launch kit.
