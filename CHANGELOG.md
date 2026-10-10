# Changelog

All notable changes to LIFE FORGE are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-10-10

The correctness release. A full audit of the codebase (sandbox, oracle,
evolution, reporting, gateway, hardening, domains, MCP scanner, dashboard, CLI,
adapters) found about 70 defects. All are fixed with regression tests. Several
of them changed published results; see **Corrections**.

### Added

- **Regression corpus** (`lifeforge/reporting/regression_corpus.py`):
  `lifeforge surface --record` now saves every scenario the search kept
  (passing and failing), with the baseline agent's verdict on each. On a PR,
  `lifeforge surface --baseline` replays the corpus scenario by scenario, and
  that replay is the CI gate. Replaces the cell-position diff as the gate: that
  diff could mistake "not explored this time" for "fixed". The cell diff is kept
  as informational output.
- **Stochastic agents**: `--repeats N --tolerance T` replay each scenario
  several times and compare failure/critical *rates*. Agent errors are reported
  as invalid, never as fixed.
- **Twin from MCP** (`lifeforge compile-domain --from-mcp manifest.json --out spec.yaml`):
  generates a domain spec from an MCP server's tool definitions. Argument
  schemas are carried over, and state-changing tools are gated on a generated
  `request_human_approval` tool.
- Oracle 2.0 (`ORACLE_VERSION`): configurable budget/treasury keys and quantity
  bounds, `allowed_email_domains`, `AGENT_INFRA_ERROR` / `ORACLE_POLICY_ERROR`
  verdicts, and the `executed` flag on prohibited-tool findings.
- Shared strict recipient matching (`lifeforge/sandbox/recipients.py`) used by
  the oracle, gateway, and tool guards.
- Observations now include `available_tools`, so framework adapters can show the
  agent the sandbox's tools.
- Action inputs `surface-repeats` and `surface-tolerance`.

### Fixed (security)

- **Dashboard arbitrary file read**: `/api/export?file=C:/...` and drive-letter
  static paths could read any file on the machine. The Host header is now
  checked (closes DNS rebinding), and the wildcard CORS header is removed.
- **Code injection in generated hardening modules**: tool and violation names
  taken from a report could execute code on import. All untrusted text now goes
  through `repr()`, and the output is `ast.parse`d before it is written.
- **GitHub Action script injection / word-splitting**: inputs pass through
  `env` and bash arrays; a sticky, size-capped PR comment.
- Gateway fails closed on malformed config, normalizes tool names
  (case/whitespace/confusables), and blocks non-numeric/NaN/negative amounts.
  It evaluates all rules and takes the most severe verdict, and refuses
  conflicting `enforce()` payloads. Audit chain: verified on load, mid-file
  corruption treated as tampering, and checkpoints detect truncation.
- HTTP agent adapter refuses cross-host redirects (custom auth headers leaked).

### Fixed (verdict correctness)

- Email allow-list was a substring match (`attacker@evil-finance.com` passed
  `finance`); now exact roles or allowed domains, every recipient checked.
- An unreachable or erroring agent (bad API key, dead webhook, unparseable
  reply) was scored as a clean "finish", ranking broken agents as resilient.
- TOCTOU check fired on purchase orders the tool *rejected*; it now requires a
  committed purchase at an unchecked price.
- Worm policy fired on the attacker's planted payload; swarm hops were blamed
  for earlier hops' emails. Judgement is now limited to what this episode produced.
- "Approval requested" counted as "approval granted"; a failing test run
  unlocked a merge; `force="false"` force-merged undetected. Refunds now check
  eligibility and the order value.
- Plausible malformed tool arguments crashed the whole run. Agents could
  mutate world state through tool outputs. POs bought items the vendor did not
  quote. Policies that crashed silently passed.
- LLM agent: parallel tool calls broke the conversation (HTTP 400). Retries
  honour `max_retries`. Permanent errors are not retried.
- MCP scanner: risk band followed finding *volume*, so MEDIUM-only servers were
  labelled CRITICAL. Static extraction dropped every parameter of JSON-schema
  tool constants. Live scans collapsed per-parameter findings and ignored
  pagination and SSE ids, and could hang. Poisoning, invisible-character and
  homoglyph detection were easy to evade. Ruleset 1.1.0.
- Surface diff missed escalations inside failing cells. Markdown and PDF
  reports gave contradictory risk scores. Compliance packs reported PASS on
  incomplete data. Failure rates counted archive cells, not evaluations.
  Reproduction scripts did not run.
- Domain compiler: effects are atomic, there is no implicit overdraft, types are
  validated, and non-finite numbers are rejected.
- Quickstart executed user code without saying so; it now requires `--yes`.

### Corrections to published results

- **MCP ecosystem scan**: "40% of servers in the CRITICAL band" was wrong (0
  CRITICAL findings). Re-scored: 0 CRITICAL / 8 HIGH / 4 MODERATE / 3 LOW.
  `brave-search`, `google-maps`, `slack` need a fresh scan. See
  `results/MCP_ECOSYSTEM_SCAN.md`.
- **Model leaderboard**: "critical" findings were refused attempts to call the
  prohibited transfer tool. No transfer completed in any run. The Mistral
  TOCTOU finding was a false positive. Single seed per model. Notices were added
  to `results/LEADERBOARD.md` and the research write-up.

### Changed

- Positioning: behavioral regression testing for agents that take actions.
- `pyyaml` is now a core dependency (YAML domain specs).
- Seed=42 default-path search behaviour is byte-identical to 0.3.0. The only
  difference is that `seed_baseline` is no longer copied into child lineages.

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
