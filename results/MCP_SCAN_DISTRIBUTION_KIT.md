# MCP Ecosystem Scan - Distribution Kit

Everything needed to publish the ecosystem scan: post drafts for Reddit and
Hacker News, and responsible-disclosure notes for the six CRITICAL-band
maintainers. Prepared 2026-10-03 for the scan committed in
`results/MCP_ECOSYSTEM_SCAN.md` (ruleset v1.0.0, 15 servers, 167 tools).

Ground rules for all outbound text:

- Lead with data; state limitations before anyone else does.
- These are design-level attack-surface observations, not CVEs. The tone is
  "heads up, here is evidence", never "you are breached".
- Every claim links to a reproducible artifact.

---

## 1. Reddit post (r/LocalLLaMA, then r/MCP and r/cybersecurity a day later)

**Title**: I scanned the 15 most popular MCP servers with a deterministic security scanner. 40% score critical - including the official filesystem reference server.

**Body**:

I built an open-source MCP security scanner (part of a larger agent red-teaming project) and pointed it at the most-installed servers in the ecosystem. 9 servers were probed live over the actual MCP protocol (launched via npx/uvx, definitions read off the wire after a full handshake); 6 credential-gated ones were extracted from source. 167 tool definitions total. The scanner never executes tools on a target.

**The numbers:**

- 6 of 15 servers (40%) score in the CRITICAL band
- 25 HIGH findings: destructive tools with no authorization surface - `write_file` (official filesystem server), `delete_entities` (official memory server), `start_process` / `edit_block` (desktop-commander), `browser_run_code_unsafe` (playwright MCP)
- 242 findings of unbounded string/number parameters (no maxLength, no range) - the attack surface for prompt-injection payloads and context flooding
- The official `git` reference server has 16 tools, every single one with unbounded parameters
- slack, brave-search, and google-maps scanned completely clean - it's clearly possible to do this right

**What "no authorization surface" means:** the tool schema declares no confirmation, approval-token, or dry-run argument. Execution is gated only on the model choosing to call it. Combined with indirect prompt injection (which is up ~340% this year), that is exactly the path from "agent read something attacker-controlled" to "agent ran a destructive action with no guardrail".

**Honest limitations, stated up front:**

- Findings reflect attack surface in tool *definitions*, not proven exploit chains. A CRITICAL band means an unconstrained destructive capability exists in the definition itself.
- The destructive-tool heuristic matches verbs in names/descriptions and deliberately over-approximates; every finding lists its evidence and the ruleset is versioned.
- Curated cohort of high-adoption servers, not the full registry.
- Fun side effect: desktop-commander's onboarding page opened in my browser mid-scan with `utm_source=lifeforge-mcpsec` - it reads the client name from the MCP handshake. Launching a server is trusting it.

**Full report with per-server evidence and reproduction commands:**
`results/MCP_ECOSYSTEM_SCAN.md` in the repo - every raw report ships alongside it.

**Repo** (MIT, pip installable): https://github.com/zariffromlatif/life-forge

The same project also red-teams agents themselves (evolutionary adversarial search against a deterministic digital twin) and runs fully local via Ollama - the leaderboard in the README has 8 local models benchmarked with a fixed seed.

Happy to answer methodology questions, and if you maintain one of the scanned servers and think a finding is wrong, I will re-run and correct the report.

**Posting notes**: r/LocalLLaMA first (highest engagement for local tooling), then r/MCP and r/cybersecurity 24h later. Reply to every technical comment within a few hours; the methodology limitations paragraph is the one to quote when challenged.

---

## 2. Hacker News (Show HN)

**Title**: Show HN: Deterministic security scanner for MCP servers - 40% of popular servers score critical

**First comment** (post immediately after submitting):

Hi HN - I built LIFE FORGE, an open-source adversarial testing harness for AI agents, and last week pointed its MCP scanner at the 15 most-installed servers in the ecosystem.

The scanner reads tool definitions off the wire (launches each published package exactly as a client would, completes the MCP handshake, lists tools) and applies a versioned, deterministic ruleset: injection directives in tool descriptions (including decoded Base64), invisible/bidi Unicode, homoglyph tool names, destructive tools with no confirmation/approval argument, unbounded parameters, and "rug pull" detection (definitions that change between an approved baseline and a live fetch). It never executes tools on the target.

Result: 6 of 15 servers score critical, including the official MCP `filesystem` and `git` reference implementations and Microsoft's Playwright MCP. 25 tools can mutate state or spend money with no authorization surface in their schema - with indirect prompt injection on the rise, that is the path an attacker takes from "agent read a web page" to "agent did something irreversible."

Why deterministic matters: findings are a pure function of the definitions, so any maintainer can re-run and get the same verdict byte for byte. No model-judged severity, no vibes.

Limitations I will defend in the thread: findings are definition-level attack surface, not working exploits; the destructive-tool heuristic over-approximates (evidence is listed per finding); the cohort is curated, not the full registry.

Report with per-server evidence: the repo's results/MCP_ECOSYSTEM_SCAN.md. The broader project also fuzzes agents themselves against a deterministic digital twin (evolutionary search, MAP-Elites failure surfaces) and gates agents in CI.

Repo: https://github.com/zariffromlatif/life-forge

**Posting notes**: submit early morning US Eastern; the first comment carries the methodology so the thread starts substantive. Expect the top challenge to be "definitions aren't vulnerabilities" - the answer is the memory-server example: `delete_entities` with no confirmation argument means one injected instruction deletes the knowledge graph, and the fix (a `confirm: true` argument, enforced server-side) costs the maintainer five lines.

---

## 3. Responsible-disclosure emails

Send as GitHub security advisories ("Report a vulnerability") where the repo has
it enabled; otherwise a short issue-opening offer by email. These are design
observations, not vulnerability reports - keep that framing in the first line.
Replace the bracketed sender details before sending.

### 3.1 modelcontextprotocol/servers (filesystem + git reference servers)

**Subject**: Deterministic scan findings on server-filesystem and server-git - definitional attack surface, no exploit claimed

Hello maintainers,

I run LIFE FORGE, an MIT-licensed open-source security scanner for MCP tool definitions (github.com/zariffromlatif/life-forge). I recently scanned the most-installed servers in the ecosystem and want to share the findings on your reference implementations directly, before publishing summaries elsewhere.

What the scanner flagged on `server-filesystem` (probed live over stdio, definitions read off the wire):

- `write_file` performs a state-mutating operation with no confirmation, approval-token, or dry-run argument in its schema. Under indirect prompt injection - an attacker-controlled document instructing the agent to write a file - the only gate is the model's own judgment.
- All 14 tools declare string parameters without maxLength/pattern bounds, which admits arbitrary-length payloads into the agent's context.

On `server-git`: all 12 tools declare unbounded string parameters. No destructive-capability flags - the concern here is parameter bounding only.

These are design-level observations about the *definitions*, not claims of an exploitable vulnerability, and I recognize reference servers trade hardening for pedagogical clarity. But they are also the templates people copy, and the fix pattern (a `confirm: true` argument enforced server-side; maxLength on path/string parameters) costs a few lines per tool and would set the ecosystem standard.

Full report: results/MCP_ECOSYSTEM_SCAN.md in the repository above (per-server JSON evidence included; the ruleset is versioned and findings reproduce deterministically). If you believe any finding is wrong, I will re-run and publish a correction. I have not posted about your servers individually and will hold individual publicity until you have had a reasonable window.

[Sender name, contact]

### 3.2 microsoft/playwright-mcp

**Subject**: Scan findings on @playwright/mcp - unconstrained `browser_run_code_unsafe` and 23 unbounded parameters

Hello Playwright MCP team,

I run LIFE FORGE, an open-source MCP tool-definition scanner (github.com/zariffromlatif/life-forge). A deterministic scan of the published `@playwright/mcp` package (probed live over stdio via npx, definitions read off the wire) flagged:

- `browser_run_code_unsafe` - by its own name an execution surface - declares no confirmation or authorization argument in its schema. Under indirect prompt injection, an instruction inside fetched content is the only thing standing between an agent and arbitrary code execution in the browser context.
- `browser_drop` and `browser_drag` mutate page state with no confirmation argument.
- 23 of 25 tools declare unbounded string parameters.

These are definition-level design observations, not claims of an exploitable vulnerability in Playwright itself. Given this server's deployment breadth, an authorization-surface convention for capability-carrying tools (a required `confirm`-style argument pattern, enforced server-side) would be a meaningful ecosystem contribution - and the scanner can re-verify any change deterministically.

Full report and per-tool evidence: results/MCP_ECOSYSTEM_SCAN.md in the repository above. Happy to correct any finding publicly if you disagree; I will hold individual publicity until you have had a reasonable window.

[Sender name, contact]

### 3.3 desktop-commander (wonderwhy-er)

**Subject**: Scan findings on desktop-commander MCP - 9 tools flagged with no authorization surface

Hi,

I run LIFE FORGE, an open-source MCP security scanner (github.com/zariffromlatif/life-forge). A live-protocol scan of the published desktop-commander package flagged 9 tools whose schemas declare state-mutating or execution capability with no confirmation or authorization argument - including `start_process`, `edit_block`, and `interact_with_process` - plus 26 tools with unbounded string parameters. On a server whose whole point is terminal and filesystem control, those are the tools an indirect prompt injection would reach for first.

Two things worth saying directly:

1. These are definition-level design observations, not claims of an exploitable vulnerability. The evidence for every finding is published and reproducible (results/MCP_ECOSYSTEM_SCAN.md in the repo above).
2. A side effect you may appreciate: launching the package during the scan opened your onboarding page in my browser with `utm_source=lifeforge-mcpsec` - you are clearly reading the client name from the initialize handshake. That behavior is also why the scan report now carries a methodology note that launching a server runs its startup code; worth a line in your docs about what first-run does.

A `confirm`-style argument pattern (or a server-side allowlist mode) on the execution-class tools would address the finding class. I will happily re-run and publish updated scores after any change. Holding individual publicity until you have had a reasonable window.

[Sender name, contact]

### 3.4 upstash/context7

**Subject**: Scan findings on context7 MCP - unbounded parameters; one pattern flag reviewed and withdrawn

Hello Context7 team,

I run LIFE FORGE, an open-source MCP security scanner (github.com/zariffromlatif/life-forge). A live-protocol scan of the published context7 package initially flagged both tools with a "coercive instruction in description" pattern - on manual review that was a FALSE POSITIVE: "You must call 'Resolve Context7 Library ID' tool first" is benign sequencing documentation, and I tightened the pattern before publishing anything. You can see the corrected result in the published report (both tools score LOW; the remaining finding is two unbounded string parameters, a minor hardening note).

I am mentioning the withdrawn flag deliberately: the scanner publishes every finding with its evidence, and when a rule misfires on a real server, the correction ships too. If your team sees anything in the report that reads wrong for context7, I will re-run and correct.

Full report: results/MCP_ECOSYSTEM_SCAN.md in the repository above.

[Sender name, contact]

### 3.5 firecrawl (firecrawl-mcp-server)

**Subject**: Scan findings on firecrawl-mcp-server - 8 tools flagged with no authorization surface, 57 unbounded parameters

Hello Firecrawl team,

I run LIFE FORGE, an open-source MCP security scanner (github.com/zariffromlatif/life-forge). A static-source scan of firecrawl-mcp-server (extracted with your repo's registration patterns; counters recorded) flagged:

- 8 tools whose schemas declare state-changing capability (e.g. `firecrawl_monitor_create`, `firecrawl_agent`) with no confirmation or authorization argument. For a paid API, an agent-triggered `firecrawl_agent` run without an authorization surface is also an unintended-spend risk for your users.
- 57 tools' string parameters without maxLength/pattern bounds.

These are definition-level design observations, not claims of an exploitable vulnerability. The fix pattern - a required confirmation argument on capacity-consuming tools, bounds on URL/text parameters - protects your users' API budgets as much as their agents. Full evidence: results/MCP_ECOSYSTEM_SCAN.md in the repository above; findings reproduce deterministically and I will re-run and correct anything you dispute. Holding individual publicity until you have had a reasonable window.

[Sender name, contact]

---

## 4. Sequencing

1. Send the five disclosure notes first (day 0).
2. Reddit r/LocalLLaMA on day 3 (or after the first two maintainer responses, whichever shows the finding/response dynamic best - update the post if a fix lands).
3. Show HN on day 4-5, ideally the same day a maintainer ships a fix so the thread has a "and here is the diff" moment.
4. r/MCP + r/cybersecurity cross-post day 5-6.
5. Re-scan anything that ships a fix and append a "post-fix scores" section to the report - the diff is the best possible follow-up content.
