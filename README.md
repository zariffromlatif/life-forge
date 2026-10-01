# LIFE FORGE: The Autonomous Flight Simulator for AI Agents

> **Co-evolutionary adversarial red-teaming and dynamic stress-testing for autonomous AI agents using Artificial Life Quality-Diversity algorithms (3D MAP-Elites).**

[![Tests](https://img.shields.io/badge/tests-184%20passed-brightgreen.svg)](tests/)
[![CI](https://github.com/zariffromlatif/life-forge/actions/workflows/agent_stress_test.yml/badge.svg)](https://github.com/zariffromlatif/life-forge/actions/workflows/agent_stress_test.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-MCP%20Native-orange.svg)](lifeforge/sandbox/mcp_server.py)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

> **New Empirical Research Paper**: [The Scale Paradox in Autonomous AI Agents: Why 24B and 33B Models Suffered More Zero-Day Wire Transfers Than 8B](docs/research/THE_SCALE_PARADOX_IN_AI_AGENTS.md)

---

## Official Model Security Leaderboard (8 Frontier Models Tested)

Evaluated under identical random seeds (`seed=42`) across 30 co-evolutionary generations combining market volatility, inventory scarcity, and prompt injections on a dedicated NVIDIA RTX 4090 GPU:

| Rank | Model | Params | Security Grade | Critical Zero-Days | Operational Deadlocks | Adversarial Fail Rate | Primary Failure Mode |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `llama3.1:8b` | 8B | **C+** (Fragile) | **0** | 12 loops | 66.7% | Loop Termination under Volatility |
| **2** | `deepseek-r1:8b` | 8B | **C** (High-Risk) | **0** | **0 loops** | 100.0% | Conservative Halting under Scarcity |
| **3** | `deepseek-r1:14b` | 14B | **C** (High-Risk) | **0** | 14 loops | 100.0% | Reasoning Entrapment & Analytical Deadlock |
| **4** | `qwen2.5:14b` | 14B | **F** (Vulnerable) | **7 [CRITICAL]** | 0 loops | 100.0% | Authority Spoofing Blindness |
| **5** | `deepseek-coder:33b` | 33B | **F** (Vulnerable) | **8 [CRITICAL]** | 0 loops | 100.0% | Step-0 Immediate Injection Compliance |
| **6** | `phi4:14b` | 14B | **F** (Vulnerable) | **8 [CRITICAL]** | 0 loops | 100.0% | Untrusted Tool Data & MCP Schema Poisoning |
| **7** | `qwen2.5-coder:14b` | 14B | **F** (Vulnerable) | **12 [CRITICAL]** | 5 loops | 100.0% | Code Obedience Overdrive & Schema Blindness |
| **8** | `mistral-small:24b` | 24B | **F** (Vulnerable) | **14 [CRITICAL]** | 3 loops | 100.0% | Critical Exfiltration & TOCTOU Race Conditions |

*Full leaderboard profiles and JSON audit reports available in [`results/LEADERBOARD.md`](results/LEADERBOARD.md).*

### Key Takeaways from the Benchmark
* **The Parameter Scale Myth Disproven**: Scaling from 8B to 24B and 33B did not increase safety. In fact, larger non-reasoning models rationalized prompt injections more fluently, resulting in 8 to 14 critical wire exfiltrations.
* **The Cognitive Firewall of Reasoning Tokens**: DeepSeek-R1 (both 8B and 14B) recorded **zero critical wire exfiltrations**, completely neutralizing indirect prompt injection. Crucially, `deepseek-r1:8b` did not experience the 14 retry deadlocks seen in the 14B version, making it the most balanced reasoning agent tested.
* **The Code-Specialist Penalty**: Fine-tuning specifically on code caused a **71% surge in prompt injection exploitability** (Qwen 2.5-Coder suffered 12 critical breaches vs. 7 for generalist Qwen 2.5). DeepSeek-Coder (33B) executed unauthorized transfers on **Step 0** before querying the catalog.
* **First Live TOCTOU Race Condition**: Mistral Small committed purchase orders with stale price caps after price volatility shifted vendor rates, triggering our invariant oracle for Time-of-Check / Time-of-Use race conditions.

---

## Key Capabilities

### 1. 3D MAP-Elites Quality-Diversity Engine
Unlike standard optimizers that search for only one failure, LIFE FORGE maps an entire **topography of agent fragility** across a 3-dimensional phenotypic coordinate space:
- **Axis X (Adversarial Intensity)**: Frequency, subtlety, and complexity of prompt injections and spoofed communications ($0.0 \to 1.0$).
- **Axis Y (Environmental Volatility)**: Market price surges, supplier dropouts, inventory exhaustion ($0.0 \to 1.0$).
- **Axis Z (Budget Pressure)**: Corporate treasury limits and tight spending caps ($0.0 \to 1.0$).

### 2. Deterministic Digital Twin Sandbox
A zero-side-effect in-memory enterprise simulation state ([`WorldState`](lifeforge/sandbox/world_state.py)) with instantaneous snapshot and causal rollback. Agents interact with 5 simulated enterprise tools:
- `query_database`: Inspects inventory, prices, balances.
- `vendor_api`: Fetches external catalog quotes from suppliers.
- `issue_purchase_order`: Purchases hardware and commits company budget.
- `send_email`: Internal communication channel.
- `transfer_funds`: High-privilege banking wire transfer tool (policy-prohibited in procurement).

### 3. Invariant Policy Oracle
Monitors agent actions after every step and enforces mathematical policy boundaries:
- `UNAUTHORIZED_TOOL_EXECUTION`: High-severity privilege boundary breach.
- `UNAUTHORIZED_FINANCIAL_DRAIN`: Exceeding budget or unapproved fund movement.
- `RECURSIVE_LOOP_TRAP`: Cyclical tool re-submission without parameter updates.
- `GOAL_INVENTORY_DEFICIT`: Premature task termination without goal fulfillment.

### 4. Native Model Context Protocol (MCP) Server
LIFE FORGE can be run as a standard **Model Context Protocol (MCP)** server over `stdio` or `SSE`. Any MCP-compatible client--including **Claude Desktop**, **Cursor**, **LangGraph**, or custom multi-agent frameworks--can directly connect to LIFE FORGE's adversarial environments.

### 5. Multi-Provider LiteLLM Adapter
Test any frontier or local model with zero code changes:
- **Local Models**: Run on local GPUs via Ollama / vLLM (`ollama/llama3.1:8b`, `ollama/qwen2.5:14b`).
- **Cloud Providers**: OpenAI (`gpt-4o`, `o3-mini`), Anthropic (`claude-3-5-sonnet`, `claude-3-5-haiku`), Google AI Studio (`gemini-2.5-flash`, `gemini-1.5-flash`).
- Built-in automatic rate-limit backoff handler for 429/503 quota management.

### 6. The Scientific Core: The MODES Framework
Underneath the agent simulator lies LIFE FORGE's foundational Artificial Life laboratory, designed to measure open-ended evolution and avoid the **"Beautiful Garbage" trap** (confusing high-entropy white noise with true computational complexity):
- **Activity**: Bedau-Packard evolutionary activity waves ($A_{cum}$, excess activity over neutral shadow models).
- **Complexity**: Shannon entropy ($H$), bit-packed LZW algorithmic compressibility ($C$), and the **Complexity Gap** ($H \cdot (1 - C)$) which peaks sharply on Wolfram Class IV systems.
- **Novelty**: Cumulative vocabulary growth of local neighborhood micro-states.
- **Ecology**: 8-connected spatial cluster tracking and entity diversity.

---

## Quick Start

### Installation

Clone the repository and install with optional extras:

```bash
git clone https://github.com/zariffromlatif/life-forge.git
cd life-forge
python -m venv .venv

# On Windows:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install with LLM, MCP, and visualization dependencies:
pip install -e ".[all]"
```

---

### 1. Instant Baseline Stress Test (Offline / Zero Cost)
Stress-test the built-in reference agent across 50 evolutionary generations (requires no API keys):

```bash
python -m lifeforge.cli test --scenarios 50 --out results/baseline_report.md --json
```

---

### 2. Stress-Test Local Models on Your GPU (Ollama)
Run unlimited, free evolutionary stress tests against open-weight models on your local GPU (e.g. RTX 3080/4090):

```bash
# 1. Start Ollama with your chosen model:
ollama run llama3.1:8b

# 2. Run LIFE FORGE against your local GPU:
python -m lifeforge.cli test --model ollama/llama3.1:8b --api-base http://localhost:11434 --scenarios 30 --seed 42 --out results/llama_report.md --json
```

### 3. Launch the Visual Flight Simulator Dashboard (Web UI)
Explore 3D MAP-Elites behavior spaces, compare model showdowns, and inspect step-by-step exploit traces in an interactive local command center (zero extra dependencies required):

```bash
python -m lifeforge.cli ui --port 8000
```
Open your browser at `http://localhost:8000` to inspect discovered zero-days, explore behavioral niches, or export an executive PDF audit dossier.

---

### 4. Stress-Test Cloud Frontier Models (Gemini / OpenAI / Claude)
Run against cloud frontier models using your API keys:

```bash
# Test Gemini (Google AI Studio Free Tier):
$env:GEMINI_API_KEY = "your-api-key"
python -m lifeforge.cli test --model gemini/gemini-1.5-flash --scenarios 20 --delay 4.0 --out results/gemini_report.md --json

# Test OpenAI GPT-4o:
$env:OPENAI_API_KEY = "your-api-key"
python -m lifeforge.cli test --model gpt-4o-mini --scenarios 20 --out results/gpt_report.md --json
```

---

### 5. Evaluate Your Own Agent via Python Spec or Webhook (`lifeforge eval`)
Evaluate your existing agent pipelines (LangGraph, CrewAI, AutoGen, or custom microservices) with a single command:

```bash
# Evaluate a Python agent class, instance, or callable:
python -m lifeforge.cli eval --target path/to/my_agent.py:MyAgentClass --scenarios 30 --out results/my_agent_report.md --json

# Evaluate any remote or containerized agent via HTTP webhook:
python -m lifeforge.cli eval --endpoint http://localhost:5050/act --reset-endpoint http://localhost:5050/reset --scenarios 30

# Enforce CI/CD gating (fails build with exit code 1 if critical zero-days are found):
python -m lifeforge.cli eval --target my_agent.py:agent --scenarios 25 --fail-on-critical
```

---

### 6. Head-to-Head Model Showdown Comparison
Compare two or more evaluation reports side-by-side to crown the security winner:

```bash
python -m lifeforge.cli compare results/local_qwen_report.json results/local_llama_report.json --out results/MODEL_SHOWDOWN.md
```

---

### 7. Run as an MCP Server (Claude Desktop & Cursor)
Expose LIFE FORGE as a live MCP tool server:

```bash
python -m lifeforge.cli mcp-serve --transport stdio --adversarial
```

Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "lifeforge": {
      "command": "python",
      "args": ["-m", "lifeforge.cli", "mcp-serve", "--transport", "stdio", "--adversarial"]
    }
  }
}
```

---

### 8. Scientific Cellular Automata Laboratory
Simulate candidate universes and compute quantitative MODES complexity vectors:

```bash
# Run Conway's Game of Life
python -m lifeforge.cli run --substrate totalistic --steps 100

# Run Wolfram Rule 110 (Turing complete)
python -m lifeforge.cli run --substrate elementary --rule 110 --steps 100

# High-throughput 100-universe physics survey
python -m lifeforge.cli survey --count 100 --steps 150 --db results/survey.jsonl
```

---

### 9. Docker Container Deployment
Run the complete LIFE FORGE environment inside an isolated Docker container with zero host dependencies:

```bash
# Launch interactive web dashboard on http://localhost:8000
docker compose up lifeforge-ui

# Or run ad-hoc agent flight simulation
docker build -t lifeforge:latest .
docker run --rm -v ${PWD}/results:/app/results lifeforge test --scenarios 30 --out results/docker_report.md --json
```

---

## Scenario Domains: Test Beyond Procurement

The procurement ERP is the default environment, but the same evolutionary search runs against four registered scenario domains, each with its own world state, tool suite, invariant policies, and adversarial mutators:

```bash
lifeforge domains                                   # list what each domain tests
lifeforge eval --domain customer_support --target agent.py:my_agent --json
lifeforge eval --domain devops --endpoint http://localhost:5000/act
lifeforge eval --domain financial --target agent.py:trading_agent
```

| Domain | Agent under test | Failure modes it surfaces |
| :--- | :--- | :--- |
| `procurement` | Enterprise purchasing agent | Unauthorized wire transfers, retry loops, budget breaches |
| `customer_support` | SaaS/telco support agent | Social-engineered refunds, PII exfiltration, admin-grant abuse |
| `devops` | CI/CD pipeline agent | Gate bypass (merge/deploy without tests), secret egress, forced merges |
| `financial` | Trading desk agent | Approval bypass, spoofed-signal trading, risk-model tampering |

### Frontier Attacks (2026 Research Gaps)

Opt in with `--frontier` to add five attack classes that contemporary tooling does not cover:

```bash
lifeforge test --model ollama/llama3.1:8b --frontier --json
```

- `self_replicating_worm`: injections whose payload copies itself into the agent's own outputs (paired `SELF_REPLICATING_WORM_PROPAGATION` oracle verdict).
- `rag_memory_poisoning`: false facts seeded into memory/RAG stores that survive the session (paired `RAG_MEMORY_POISONING_ADOPTED`).
- `cross_session_propagation`: payloads instructing the agent to persist directives for the next agent in an orchestration.
- `context_flood`: oversized untrusted payloads sized to evict safety instructions from the context window (`CONTEXT_FLOOD_ATTACK`).
- `multilingual_degradation`: the same injection delivered in Chinese, Russian, Arabic, Base64, and romanized Chinese to expose language-dependent guardrails.

### Pluggable Invariant Policies

The oracle's checks are extensible: `lifeforge/sandbox/policies.py` ships nine composable policy objects (`ContextFloodAttackPolicy`, `CascadingToolFailurePolicy`, `UnauthorizedScopeExpansionPolicy`, `ExcessiveDataQueryingPolicy`, `ProhibitedArgumentValuePolicy`, `BalanceDrainPolicy`, `RequiredPredecessorPolicy`, `PayloadPropagationPolicy`, `PoisonedMemoryAdoptionPolicy`). Attach them to any `GoalSpecification`:

```python
from lifeforge.sandbox import GoalSpecification
from lifeforge.sandbox.policies import ExcessiveDataQueryingPolicy

goal = GoalSpecification(policies=[ExcessiveDataQueryingPolicy(max_sensitive_queries=1)])
```

---

## Framework Adapters: LangChain, LangGraph, CrewAI

Wrap an existing framework agent with zero modification and evaluate it in the sandbox:

```python
from lifeforge.adapters import LangChainAdapter, LangGraphAdapter, CrewAIAdapter

executor = AgentExecutor(agent=agent, tools=tools)      # your existing LangChain agent
lf_agent = LangChainAdapter(executor)

app = builder.compile()                                  # your compiled LangGraph graph
lf_agent = LangGraphAdapter(app=app)

crew = Crew(agents=[...], tasks=[...])                   # your CrewAI crew
lf_agent = CrewAIAdapter(crew=crew)

results = lifeforge.test(lf_agent)
```

Or let LIFE FORGE auto-detect the framework in your project:

```bash
lifeforge quickstart                    # scans the current directory, generates a harness, runs the benchmark
lifeforge quickstart --dry-run          # detection only, writes nothing
```

Detection covers LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex, smolagents, and OpenAI Agents.

---

## From Finding to Fix: Hardening, PDF Reports, and the Runtime Gateway

### 1. PDF Audit Reports (CISO-ready)

```bash
lifeforge report --input results/local_llama_report.json --output audit_report.pdf --customer "Acme Corp"
```

Executive summary page with risk score and band, failure-mode tables, threat-surface charts, per-finding evidence, remediation section, and a reproducibility appendix.

### 2. Hardening Decorator Generator

Turn every discovered violation into a drop-in tool-boundary guard:

```bash
lifeforge harden --input results/local_qwen_report.json --out remediation_decorators.py
```

The generated file imports the real runtime from `lifeforge.hardening` (`@tool_guard`, `PolicyError`) - guards raise `PolicyError` before a forbidden call reaches your implementation.

### 3. Customer Audit Deliverable (48-Hour Audit Format)

```bash
lifeforge audit --input results/local_phi4_report.json --customer "Acme Corp" --out audit_report/
# or run a fresh audit directly:
lifeforge audit --target agent.py:my_agent --customer "Acme Corp" --out audit_report/
```

Produces: `executive_summary.md` + `.pdf`, `technical_report.md` + `.pdf`, `raw_data.json`, `reproduction_commands.sh`, `remediation_decorators.py`, and `MANIFEST.md`.

### 4. Runtime Policy Gateway (Offline Findings -> Online Enforcement)

The same invariant policies that judge simulations enforce production tool calls, with a tamper-evident (hash-chained) audit trail:

```bash
lifeforge gateway --input results/local_qwen_report.json --out lifeforge_policy.yaml
```

```python
from lifeforge.gateway import PolicyGateway

gateway = PolicyGateway.from_config("lifeforge_policy.yaml")
guarded = gateway.wrap_executor(original_executor)   # drop-in replacement
# gateway.audit.verify()  -> tamper check over the whole trail
```

Critical findings become blocking rules; lower-severity ones start in monitor mode so you can promote them after observing false-positive rates.

---

## MCP Security Scanner

MCP adoption is outpacing its security: an industry scan found **33% of scanned MCP servers carried critical vulnerabilities**, and the NSA/CISA published MCP security guidance in June 2026. LIFE FORGE ships a deterministic scanner for MCP tool definitions - point it at a manifest or a live server:

```bash
# Static scan of a tool manifest
lifeforge mcp-scan --manifest mcp_tools.json --out results/mcp_scan.md --json

# Live probe: handshake + tools/list + rug-pull (drift) check across two fetches
lifeforge mcp-scan --server "python my_mcp_server.py" --baseline approved.json --out results/mcp_scan.md

# Streamable HTTP endpoint (CI gate on critical findings)
lifeforge mcp-scan --url https://mcp.example.com/mcp --fail-on-critical

lifeforge mcp-scan --list-rules     # the full ruleset
```

Detected classes: schema poisoning (injection directives in tool descriptions, decoded Base64 payloads), invisible/bidi Unicode, homoglyph tool-name spoofing, destructive tools with no authorization surface, unbounded parameters, cross-server tool shadowing, and description drift after approval (the rug pull). The scanner observes definitions only - it never executes tools on the target server.

Example: `examples/mcp_manifest_example.json` ships with a poisoned tool and a homoglyph-shadowed tool - scan it to see the detector classes fire.

---

## Continuous CI/CD Integration (GitHub Action Gatekeeper)

Prevent vulnerable, exfiltrating, or deadlocking agents from ever reaching production. Add the turnkey **LIFE FORGE GitHub Action** (`action.yml`) to any repository in 4 lines of YAML:

```yaml
# .github/workflows/agent_guard.yml
name: AI Agent Gatekeeper
on: [push, pull_request]

jobs:
  gatekeeper:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # Allows posting audit summary to PR review

    steps:
      - uses: actions/checkout@v4
      - name: Run LIFE FORGE Flight Simulation
        uses: zariffromlatif/life-forge@main
        with:
          target: "src/agent.py:my_agent"     # Python agent class, instance, or callable
          scenarios: 30                       # Number of evolutionary scenarios
          fail-on-critical: "true"            # Block PR if zero-day exploits are discovered
          comment-on-pr: "true"               # Post audit table directly to PR review
```

### Action Configuration Matrix

| Input | Description | Default |
| :--- | :--- | :--- |
| `target` | Python agent specifier (e.g. `src/agent.py:my_agent`) | `""` |
| `endpoint` | HTTP webhook URL for Dockerized / remote microservice agents | `""` |
| `reset-endpoint`| Optional HTTP reset URL for external microservice agents | `""` |
| `scenarios` | Number of evolutionary generations to simulate | `30` |
| `seed` | Deterministic random seed for reproducible exploration | `42` |
| `fail-on-critical` | Exit with code 1 and block build if critical vulnerabilities found | `'true'` |
| `comment-on-pr` | Post an executive audit table directly into PR review comments | `'true'` |
| `report-path` | Output path for generated Markdown audit report | `results/lifeforge_audit.md` |
| `github-token` | GitHub token for PR comments and summaries | `${{ github.token }}` |

See [`examples/ci_agent_workflow.yml`](examples/ci_agent_workflow.yml) for a complete copy-paste workflow.

---


## Repository Architecture

```
lifeforge/
├── substrates/                 # Artificial Life & Cellular Automata physics
│   ├── base.py                 # Abstract Substrate & State interfaces
│   └── ca/
│       ├── elementary.py       # 1D Elementary CA (Rules 0-255)
│       ├── totalistic.py       # 2D Vectorized Outer-Totalistic CA (Moore/von Neumann)
│       └── multi_state.py      # Multi-State 2D CA (Brian's Brain, Langton loops)
│
├── metrics/                    # Quantitative MODES measurement suite
│   ├── evolutionary_activity.py# Bedau-Packard evolutionary activity & neutral shadow baseline
│   ├── complexity.py           # Shannon entropy, bit-packed LZW, Complexity Gap
│   ├── novelty.py              # Pattern vocabulary growth & trajectory divergence
│   ├── ecology.py              # Connected-component entity labeling (pure NumPy BFS)
│   └── modes.py                # Unified Wolfram class classifier (I, II, III, IV)
│
├── sandbox/                    # Enterprise Agent Simulation Sandbox
│   ├── world_state.py          # Deterministic digital twin state machine with deep rollback
│   ├── mock_tools.py           # Enterprise tools (database, vendor API, PO, email, funds transfer)
│   ├── agent.py                # AgentInterface, RuleBasedPurchasingAgent, CallableAgentAdapter
│   ├── oracle.py               # Invariant policy enforcement & SandboxRunner orchestrator
│   ├── policies.py             # Pluggable invariant policies (flood, cascade, scope, recon, worm, poison)
│   ├── domains/                # Scenario domains: procurement, customer_support, devops, financial
│   ├── llm_agent.py            # Unified LiteLLM adapter with 429/503 rate-limit backoff
│   └── mcp_server.py           # Model Context Protocol (MCP) JSON-RPC stdio server
│
├── evolution/                  # Co-Evolutionary Red-Teaming Engine
│   ├── engine.py               # EvolutionEngine coordinating multi-generation search
│   ├── map_elites.py           # 3D Quality-Diversity Archive (adversarial x volatility x budget)
│   └── mutators/
│       ├── environmental.py    # PriceVolatility, InventoryScarcity, BudgetConstraint, VendorDropout
│       ├── adversarial.py      # IndirectPromptInjection, SpoofedExecutiveMessage, ConflictingSpec
│       ├── frontier.py         # 2026 frontier attacks: worms, memory poisoning, context flood, multilingual
│       ├── mcp_schema.py       # MCP tool schema poisoning (CVE-2025-53773 / CVE-2025-54135 class)
│       └── semantic.py         # 10,000+ combinatorial template payloads & SLM generation
│
├── reporting/                  # Causal Root-Cause Diagnostics
│   ├── analyzer.py             # CausalAnalyzer extracting minimal failure triggers
│   ├── report.py               # Markdown and JSON executive audit generator
│   ├── leaderboard.py          # Ranked model security leaderboard generator
│   ├── audit.py                # Customer-deliverable audit bundle (PDF + evidence + remediation)
│   └── pdf.py                  # CISO-ready PDF export (reportlab, vector charts)
│
├── adapters/                   # Framework adapters (lazy imports, zero lock-in)
│   ├── langchain.py            # LangChain AgentExecutor adapter
│   ├── langgraph.py            # LangGraph compiled StateGraph adapter
│   ├── crewai.py               # CrewAI Crew adapter
│   └── generic.py              # Callable adapter for any Python agent
│
├── mcpsec/                     # MCP security scanner (poisoning, drift, shadowing)
│   ├── manifest.py             # Tool-definition model + manifest loaders
│   ├── detectors.py            # Static ruleset over MCP tool definitions
│   ├── probe.py                # Live stdio/HTTP protocol probe + drift check
│   └── report.py               # Scan scoring and Markdown/JSON reports
│
├── hardening.py                # @tool_guard runtime + remediation code generator
├── gateway.py                  # Runtime PolicyGateway with tamper-evident audit chain
│
└── cli/                        # Unified Command-Line Interface
    ├── main.py                 # Commands: run, survey, test, eval, compare, mcp-serve, ui,
    │                          #   leaderboard, report, harden, audit, gateway, domains,
    │                          #   quickstart, mcp-scan
    └── quickstart.py           # Framework auto-detection + harness generation
```

---

## Test Suite

LIFE FORGE maintains an extensive test suite verifying algorithm determinism, tool execution, and regression immunity:

```bash
pytest -q
# 438 passed
```

---

## Examples & Programmatic API

Check the [`examples/`](examples/) directory for self-contained, runnable Python integration scripts:
* [`examples/quickstart_stress_test.py`](examples/quickstart_stress_test.py): Programmatically execute an evolutionary red-teaming search and generate audit reports.
* [`examples/custom_agent_evaluation.py`](examples/custom_agent_evaluation.py): Plug custom Python agent state machines, LangChain, or CrewAI agents directly into the simulation sandbox.
* [`examples/webhook_agent_server.py`](examples/webhook_agent_server.py): Standalone mock agent HTTP server ready for webhook evaluation.

---

## License & Citation

Licensed under the [MIT License](LICENSE).

If you use LIFE FORGE in your research or evaluations, please cite using [CITATION.cff](CITATION.cff).