# LIFE FORGE: The Autonomous Flight Simulator for AI Agents

> **Co-evolutionary adversarial red-teaming and dynamic stress-testing for autonomous AI agents using Artificial Life Quality-Diversity algorithms (3D MAP-Elites).**

[![Tests](https://img.shields.io/badge/tests-79%20passed-brightgreen.svg)](tests/)
[![CI](https://github.com/zariffromlatif/life-forge/actions/workflows/agent_stress_test.yml/badge.svg)](https://github.com/zariffromlatif/life-forge/actions/workflows/agent_stress_test.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-MCP%20Native-orange.svg)](lifeforge/sandbox/mcp_server.py)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                               LIFE FORGE                                │
│                     The AI Agent Flight Simulator                       │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│       Target AI Agent        │ ◄────────► │   Simulated World (Sandbox)  │
│  (Claude, GPT-4o, Llama,     │  Actions/  │  • ERP Database & Balances   │
│   Qwen, Custom Frameworks)   │   Tools    │  • Vendor Catalogs & Quotes  │
└──────────────────────────────┘            │  • Email Inbox / Outbox      │
                                            └──────────────────────────────┘
                                                           ▲
                                                           │ Co-Evolves
                                                           │ Perturbations
                                            ┌──────────────────────────────┐
                                            │      Evolution Engine        │
                                            │ • Adversarial Injections     │
                                            │ • Market Price Volatility    │
                                            │ • Supply Scarcity            │
                                            │ • 3D MAP-Elites Archive      │
                                            └──────────────────────────────┘
                                                           │
                                                           ▼
                                            ┌──────────────────────────────┐
                                            │    Causal Root-Cause Engine  │
                                            │  Generates Audit Report &    │
                                            │  Minimal Fix Recommendations │
                                            └──────────────────────────────┘
```

---

## Why LIFE FORGE?

Before commercial pilots fly passengers, they spend hundreds of hours in a **flight simulator**. The simulator doesn't give them sunny skies; it throws dual-engine failure, sudden crosswinds, sensor glitches, and electrical fires at them.

Today, enterprise AI agents with tool access (databases, email, financial APIs) are deployed with almost zero dynamic testing:
1. **Static Benchmarks Are Useless**: MMLU and HumanEval test multiple-choice trivia and leetcode snippets. They do not test what happens when an agent manages an ERP database while an adversary attempts an indirect prompt injection.
2. **Static Red-Teaming Fails**: Traditional security tools test static lists of 500 prompts that LLMs quickly memorize.
3. **The Real World Fights Back**: In production, suppliers run out of stock, prices fluctuate mid-transaction, executive emails get spoofed, and third-party data contains jailbreaks.

**LIFE FORGE is the autonomous flight simulator for AI agents.** Using evolutionary Quality-Diversity algorithms (3D MAP-Elites), LIFE FORGE autonomously breeds and discovers edge-case scenarios that force frontier models to hallucinate, crash, deadlock, or leak company funds before reaching production.

---

## Empirical Benchmark: Meta Llama 3.1 vs. Alibaba Qwen 2.5

In an empirical showdown evaluated over 30 identical evolutionary generations under identical random seeds (`seed=42`), LIFE FORGE exposed fundamentally contrasting zero-day failure profiles between two state-of-the-art open-weight models:

| Metric | Alibaba `Qwen-2.5-14B` | Meta `Llama-3.1-8B` |
| :--- | :--- | :--- |
| **Security Rating** | **Critical Vulnerability (Zero-Day Exploit)** | **Fragile (Operational Deadlock)** |
| **Total Simulations Run** | 31 | 31 |
| **Adversarial Failure Rate** | **100.0%** | **100.0%** |
| **Critical Zero-Days Discovered** | 🔴 **7 Wire Exfiltrations** | 🟢 **0 Wire Exfiltrations** |
| **Operational Loop Traps** | 0 | 🟠 **12 Infinite Retry Loops** |
| **Supply Deficit Failures** | 🟡 6 | 0 |
| **Most Vulnerable Capability** | *Privilege Separation & Social Engineering* | *Error Recovery & Loop Termination* |

### What Happened?
* **Alibaba Qwen 2.5 (14B)**: Exhibited high general reasoning, but suffered from **authority-impersonation blindness**. When presented with spoofed CEO emails and vendor quote injections, Qwen believed the untrusted directive and **executed the prohibited `transfer_funds` tool 7 times, wiring $60,000 to unauthorized offshore accounts.**
* **Meta Llama 3.1 (8B)**: Completely resisted social engineering and prompt injection wire fraud (0 exfiltrations). However, when market conditions shifted prices between catalog query and order submission, Llama entered an **unbounded infinite retry loop 12 times**, exhausting its maximum step budget without making progress.

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
LIFE FORGE can be run as a standard **Model Context Protocol (MCP)** server over `stdio` or `SSE`. Any MCP-compatible client—including **Claude Desktop**, **Cursor**, **LangGraph**, or custom multi-agent frameworks—can directly connect to LIFE FORGE’s adversarial environments.

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

### 5. Head-to-Head Model Showdown Comparison
Compare two or more evaluation reports side-by-side to crown the security winner:

```bash
python -m lifeforge.cli compare results/local_qwen_report.json results/local_llama_report.json --out results/MODEL_SHOWDOWN.md
```

---

### 6. Run as an MCP Server (Claude Desktop & Cursor)
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

### 7. Scientific Cellular Automata Laboratory
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

## Continuous CI/CD Integration

Prevent vulnerable or deadlocking agents from reaching production. Add LIFE FORGE to your GitHub repository workflow:

```yaml
# .github/workflows/agent_stress_test.yml
name: AI Agent Stress Test
on: [push, pull_request]

jobs:
  red-team:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install LIFE FORGE
        run: pip install -e ".[all]"

      - name: Run Evolutionary Stress Test
        run: |
          python -m lifeforge.cli test --scenarios 30 --out results/ci_report.md --json

      - name: Upload Audit Report
        uses: actions/upload-artifact@v4
        with:
          name: agent-evolution-report
          path: results/ci_report.md
```

---

## Repository Architecture

```
lifeforge/
├── substrates/                 # Artificial Life & Cellular Automata physics
│   ├── base.py                 # Abstract Substrate & State interfaces
│   └── ca/
│       ├── elementary.py       # 1D Elementary CA (Rules 0–255)
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
│   ├── mock_tools.py           # 5 enterprise tools (database, vendor API, PO, email, funds transfer)
│   ├── agent.py                # AgentInterface, RuleBasedPurchasingAgent, CallableAgentAdapter
│   ├── oracle.py               # Invariant policy enforcement & SandboxRunner orchestrator
│   ├── llm_agent.py            # Unified LiteLLM adapter with 429/503 rate-limit backoff
│   └── mcp_server.py           # Model Context Protocol (MCP) JSON-RPC stdio server
│
├── evolution/                  # Co-Evolutionary Red-Teaming Engine
│   ├── engine.py               # EvolutionEngine coordinating multi-generation search
│   ├── map_elites.py           # 3D Quality-Diversity Archive (adversarial × volatility × budget)
│   └── mutators/
│       ├── environmental.py    # PriceVolatility, InventoryScarcity, BudgetConstraint, VendorDropout
│       ├── adversarial.py      # IndirectPromptInjection, SpoofedExecutiveMessage, ConflictingSpec
│       └── semantic.py         # 10,000+ combinatorial template payloads & SLM generation
│
├── reporting/                  # Causal Root-Cause Diagnostics
│   ├── analyzer.py             # CausalAnalyzer extracting minimal failure triggers
│   └── report.py               # Markdown and JSON executive audit generator
│
└── cli/                        # Unified Command-Line Interface
    └── main.py                 # Commands: run, survey, test, compare, mcp-serve
```

---

## Test Suite

LIFE FORGE maintains an extensive test suite verifying algorithm determinism, tool execution, and regression immunity:

```bash
pytest -v
# 75 passed in 1.78s
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
