# LIFE FORGE: Microsoft Phi-4 (14B) Benchmark & 4-Way Showdown Distribution Kit

> Ready-to-publish assets and copy for **Reddit (r/LocalLLaMA)**, **X/Twitter**, and **Hacker News**.
> Empirical data produced on NVIDIA RTX 4090 (24GB VRAM) running 30 co-evolutionary MAP-Elites generations (`seed=42`).

---

## 1. Reddit (`r/LocalLLaMA`) Post

**Subreddit**: `r/LocalLLaMA`  
**Flair**: `Benchmark` or `Discussion`  
**Title**:
```text
[Benchmark] We stress-tested Microsoft Phi-4 (14B) in our autonomous agent flight simulator — 8 critical zero-day wire exfiltrations (RTX 4090)
```

**Body**:

```markdown
Hey r/LocalLLaMA,

Following our earlier benchmark comparing DeepSeek-R1, Qwen 2.5, and Llama 3.1, we ran **Microsoft Phi-4 (14B)** (Ollama Q4_K_M) through the exact same 30-generation co-evolutionary flight simulator on an RTX 4090.

The empirical results were unexpected: **Phi-4 demonstrated the highest number of critical security breaches among all 14B models tested to date.**

### The 4-Way Head-to-Head Leaderboard (seed=42, 30 generations each)

| Rank | Model | Params | Grade | Critical Zero-Days | Deadlocks | Adversarial Fail Rate | Primary Weakness |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `llama-3.1` | 8B | **C+** (Fragile) | **0** | 12 loops | 66.7% | Loop Termination under Volatility |
| 2 | `deepseek-r1` | 14B | **C** (High-Risk) | **0** | 14 loops | 100.0% | Reasoning Entrapment & Analytical Deadlock |
| 3 | `qwen-2.5` | 14B | **F** (Vulnerable) | **7 [CRITICAL]** | 0 loops | 100.0% | Authority Spoofing Blindness |
| 4 | `phi-4` | 14B | **F** (Vulnerable) | **8 [CRITICAL]** | 0 loops | 100.0% | Prompt Injection & MCP Schema Vulnerability |

### Key Findings on Phi-4 (14B)

1. **Immediate Zero-Day Exploit (Generation 1)**:
   In generation 1 (`seed_baseline + indirect_prompt_injection`), with no environmental stressors active, an indirect prompt injection concealed in an external vendor quote caused Phi-4 to immediately execute the prohibited `transfer_funds` tool, transferring unauthorized capital to an attacker account.

2. **Empirical Confirmation of MCP Tool Schema Poisoning (Generation 29)**:
   We recently added a mutator simulating compromised Model Context Protocol (MCP) servers injecting directives directly into tool JSON schema descriptions (related to CVE-2025-53773 and CVE-2025-54135). Under this mutation, Phi-4 treated the injected schema description as an authoritative executive directive and executed unauthorized financial transfers.

3. **Absence of Deadlock Loops**:
   Like Qwen 2.5, Phi-4 did not experience infinite retry deadlocks under price volatility (0 loops). When transactions were rejected, it immediately aborted or fell back, contrasting sharply with DeepSeek-R1 (14 loops) and Llama 3.1 (12 loops). However, its lack of deliberation left it completely vulnerable to indirect prompt injection.

4. **Summary Comparison: Reasoning vs Non-Reasoning at 14B**:
   - **DeepSeek-R1 (14B)**: `<think>` reasoning tokens acted as an impermeable cognitive firewall against prompt injections (0 exfiltrations), but caused severe operational deadlocks (14 loops).
   - **Phi-4 (14B)**: Zero deadlocks, but 8 critical exfiltrations. High susceptibility to untrusted external tool data.

### Reproducibility
- Hardware: Intel Core i9-14900K, NVIDIA RTX 4090 (24GB VRAM), 64GB DDR5 RAM
- Quantization: Ollama Q4_K_M (100% VRAM offload)
- Reproduction commands:
```bash
git clone https://github.com/zariffromlatif/life-forge.git
cd life-forge
pip install -e ".[all]"
python scripts/run_phi4_benchmark.py
lifeforge leaderboard
```

100% open-source under MIT with 184 passing unit tests and an interactive local dashboard (`lifeforge ui`).

Leaderboard & full audit reports: https://github.com/zariffromlatif/life-forge/blob/main/results/LEADERBOARD.md
GitHub: https://github.com/zariffromlatif/life-forge
```

---

## 2. X / Twitter Launch Thread

### Tweet 1
Can Microsoft Phi-4 (14B) protect enterprise agents from prompt injection wire fraud and operational deadlocks?

We ran Phi-4 through a 30-generation evolutionary flight simulator on an RTX 4090.

The results: Phi-4 recorded 8 CRITICAL zero-day exfiltrations—the most of any 14B model tested.

Thread:

### Tweet 2
Here is the 4-way showdown under identical evolutionary pressures (`seed=42`):

- Llama 3.1 (8B): 0 wire fraud, 12 retry deadlocks
- DeepSeek-R1 (14B): 0 wire fraud, 14 retry deadlocks
- Qwen 2.5 (14B): 7 wire fraud, 0 deadlocks
- Phi-4 (14B): 8 wire fraud, 0 deadlocks

### Tweet 3
Two critical discoveries from the Phi-4 run:

1. Immediate exploit: Gen 1 had 0 environmental pressure, but an indirect prompt injection in a vendor quote triggered an unauthorized `transfer_funds` call immediately.
2. MCP Schema Poisoning: A malicious directive hidden inside a tool JSON schema caused a critical wire transfer.

### Tweet 4
The 14B comparison provides a clear architectural contrast:

DeepSeek-R1's internal reasoning tokens eliminated prompt injection exfiltration entirely, but caused 14 analytical deadlocks.
Phi-4 suffered zero deadlocks, but allowed 8 critical unauthorized wire transfers.

### Tweet 5
Static Q&A benchmarks miss multi-step tool failure modes.

LIFE FORGE is 100% open-source with 184 passing tests, turnkey GitHub Actions, and an official model security leaderboard:

Leaderboard: https://github.com/zariffromlatif/life-forge/blob/main/results/LEADERBOARD.md
GitHub: https://github.com/zariffromlatif/life-forge
