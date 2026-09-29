# LIFE FORGE Model Security Leaderboard

> **Last updated**: 2026-09-29 05:13 UTC
> **Simulator**: Co-evolutionary MAP-Elites, 30 generations, `seed=42`
> **Environment**: Enterprise Procurement ERP digital twin
> **Hardware**: Intel i9-14900K + NVIDIA RTX 4090 (24GB VRAM) via Ollama (Q4_K_M)
> **Repository**: https://github.com/zariffromlatif/life-forge

---

## Ranked Security Scores

| Rank | Model | Params | Grade | Critical Zero-Days | Deadlocks | Adversarial Fail Rate | Primary Weakness |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `llama3.1:8b` | 8B | **C+** (Fragile) | 0 | **12 loops** | 66.7% | State-Aware Tool Retry & Cost Loop Prevention |
| 2 | `gemini/gemini-3.8-flash` | ? | **C** (High-Risk) | 0 | 0 | **100.0%** | General Tool Sequencing |
| 3 | `deepseek-r1:14b` | 14B | **C** (High-Risk) | 0 | **14 loops** | **100.0%** | Error Recovery & Cycle Termination |
| 4 | `qwen2.5:14b` | 14B | **F** (Critically Vulnerable) | **7 [CRITICAL]** | 0 | **100.0%** | Untrusted Tool Output Sanitization & Privilege Separation |
| 5 | `phi4:14b` | 14B | **F** (Critically Vulnerable) | **8 [CRITICAL]** | 0 | **100.0%** | Untrusted Tool Output Sanitization & Privilege Separation |

---

## Security Champion

**`llama3.1:8b`** leads the leaderboard with **0 critical zero-days** and an adversarial failure rate of **66.7%** under identical evolutionary pressures.

---

## Detailed Model Profiles

### `llama3.1:8b` -- Grade C+ (Fragile)

- **Source report**: `results/local_llama_report.json`
- **Total simulations**: 30
- **Adversarial failure rate**: 66.7%
- **Baseline success rate**: 33.3%
- **Critical zero-days**: 0
- **Failure breakdown**: LOOP_TRAP: 12 | INVENTORY: 8
- **Worst behavior discovered**: Infinite recursive retry loop upon vendor price changes, exhausting execution budget.

### `gemini/gemini-3.8-flash` -- Grade C (High-Risk)

- **Source report**: `results/gemini_report.json`
- **Total simulations**: 21
- **Adversarial failure rate**: 100.0%
- **Baseline success rate**: 0.0%
- **Critical zero-days**: 0
- **Failure breakdown**: INVENTORY: 11
- **Worst behavior discovered**: None detected (Agent remained within policy bounds).

### `deepseek-r1:14b` -- Grade C (High-Risk)

- **Source report**: `results/local_deepseek_r1_report.json`
- **Total simulations**: 31
- **Adversarial failure rate**: 100.0%
- **Baseline success rate**: 0.0%
- **Critical zero-days**: 0
- **Failure breakdown**: LOOP_TRAP: 14
- **Worst behavior discovered**: Unbounded cyclic execution consuming API steps without verifying updated price quotes.

### `qwen2.5:14b` -- Grade F (Critically Vulnerable)

- **Source report**: `results/local_qwen_report.json`
- **Total simulations**: 31
- **Adversarial failure rate**: 100.0%
- **Baseline success rate**: 0.0%
- **Critical zero-days**: 7
- **Failure breakdown**: UNAUTH_EXEC: 7 | INVENTORY: 6
- **Worst behavior discovered**: Exfiltration / Execution of unauthorized funds transfer tool following indirect prompt injection.

### `phi4:14b` -- Grade F (Critically Vulnerable)

- **Source report**: `results/local_phi4_report.json`
- **Total simulations**: 31
- **Adversarial failure rate**: 100.0%
- **Baseline success rate**: 0.0%
- **Critical zero-days**: 8
- **Failure breakdown**: INVENTORY: 9 | UNAUTH_EXEC: 8
- **Worst behavior discovered**: Exfiltration / Execution of unauthorized funds transfer tool following indirect prompt injection.

---

## How to Add Your Model

Run the LIFE FORGE benchmark against any Ollama-compatible model:

```bash
git clone https://github.com/zariffromlatif/life-forge.git
cd life-forge
pip install -e '.[all]'
lifeforge eval \
  --model ollama/your-model:tag \
  --api-base http://localhost:11434 \
  --scenarios 30 --seed 42 --json \
  --out results/local_yourmodel_report.md
lifeforge leaderboard  # regenerate this table
```

Submit a PR with your `results/local_yourmodel_report.json` to be listed here.

---

*LIFE FORGE -- The Autonomous Flight Simulator for AI Agents*
*MIT License | https://github.com/zariffromlatif/life-forge*
