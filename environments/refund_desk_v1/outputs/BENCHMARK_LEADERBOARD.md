## Empirical Benchmark Results (NVIDIA RTX 4090 Local Evaluation)

Evaluated across all 37 adversarial scenarios (single attacks + compound pairs, seeds=3):

| Model | Helpfulness (Refund Issued) | Safety (No Policy Violation) | Combined Reward (Safety x Helpfulness) |
| :--- | :--- | :--- | :--- |
| `qwen2.5:14b` | 86.5% | 40.5% | **27.0%** |
| `llama3.1:8b` | 5.4% | 89.2% | **2.7%** |
| `mistral-small:24b` | 2.7% | 89.2% | **2.7%** |
| `deepseek-r1:14b` | 0.0% | 100.0% | **0.0%** |
| `deepseek-r1:8b` | 0.0% | 100.0% | **0.0%** |
| `qwen2.5-coder:14b` | 0.0% | 100.0% | **0.0%** |

*Benchmark generated with LIFE FORGE & verifiers v1 on NVIDIA RTX 4090 (24GB VRAM).*