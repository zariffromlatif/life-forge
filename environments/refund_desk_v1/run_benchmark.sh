#!/usr/bin/env bash
# LIFE FORGE: Power PC Benchmark Runner for refund-desk-v1
# Runs 37 scenarios across the target model fleet and outputs evaluation logs.

set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${ENV_DIR}/benchmark_results"
mkdir -p "${RESULTS_DIR}"

echo "=========================================================="
echo "  LIFE FORGE -- Power PC Benchmark Fleet Runner"
echo "  Target: refund-desk-v1 (37 scenarios)"
echo "=========================================================="

# 1. Model-Free Ground Truth Validation
echo "[1/4] Running model-free verification (vf-validate)..."
vf-validate refund-desk-v1

# 2. Candidate Models Fleet (Ollama endpoints)
MODELS=(
    "ollama/llama3.1:8b"
    "ollama/qwen2.5:14b"
    "ollama/deepseek-r1:14b"
    "ollama/qwen2.5-coder:14b"
)

# Optional: Add 24B if pulled:
# MODELS+=("ollama/mistral-small:24b")

echo "[2/4] Starting model evaluation across ${#MODELS[@]} models..."

for MODEL in "${MODELS[@]}"; do
    CLEAN_NAME=$(echo "${MODEL}" | tr '/:' '__')
    OUT_FILE="${RESULTS_DIR}/${CLEAN_NAME}.json"
    
    echo "----------------------------------------------------------"
    echo "Evaluating: ${MODEL}"
    echo "Output: ${OUT_FILE}"
    echo "----------------------------------------------------------"
    
    vf-eval refund-desk-v1 -m "${MODEL}" --output "${OUT_FILE}" || {
        echo "WARNING: Evaluation for ${MODEL} exited with non-zero status. Continuing with remaining fleet..."
    }
done

echo "[3/4] Compiling benchmark results matrix..."
python3 "${ENV_DIR}/compile_benchmark.py" "${RESULTS_DIR}"

echo "=========================================================="
echo "  Benchmark run complete! Results saved in ${RESULTS_DIR}"
echo "=========================================================="
