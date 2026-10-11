#!/usr/bin/env bash
# LIFE FORGE: Power PC Benchmark Runner for refund-desk-v1
# Runs 37 scenarios across target models using local Ollama on RTX 4090.

set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUTS_DIR="${ENV_DIR}/outputs"
export OLLAMA_API_KEY="ollama"

echo "=========================================================="
echo "  LIFE FORGE -- Power PC Benchmark Fleet Runner"
echo "  Target: refund-desk-v1 (37 scenarios)"
echo "  Hardware: RTX 4090 (24GB VRAM) via Ollama"
echo "=========================================================="

VIRTUAL_ENV="${VIRTUAL_ENV:-$HOME/env}"
VALIDATE_BIN="${VIRTUAL_ENV}/bin/validate"
EVAL_BIN="${VIRTUAL_ENV}/bin/eval"

# 1. Model-Free Ground Truth Validation
echo "[1/3] Running model-free verification (validate)..."
"${VALIDATE_BIN}" refund-desk-v1 --runtime.type subprocess --clean

# 2. Candidate models (Ollama). The taskset's own harness (RefundDeskHarness: chat + desk
#    tools, no shell) is used by default; do not pass a --env.agent.harness override.
MODELS=(
    "llama3.1:8b"
    "qwen2.5:14b"
    "qwen2.5-coder:14b"
    "deepseek-r1:8b"
    "deepseek-r1:14b"
    "mistral-small:24b"
)

echo "[2/3] Starting model evaluation across ${#MODELS[@]} models..."

# Ollama reports per-model capabilities. A model without native tool calling cannot
# call the desk's tools, so its result would measure the serving stack, not the model.
supports_tools() {
    curl -s http://localhost:11434/api/show -d "{\"model\": \"$1\"}"         | python3 -c 'import json,sys; sys.exit(0 if "tools" in json.load(sys.stdin).get("capabilities", []) else 1)'
}

for MODEL in "${MODELS[@]}"; do
    if ! supports_tools "${MODEL}"; then
        echo "SKIP ${MODEL}: Ollama reports no native tool-calling support (result would not be measurable)."
        continue
    fi
    RUN_NAME="eval_$(echo "${MODEL}" | tr '.:/' '___')"
    echo "----------------------------------------------------------"
    echo "Evaluating: ${MODEL}"
    echo "Run name: ${RUN_NAME}"
    echo "----------------------------------------------------------"

    "${EVAL_BIN}" refund-desk-v1 \
        -m "${MODEL}" \
        --client.base-url http://localhost:11434/v1 \
        --client.api-key-var OLLAMA_API_KEY \
        --env.agent.runtime.type subprocess \
        --run.name "${RUN_NAME}" \
        --clean \
        -c 1 \
        --no-push || {
        echo "WARNING: Evaluation for ${MODEL} exited with non-zero status. Continuing with remaining fleet..."
    }
done

echo "[3/3] Compiling benchmark results matrix..."
python3 "${ENV_DIR}/compile_benchmark.py" "${OUTPUTS_DIR}"

echo "=========================================================="
echo "  Benchmark fleet complete! Leaderboard updated."
echo "=========================================================="

