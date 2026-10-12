#!/usr/bin/env bash
# refund-desk-v1 benchmark runner (free: local Ollama models only by default).
#
#   git pull && bash environments/refund_desk_v1/run_benchmark.sh
#
# Safe to re-run: a model whose run already has results is resumed (missing or
# errored rollouts only), never overwritten. Everything is configurable through
# environment variables, e.g.:
#
#   ROLLOUTS=3 MODELS="qwen2.5:14b qwen3:14b" bash run_benchmark.sh
#   PULL=1 bash run_benchmark.sh            # also `ollama pull` models that are missing
#   DRY_RUN=1 bash run_benchmark.sh         # validate configs only, run nothing
#
# Optional free "ceiling" model on an OpenAI-compatible endpoint (e.g. a free tier):
#   CEILING_MODEL=<model-id> CEILING_BASE_URL=<https://.../v1> CEILING_KEY_VAR=<ENV_VAR_WITH_KEY>
#
# Uses verifiers' own console scripts from the active virtualenv by full path
# (bare `eval` is a shell builtin). Results are NOT uploaded anywhere (--no-push).
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${ENV_DIR}/outputs/benchmark_v2}"
ROLLOUTS="${ROLLOUTS:-5}"            # samples per task (-r)
TEMPERATURE="${TEMPERATURE:-0.7}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
MODELS="${MODELS:-qwen2.5:14b llama3.1:8b mistral-small:24b qwen3:14b gpt-oss:20b}"
PULL="${PULL:-0}"
DRY_RUN="${DRY_RUN:-0}"
export OLLAMA_API_KEY="${OLLAMA_API_KEY:-ollama}"

VENV="${VIRTUAL_ENV:-$HOME/env}"
pick_bin() {  # verifiers 0.3.1 names them eval/validate; later builds vf-eval/vf-validate
    for name in "$@"; do
        if [ -x "${VENV}/bin/${name}" ]; then echo "${VENV}/bin/${name}"; return 0; fi
    done
    return 1
}
EVAL_BIN="$(pick_bin eval vf-eval)" || { echo "No verifiers eval command in ${VENV}/bin (activate your venv)"; exit 1; }
VALIDATE_BIN="$(pick_bin validate vf-validate)" || { echo "No verifiers validate command in ${VENV}/bin"; exit 1; }

echo "=============================================================="
echo " refund-desk-v1 benchmark"
echo "  models      : ${MODELS}"
echo "  samples/task: ${ROLLOUTS} at temperature ${TEMPERATURE} (37 tasks)"
echo "  output      : ${OUTPUT_DIR}"
echo "  harness     : RefundDeskHarness (package default; chat + desk tools, no shell)"
echo "=============================================================="

# 0. Pre-flight: the installed environment must be the current one (0.2.0+ ships the
#    no-shell harness), and Ollama must be reachable.
python - <<'EOF'
import importlib.metadata as m, sys
version = tuple(int(x) for x in m.version("refund-desk-v1").split(".")[:2])
if version < (0, 2):
    sys.exit(f"refund-desk-v1 {m.version('refund-desk-v1')} is installed; 0.2.0+ is required "
             "(pip install -e environments/refund_desk_v1 or prime env install zariffromlatif/refund-desk-v1)")
from refund_desk_v1 import RefundDeskHarness
assert RefundDeskHarness.EXECUTES_CODE is False
print(f"refund-desk-v1 {m.version('refund-desk-v1')}, lifeforge {m.version('lifeforge')}: OK")
EOF
if [ "${DRY_RUN}" != "1" ]; then
    curl -sf "${OLLAMA_URL}/api/version" >/dev/null || { echo "Ollama is not reachable at ${OLLAMA_URL}"; exit 1; }
    # Ollama's default context window (a few thousand tokens) silently truncates the
    # longest scenarios. It is a server setting, so this script cannot change it.
    if [ -z "${OLLAMA_CONTEXT_LENGTH:-}" ]; then
        echo "WARNING: start Ollama with a larger context, e.g.  OLLAMA_CONTEXT_LENGTH=16384 ollama serve"
        echo "         (the first local run likely truncated long prompts). Ctrl-C now to fix, or wait 10s."
        sleep 10
    fi
fi

echo "[1/3] Model-free validation..."
"${VALIDATE_BIN}" refund-desk-v1 --runtime.type subprocess --clean -o "${OUTPUT_DIR}/_validate"

has_model() { curl -sf "${OLLAMA_URL}/api/tags" | python3 -c 'import json,sys; names={m["name"] for m in json.load(sys.stdin)["models"]}; sys.exit(0 if sys.argv[1] in names or sys.argv[1]+":latest" in names else 1)' "$1"; }
supports_tools() { curl -sf "${OLLAMA_URL}/api/show" -d "{\"model\": \"$1\"}" | python3 -c 'import json,sys; sys.exit(0 if "tools" in json.load(sys.stdin).get("capabilities", []) else 1)'; }

run_eval() {  # $1 model, $2 run name, $3 base url, $4 api key var
    local model="$1" run="$2" base_url="$3" key_var="$4"
    local saved="${OUTPUT_DIR}/${run}/configs/resolved/eval.json"
    if [ "${DRY_RUN}" = "1" ]; then
        "${EVAL_BIN}" refund-desk-v1 -m "${model}" --client.base-url "${base_url}" --client.api-key-var "${key_var}" \
            -r "${ROLLOUTS}" --sampling.temperature "${TEMPERATURE}" -c 1 --run.name "${run}" -o "${OUTPUT_DIR}" \
            --no-push --dry-run
        return
    fi
    if [ -s "${OUTPUT_DIR}/${run}/traces.jsonl" ] && [ -f "${saved}" ]; then
        echo "  resuming existing run (missing/errored rollouts only)"
        "${EVAL_BIN}" @ "${saved}" --resume
    else
        "${EVAL_BIN}" refund-desk-v1 -m "${model}" --client.base-url "${base_url}" --client.api-key-var "${key_var}" \
            -r "${ROLLOUTS}" --sampling.temperature "${TEMPERATURE}" -c 1 --run.name "${run}" -o "${OUTPUT_DIR}" \
            --no-push
    fi
}

echo "[2/3] Evaluating..."
START=$(date +%s)
for MODEL in ${MODELS}; do
    RUN="eval_$(echo "${MODEL}" | tr '.:/' '___')"
    echo "--------------------------------------------------------------"
    echo " ${MODEL}  ->  ${RUN}"
    if [ "${DRY_RUN}" = "1" ]; then
        run_eval "${MODEL}" "${RUN}" "${OLLAMA_URL}/v1" OLLAMA_API_KEY
        continue
    fi
    if ! has_model "${MODEL}"; then
        if [ "${PULL}" = "1" ]; then
            ollama pull "${MODEL}"
        else
            echo " SKIP: not installed in Ollama (run 'ollama pull ${MODEL}' or set PULL=1)"
            continue
        fi
    fi
    if ! supports_tools "${MODEL}"; then
        echo " SKIP: Ollama reports no native tool calling for ${MODEL} (would not be measurable)"
        continue
    fi
    T0=$(date +%s)
    run_eval "${MODEL}" "${RUN}" "${OLLAMA_URL}/v1" OLLAMA_API_KEY || echo " WARNING: ${MODEL} exited non-zero; re-run this script to resume it."
    echo " ${MODEL} took $(( ($(date +%s) - T0) / 60 )) min"
done

if [ -n "${CEILING_MODEL:-}" ]; then
    : "${CEILING_BASE_URL:?set CEILING_BASE_URL}" "${CEILING_KEY_VAR:?set CEILING_KEY_VAR}"
    RUN="eval_ceiling_$(echo "${CEILING_MODEL}" | tr '.:/' '___')"
    echo "--------------------------------------------------------------"
    echo " ceiling: ${CEILING_MODEL}  ->  ${RUN}"
    run_eval "${CEILING_MODEL}" "${RUN}" "${CEILING_BASE_URL}" "${CEILING_KEY_VAR}" || echo " WARNING: ceiling model exited non-zero"
fi

if [ "${DRY_RUN}" = "1" ]; then
    echo "Dry run complete: configs resolved and validated, nothing evaluated."
    exit 0
fi

echo "[3/3] Compiling results..."
python3 "${ENV_DIR}/compile_benchmark.py" "${OUTPUT_DIR}"
echo "Done in $(( ($(date +%s) - START) / 60 )) min. Commit ${OUTPUT_DIR} and push."
