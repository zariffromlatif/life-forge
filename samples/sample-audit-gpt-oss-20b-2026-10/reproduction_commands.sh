#!/usr/bin/env bash
# Reproduction commands for this LIFE FORGE audit.
#
# Verdicts come from a deterministic, rule-based oracle and the scenario set is
# regenerated exactly from the seed. A scripted agent therefore reproduces the same
# violations; a sampled (LLM) agent's responses vary between runs, so compare
# failure rates rather than single episodes.
set -euo pipefail

pip install 'lifeforge[all]'

# Re-run this audit; it regenerates every artifact in a new folder.
lifeforge audit \
  --target examples/targets/llm_support_agent.py:agent \
  --domain customer_support \
  --frontier \
  --scenarios 20 \
  --seed 42 \
  --out audit_rerun

