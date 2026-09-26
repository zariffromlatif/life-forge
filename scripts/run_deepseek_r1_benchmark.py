#!/usr/bin/env python3
"""
Pre-Flight Runner & Automated Benchmark for DeepSeek-R1 on Local RTX 4090 GPU.

Evaluates DeepSeek-R1 (14B or 8B) across 30 identical evolutionary generations
(seed=42) to analyze whether reasoning tokens (<think>...</think>) protect agents
from prompt injection wire fraud or trigger cyclic reasoning deadlock loops.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


def check_ollama_service(api_base: str = "http://localhost:11434") -> list[str]:
    """Verify Ollama is reachable and return list of available models."""
    url = f"{api_base.rstrip('/')}/api/tags"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LifeForge-Preflight/1.0"})
        with urllib.request.urlopen(req, timeout=5.0) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                return models
    except urllib.error.URLError:
        return []
    return []


def main() -> None:
    parser = argparse.ArgumentParser(description="LIFE FORGE: DeepSeek-R1 Benchmark Harness")
    parser.add_argument(
        "--model",
        type=str,
        default="ollama/deepseek-r1:14b",
        help="Model identifier (default: ollama/deepseek-r1:14b)",
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default="http://localhost:11434",
        help="Ollama API base URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--scenarios",
        type=int,
        default=30,
        help="Number of evolutionary scenarios (default: 30)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed matching prior runs (default: 42)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Run pre-flight connectivity checks without executing simulation",
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  LIFE FORGE -- DeepSeek-R1 Empirical Flight Simulation Harness")
    print("=" * 65)

    clean_model_name = args.model.replace("ollama/", "")

    # 1. Pre-flight check: Ollama connectivity
    print(f"\n[*] Checking Ollama service at {args.api_base}...")
    available_models = check_ollama_service(args.api_base)

    if not available_models:
        print("\n[FAIL] Ollama service not detected on localhost:11434.")
        print("       Please ensure Ollama is running:")
        print("         ollama serve")
        sys.exit(1)

    print(f"[OK] Ollama is active. Available models: {', '.join(available_models) if available_models else 'None'}")

    # 2. Check model presence
    matched_models = [m for m in available_models if clean_model_name in m or m.startswith(clean_model_name)]
    if not matched_models:
        print(f"\n[WARN] Model '{clean_model_name}' is not yet downloaded in Ollama.")
        print(f"       Run the following command to pull it onto your GPU:")
        print(f"         ollama pull {clean_model_name}")
        print("\n       Alternative lightweight model for quick validation:")
        print("         ollama pull deepseek-r1:8b")
        if args.check_only:
            sys.exit(1)
        print("\n       Aborting execution until model is pulled.")
        sys.exit(1)
    else:
        print(f"[OK] Model '{matched_models[0]}' is ready on GPU.")

    if args.check_only:
        print("\n[OK] Pre-flight verification completed successfully.")
        return

    # 3. Execute evolutionary flight simulation
    out_md = Path("results/local_deepseek_r1_report.md")
    out_json = Path("results/local_deepseek_r1_report.json")
    out_md.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "lifeforge.cli",
        "test",
        "--model",
        args.model,
        "--api-base",
        args.api_base,
        "--scenarios",
        str(args.scenarios),
        "--seed",
        str(args.seed),
        "--out",
        str(out_md),
        "--json",
    ]

    print(f"\n[*] Executing 30-scenario evolutionary stress test (seed={args.seed})...")
    print(f"    Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd)

    if result.returncode != 0 and not out_json.exists():
        print(f"\n[FAIL] Flight simulation exited with code {result.returncode}")
        sys.exit(result.returncode)

    print(f"\n[OK] DeepSeek-R1 evaluation report saved: {out_md}")

    # 4. Automated 3-way showdown comparison if Qwen and Llama reports exist
    qwen_json = Path("results/local_qwen_report.json")
    llama_json = Path("results/local_llama_report.json")
    showdown_out = Path("results/THREE_WAY_MODEL_SHOWDOWN.md")

    if qwen_json.exists() and llama_json.exists() and out_json.exists():
        print("\n[*] Generating 3-Way Model Showdown Comparison Matrix...")
        compare_cmd = [
            sys.executable,
            "-m",
            "lifeforge.cli",
            "compare",
            str(qwen_json),
            str(llama_json),
            str(out_json),
            "--out",
            str(showdown_out),
        ]
        compare_res = subprocess.run(compare_cmd)
        if compare_res.returncode == 0:
            print(f"[OK] 3-Way Showdown Matrix generated: {showdown_out}")


if __name__ == "__main__":
    main()
