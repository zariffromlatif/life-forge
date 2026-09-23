# Contributing to LIFE FORGE

Thank you for your interest in contributing to LIFE FORGE. We welcome contributions from researchers, security engineers, systems developers, and artificial life practitioners.

---

## Code of Conduct & Standards

To maintain an enterprise-grade and defense-ready codebase, all contributions must adhere to the following architectural standards:

1. **Zero-Emoji Policy**:
   - No emojis in source code, docstrings, commit messages, documentation, CLI outputs, or UI assets.
   - Use standard defense/aerospace ASCII markers: `[OK]`, `[FAIL]`, `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`.

2. **Deterministic & Vectorized Implementations**:
   - Substrate physics and metric calculators must be vectorized using NumPy.
   - All random generation must accept and respect explicit `seed` parameters for scientific reproducibility.

3. **Type Annotations**:
   - Python code must feature comprehensive type annotations (`from __future__ import annotations`).

4. **100% Test Passing Rate**:
   - All contributions must pass the entire test suite without regressions:
     ```bash
     pytest -v
     ```

---

## Development Setup

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/<your-username>/life-forge.git
   cd life-forge
   ```

2. **Create Virtual Environment**:
   ```bash
   python -m venv .venv
   # On Windows:
   .\.venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install Editable with Development Extras**:
   ```bash
   pip install -e ".[all,dev]"
   ```

4. **Verify Test Suite**:
   ```bash
   pytest -v
   ```

---

## Contribution Areas

We actively invite pull requests in the following core areas:

- **New Mutators** (`lifeforge/evolution/mutators/`): Novel environmental pressures (e.g. latency jitter, multi-turn conversational diversion, token budget compression).
- **New Policy Invariants** (`lifeforge/sandbox/oracle.py`): Enterprise compliance checks, PII leakage detection, regulatory constraint monitors.
- **Model Harnesses** (`lifeforge/sandbox/`): Adapters for local and specialized agent frameworks (LangGraph, CrewAI, AutoGen, Semantic Kernel).
- **Substrates & Complexity Metrics** (`lifeforge/substrates/`, `lifeforge/metrics/`): Additional Artificial Life systems (Lenia, Continuous CA) and open-ended evolution metrics.

---

## Pull Request Guidelines

1. Create a focused feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Write unit tests for all new functionality under `tests/`.
3. Ensure no trailing whitespaces or formatting issues.
4. Submit your pull request against the `main` branch with a clear description of the problem solved and test evidence.
