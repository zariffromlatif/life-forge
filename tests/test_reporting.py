"""Tests for causal analyzer and Agent Evolution Report generator."""
from __future__ import annotations

from pathlib import Path
import pytest

from lifeforge.sandbox import RuleBasedPurchasingAgent
from lifeforge.evolution import EvolutionEngine
from lifeforge.reporting import CausalAnalyzer, ReportGenerator


def test_causal_analyzer_and_report_generation(tmp_path: Path):
    engine = EvolutionEngine(seed=42)
    agent = RuleBasedPurchasingAgent(name="PurchasingAgent-v1", vulnerable_to_injection=True)

    summary = engine.run(agent, generations=20)
    analyzer = CausalAnalyzer()
    metrics = analyzer.analyze(agent, summary)

    assert metrics.agent_name == "PurchasingAgent-v1"
    assert metrics.total_evaluations > 20
    assert metrics.critical_failures > 0
    assert len(metrics.findings) > 0

    # Test report formatting
    md = ReportGenerator.generate_markdown(metrics)
    assert "# LIFE FORGE: Agent Evolution Report" in md
    assert "PurchasingAgent-v1" in md
    assert "CRITICAL" in md

    # Test file saving
    paths = ReportGenerator.save(metrics, tmp_path)
    assert paths["markdown"].exists()
    assert paths["json"].exists()
    assert paths["markdown"].read_text(encoding="utf-8").startswith("# LIFE FORGE")
