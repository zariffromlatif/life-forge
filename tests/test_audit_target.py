"""Tests for open-source audit target agent and audit bundle generation."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from lifeforge.cli.main import cmd_audit, cmd_eval
from lifeforge.sandbox.agent import AgentInterface
from lifeforge.sandbox.loader import load_agent_from_spec
from lifeforge.sandbox.domains import get_domain


def test_load_langgraph_customer_support_from_spec() -> None:
    target_path = Path("examples/targets/langgraph_customer_support.py")
    assert target_path.exists()

    agent = load_agent_from_spec(f"{target_path}:agent")
    assert isinstance(agent, AgentInterface)
    assert type(agent).__name__ == "LangGraphCustomerSupportAgent"
    assert agent.name == "LangGraph-CustomerSupport-v1"


def test_load_hardened_langgraph_customer_support_from_spec() -> None:
    target_path = Path("examples/targets/langgraph_customer_support.py")
    agent = load_agent_from_spec(f"{target_path}:hardened_agent")
    assert isinstance(agent, AgentInterface)
    assert type(agent).__name__ == "HardenedLangGraphCustomerSupportAgent"
    assert agent.name == "LangGraph-CustomerSupport-Hardened"


def test_customer_support_audit_bundle_execution(tmp_path: Path) -> None:
    out_dir = tmp_path / "test_audit_bundle"
    args = argparse.Namespace(
        input=None,
        target="examples/targets/langgraph_customer_support.py:agent",
        endpoint=None,
        customer="Test Organization",
        model="LangGraph-CustomerSupport-Test",
        hardware="Test Environment",
        domain="customer_support",
        scenarios=5,
        seed=42,
        delay=0.0,
        frontier=False,
        out=str(out_dir),
        no_pdf=True,
    )

    cmd_audit(args)

    assert out_dir.exists()
    assert (out_dir / "executive_summary.md").exists()
    assert (out_dir / "technical_report.md").exists()
    assert (out_dir / "remediation_decorators.py").exists()
    assert (out_dir / "reproduction_commands.sh").exists()
    assert (out_dir / "raw_data.json").exists()
    assert (out_dir / "MANIFEST.md").exists()

    exec_summary = (out_dir / "executive_summary.md").read_text(encoding="utf-8")
    assert "Security Audit: Executive Summary" in exec_summary
    assert "LangGraph-CustomerSupport-v1" in exec_summary
