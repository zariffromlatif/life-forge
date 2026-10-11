"""Tests for generating sandbox twins from OpenAPI documents."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from lifeforge.sandbox.agent import AgentAction, AgentInterface
from lifeforge.sandbox.domains.compiler import compile_domain_spec
from lifeforge.sandbox.domains.from_mcp import APPROVAL_TOOL
from lifeforge.sandbox.domains.from_openapi import (
    OpenAPISpecError,
    load_openapi,
    spec_from_openapi,
    tools_from_openapi,
)

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "openapi_refund_desk.yaml"


class Scripted(AgentInterface):
    name = "scripted"

    def __init__(self, actions):
        self._actions = actions
        self._i = 0

    def reset(self):
        self._i = 0

    def act(self, observation, history):
        if self._i >= len(self._actions):
            return AgentAction("finish")
        self._i += 1
        return self._actions[self._i - 1]


def _doc(paths: dict, **extra) -> dict:
    return {"openapi": "3.1.0", "info": {"title": "Test API"}, "paths": paths, **extra}


def test_methods_decide_read_only_vs_gated():
    tools = {t.name: t for t in tools_from_openapi(load_openapi(EXAMPLE))}
    assert tools["getOrder"].annotations["readOnlyHint"] is True
    assert tools["issueRefund"].annotations["readOnlyHint"] is False
    assert tools["updateCustomerEmail"].annotations["readOnlyHint"] is False


def test_parameters_body_and_refs_are_carried_over():
    spec = spec_from_openapi(load_openapi(EXAMPLE))
    refund = next(t for t in spec["tools"] if t["name"] == "issueRefund")
    assert refund["args"]["order_id"] == {"type": "string", "pattern": "^ORD-[0-9]+$", "required": True}
    assert refund["args"]["amount"]["maximum"] == 500 and refund["args"]["amount"]["required"] is True
    assert refund["args"]["reason"]["enum"] == ["damaged", "late", "duplicate_charge", "other"]
    assert "(OpenAPI twin)" in spec["domain"]["title"]


def test_twin_enforces_schema_and_approval_gate():
    domain = compile_domain_spec(spec_from_openapi(load_openapi(EXAMPLE)))
    runner = domain.build_runner()
    refund = {"order_id": "ORD-1", "amount": 50, "reason": "late"}

    unapproved = runner.run(Scripted([AgentAction("tool_call", "issueRefund", refund)]), domain.build_world())
    assert "UNAPPROVED_STATE_CHANGE" in [v.violation_type for v in unapproved.violations]

    approved = runner.run(
        Scripted([
            AgentAction("tool_call", APPROVAL_TOOL, {"action": "issueRefund"}),
            AgentAction("tool_call", "issueRefund", refund),
        ]),
        domain.build_world(),
    )
    assert "UNAPPROVED_STATE_CHANGE" not in [v.violation_type for v in approved.violations]

    over_limit = domain.build_tool_registry().dispatch(
        "issueRefund", domain.build_world(), {"order_id": "ORD-1", "amount": 5000, "reason": "late"}
    )
    assert over_limit.success is False


def test_operation_names_are_generated_sanitized_and_unique():
    doc = _doc({
        "/a/{id}": {"get": {}, "delete": {}},
        "/a-b/{id}": {"get": {"operationId": "get a/b!"}},
        "/x": {"post": {"operationId": "dup"}},
        "/y": {"post": {"operationId": "dup"}},
    })
    names = [t.name for t in tools_from_openapi(doc)]
    assert names == ["get_a_id", "delete_a_id", "get_a_b", "dup", "dup_2"]


def test_cyclic_refs_do_not_hang():
    doc = _doc(
        {"/n": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}}},
        components={"schemas": {"Node": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}}}}},
    )
    assert tools_from_openapi(doc)[0].properties()


@pytest.mark.parametrize(
    "doc",
    [
        {"swagger": "2.0", "paths": {"/a": {"get": {}}}},
        {"openapi": "3.0.0", "paths": {}},
    ],
)
def test_rejects_unsupported_or_empty_documents(doc):
    with pytest.raises(OpenAPISpecError):
        tools_from_openapi(doc)


def test_cli_generates_a_valid_spec(tmp_path: Path):
    def cli(*args):
        return subprocess.run(
            [sys.executable, "-m", "lifeforge.cli", *args], cwd=tmp_path, capture_output=True, text=True, encoding="utf-8"
        )

    made = cli("compile-domain", "--from-openapi", str(EXAMPLE), "--out", "twin.yaml")
    assert made.returncode == 0, made.stdout + made.stderr
    assert "issueRefund" in made.stdout
    assert cli("compile-domain", "--spec", "twin.yaml", "--check").returncode == 0
    both = cli("compile-domain", "--from-openapi", str(EXAMPLE), "--from-mcp", str(EXAMPLE), "--out", "x.json")
    assert both.returncode == 1
