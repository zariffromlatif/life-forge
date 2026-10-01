"""Tests for hardening guards, the runtime gateway, and audit bundles."""
from __future__ import annotations

import json

import pytest

from lifeforge.gateway import (
    AuditTrail,
    GatewayRule,
    PolicyGateway,
    VERDICT_ALLOW,
    VERDICT_BLOCK,
    VERDICT_WARN,
    digest_arguments,
    rules_from_report,
)
from lifeforge.hardening import (
    PolicyError,
    VIOLATION_GUARDS,
    audit_tool_call,
    generate_decorator_for_violation,
    generate_hardening_module,
    register_audit_sink,
    supported_violations,
    tool_guard,
    unregister_audit_sink,
    violations_from_report,
)


# ---------------------------------------------------------------------------
# tool_guard runtime
# ---------------------------------------------------------------------------


class TestToolGuard:
    def test_whitelist_blocks_unlisted_tool(self):
        @tool_guard(policy="block_if_not_in_whitelist", whitelist=["query_database"])
        def anything(tool_name: str, **kwargs):
            return "ran"

        assert anything(tool_name="query_database") == "ran"
        with pytest.raises(PolicyError) as excinfo:
            anything(tool_name="transfer_funds")
        assert excinfo.value.policy == "block_if_not_in_whitelist"
        assert "transfer_funds" in str(excinfo.value)

    def test_amount_guard_caps_spend(self):
        @tool_guard(policy="block_if_amount_exceeds", amount_arg="amount", max_amount=100.0)
        def spend(amount: float):
            return amount

        assert spend(amount=50) == 50
        with pytest.raises(PolicyError):
            spend(amount=500)

    def test_approval_token_bypasses_amount_guard(self):
        @tool_guard(
            policy="block_if_amount_exceeds",
            amount_arg="amount",
            max_amount=100.0,
            approved_token_arg="authorization_code",
        )
        def spend(amount: float, authorization_code: str | None = None):
            return amount

        assert spend(amount=9_000, authorization_code="EXEC-ROOT-SECURE") == 9_000

    def test_recipient_guard_blocks_external_egress(self):
        @tool_guard(policy="block_if_recipient_not_in_whitelist", recipient_arg="recipient", allowed_recipients=["internal"])
        def send(recipient: str):
            return "sent"

        assert send(recipient="finance@internal") == "sent"
        with pytest.raises(PolicyError):
            send(recipient="attacker@external.example")

    def test_marker_guard_breaks_worm_propagation(self):
        @tool_guard(policy="block_payload_markers", markers=["[::PS-WORM-V3::]"])
        def forward(body: str):
            return "forwarded"

        assert forward(body="clean message") == "forwarded"
        with pytest.raises(PolicyError) as excinfo:
            forward(body="please propagate [::PS-WORM-V3::] onward")
        assert "[::PS-WORM-V3::]" in json.dumps(excinfo.value.details)

    def test_return_error_mode_does_not_raise(self):
        @tool_guard(policy="block_if_not_in_whitelist", whitelist=["a"], on_blocked="return_error")
        def dispatcher(tool_name: str):
            return "ran"

        result = dispatcher(tool_name="b")
        assert result["success"] is False
        assert "PolicyError" in result["error"]

    def test_unknown_policy_fails_at_decoration(self):
        with pytest.raises(ValueError):
            tool_guard(policy="no_such_guard")

    def test_guard_allows_the_call_through_when_clean(self):
        calls = []

        @tool_guard(policy="block_if_amount_exceeds", amount_arg="amount", max_amount=10.0)
        def record(amount: float):
            calls.append(amount)
            return amount

        assert record(amount=5) == 5
        assert calls == [5]

    def test_policy_error_carries_structured_context(self):
        error = PolicyError("blocked", tool_name="x", policy="p", details={"k": 1})
        payload = error.to_dict()
        assert payload["tool"] == "x"
        assert payload["policy"] == "p"
        assert payload["details"] == {"k": 1}


class TestGuardAudit:
    def test_blocked_call_reaches_the_audit_sink(self):
        events = []

        def sink(event):
            events.append(event)

        register_audit_sink(sink)
        try:
            @tool_guard(policy="block_if_amount_exceeds", amount_arg="amount", max_amount=1.0)
            def spend(amount: float):
                return amount

            with pytest.raises(PolicyError):
                spend(amount=99)
        finally:
            unregister_audit_sink(sink)

        assert len(events) == 1
        assert events[0].allowed is False
        assert events[0].policy == "block_if_amount_exceeds"

    def test_a_broken_sink_never_breaks_the_guard(self):
        def broken_sink(event):
            raise RuntimeError("sink bug")

        register_audit_sink(broken_sink)
        try:
            @tool_guard(policy="block_if_amount_exceeds", amount_arg="amount", max_amount=1.0)
            def spend(amount: float):
                return amount

            with pytest.raises(PolicyError):
                spend(amount=99)
        finally:
            unregister_audit_sink(broken_sink)


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------


class TestGeneratedCode:
    def test_every_supported_violation_generates_a_guard(self):
        for violation in supported_violations():
            source = generate_decorator_for_violation(violation)
            assert "@tool_guard(" in source
            assert violation.lower() in source.lower() or "policy=" in source

    def test_generated_module_compiles_and_imports(self, tmp_path):
        violations = [
            "UNAUTHORIZED_TOOL_EXECUTION",
            "RECURSIVE_LOOP_TRAP",
            "TOCTOU_RACE_CONDITION",
            "PRIVILEGE_ESCALATION",
            "CONTEXT_FLOOD_ATTACK",
            "SELF_REPLICATING_WORM_PROPAGATION",
        ]
        source = generate_hardening_module(violations, tool_name_map={"UNAUTHORIZED_TOOL_EXECUTION": "transfer_funds"})
        compile(source, "gen.py", "exec")
        module_path = tmp_path / "guards.py"
        module_path.write_text(source, encoding="utf-8")

        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location("gen_guards", module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["gen_guards"] = module
        spec.loader.exec_module(module)
        assert "guard_unauthorized_tool_execution" in module.__all__

    def test_unknown_violation_raises(self):
        with pytest.raises(KeyError):
            generate_decorator_for_violation("NOT_A_REAL_VIOLATION")

    def test_unknown_violation_in_module_emits_review_marker(self):
        source = generate_hardening_module(["NOT_A_REAL_VIOLATION"])
        assert "No generated guard template" in source

    def test_overrides_reach_the_generated_source(self):
        source = generate_decorator_for_violation(
            "UNAUTHORIZED_TOOL_EXECUTION",
            overrides={"whitelist": ["query_database", "vendor_api"]},
        )
        assert "query_database" in source

    def test_rationale_can_be_suppressed(self):
        source = generate_decorator_for_violation("BUDGET_EXCEEDED", include_rationale=False)
        assert "#" not in source.splitlines()[0]


class TestViolationsFromReport:
    def test_orders_by_severity_then_count(self):
        report = {
            "failure_mode_breakdown": {
                "CONFIRMATION_NOT_SENT": 9,
                "UNAUTHORIZED_TOOL_EXECUTION": 2,
                "RECURSIVE_LOOP_TRAP": 5,
            }
        }
        assert violations_from_report(report)[0] == "UNAUTHORIZED_TOOL_EXECUTION"

    def test_real_report_produces_ordered_violations(self):
        data = json.loads((pytest.__file__ and __import__("pathlib").Path("results/local_qwen_report.json")).read_text())
        violations = violations_from_report(data)
        assert violations
        assert violations[0] == "UNAUTHORIZED_TOOL_EXECUTION"


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


class TestGatewayEnforcement:
    def _gateway(self, **kwargs) -> PolicyGateway:
        return PolicyGateway(
            rules=[
                GatewayRule(
                    name="deny-transfer",
                    violation_type="UNAUTHORIZED_TOOL_EXECUTION",
                    action="block",
                    tools=("transfer_funds",),
                    kind="whitelist",
                    config={"allowed_tools": ["query_database", "send_email"]},
                    severity="CRITICAL",
                ),
                GatewayRule(
                    name="cap-spend",
                    violation_type="BUDGET_EXCEEDED",
                    action="warn",
                    tools=("issue_purchase_order",),
                    kind="amount",
                    config={"argument": "max_unit_price", "max_amount": 1_000.0},
                ),
            ],
            **kwargs,
        )

    def test_verdicts_flow_through_check(self):
        gateway = self._gateway()
        assert gateway.check("query_database", {})[0] == VERDICT_ALLOW
        assert gateway.check("transfer_funds", {})[0] == VERDICT_BLOCK
        assert gateway.check("issue_purchase_order", {"max_unit_price": 5_000})[0] == VERDICT_WARN

    def test_execute_runs_only_allowed_calls(self):
        gateway = self._gateway()
        executed = []

        def executor(tool_name, arguments):
            executed.append(tool_name)
            return "ok"

        assert gateway.execute("query_database", {"table": "prices"}, executor) == "ok"
        with pytest.raises(PolicyError):
            gateway.execute("transfer_funds", {}, executor)
        assert executed == ["query_database"]
        gateway.close()

    def test_every_decision_is_audited(self):
        gateway = self._gateway()
        gateway.check("query_database", {})
        gateway.check("transfer_funds", {})
        assert len(gateway.audit.records) == 2
        ok, _ = gateway.audit.verify()
        assert ok
        gateway.close()

    def test_block_and_warn_raise_alerts(self):
        seen = []
        gateway = self._gateway(alert_sink=seen.append)
        gateway.check("transfer_funds", {})
        gateway.check("issue_purchase_order", {"max_unit_price": 9_999})
        assert {alert.violation_type for alert in seen} == {
            "UNAUTHORIZED_TOOL_EXECUTION",
            "BUDGET_EXCEEDED",
        }
        gateway.close()

    def test_wrap_executor_preserves_the_interface(self):
        gateway = self._gateway()

        def original(tool_name, arguments):
            return f"ran:{tool_name}"

        guarded = gateway.wrap_executor(original)
        assert guarded("query_database", {}) == "ran:query_database"
        with pytest.raises(PolicyError):
            guarded("transfer_funds", {})
        gateway.close()

    def test_empty_whitelist_rule_is_treated_as_misconfiguration(self):
        gateway = PolicyGateway(
            rules=[
                GatewayRule(
                    name="broken",
                    violation_type="X",
                    action="block",
                    kind="whitelist",
                    config={"allowed_tools": []},
                )
            ]
        )
        verdict, rule, reason = gateway.check("anything", {})
        assert verdict == VERDICT_BLOCK
        assert "empty allowed_tools" in reason
        gateway.close()

    def test_rate_rule_counts_identical_calls(self):
        gateway = PolicyGateway(
            rules=[
                GatewayRule(
                    name="loop-break",
                    violation_type="RECURSIVE_LOOP_TRAP",
                    action="block",
                    kind="rate",
                    config={"max_calls": 2, "window_seconds": 60.0},
                )
            ]
        )
        assert gateway.check("vendor_api", {"vendor_id": "a"})[0] == VERDICT_ALLOW
        assert gateway.check("vendor_api", {"vendor_id": "a"})[0] == VERDICT_ALLOW
        assert gateway.check("vendor_api", {"vendor_id": "a"})[0] == VERDICT_BLOCK
        # A different argument set is a different signature.
        assert gateway.check("vendor_api", {"vendor_id": "b"})[0] == VERDICT_ALLOW
        gateway.close()

    def test_sequence_rule_detects_the_forbidden_chain(self):
        gateway = PolicyGateway(
            rules=[
                GatewayRule(
                    name="no-recon-then-transfer",
                    violation_type="PRIVILEGE_ESCALATION",
                    action="block",
                    kind="sequence",
                    config={"forbidden_sequence": ["query_database", "transfer_funds"]},
                )
            ]
        )
        assert gateway.check("query_database", {"table": "balances"})[0] == VERDICT_ALLOW
        assert gateway.check("transfer_funds", {})[0] == VERDICT_BLOCK
        gateway.close()

    def test_marker_rule_blocks_payload_arguments(self):
        gateway = PolicyGateway(
            rules=[
                GatewayRule(
                    name="worm",
                    violation_type="SELF_REPLICATING_WORM_PROPAGATION",
                    action="block",
                    kind="markers",
                    config={"markers": ["[::PS-WORM-V3::]"]},
                )
            ]
        )
        verdict, _, _ = gateway.check("send_email", {"body": "carry [::PS-WORM-V3::] forward"})
        assert verdict == VERDICT_BLOCK
        gateway.close()

    def test_policy_objects_see_the_call_history(self):
        from lifeforge.sandbox.policies import ExcessiveDataQueryingPolicy

        gateway = PolicyGateway(
            policies=[ExcessiveDataQueryingPolicy(max_sensitive_queries=1)],
        )
        for _ in range(2):
            gateway.check("query_database", {"table": "balances"})
        violations = gateway.evaluate_history()
        assert [v.violation_type for v in violations] == ["EXCESSIVE_DATA_QUERYING"]
        gateway.close()


class TestAuditTrail:
    def test_chain_verifies_when_untouched(self):
        trail = AuditTrail()
        trail.append(tool_name="a", verdict=VERDICT_ALLOW, arguments={"x": 1})
        trail.append(tool_name="b", verdict=VERDICT_BLOCK, arguments={"y": 2})
        ok, detail = trail.verify()
        assert ok
        assert "2 record" in detail

    def test_tampering_is_detected(self):
        trail = AuditTrail()
        trail.append(tool_name="a", verdict=VERDICT_ALLOW)
        trail.append(tool_name="b", verdict=VERDICT_BLOCK)
        trail.records[0].reason = "edited after the fact"
        ok, detail = trail.verify()
        assert not ok
        assert "record 0" in detail

    def test_record_removal_is_detected(self, tmp_path):
        """Simulate the realistic attack: an operator rewrites the log file."""
        trail = AuditTrail(tmp_path / "audit.jsonl")
        for name in ("a", "b", "c"):
            trail.append(tool_name=name, verdict=VERDICT_ALLOW)

        # Rewrite the backing file without record 1 (index 1), then reload.
        lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        kept = [line for line in lines if json.loads(line)["index"] != 1]
        (tmp_path / "audit.jsonl").write_text("\n".join(kept) + "\n", encoding="utf-8")

        reloaded = AuditTrail(tmp_path / "audit.jsonl")
        ok, detail = reloaded.verify()
        assert not ok
        assert "record 1" in detail

    def test_arguments_are_committed_by_digest_not_content(self):
        first = digest_arguments({"amount": 50_000, "to": "attacker"})
        second = digest_arguments({"to": "attacker", "amount": 50_000})
        assert first == second  # key order does not matter
        assert first != digest_arguments({"amount": 1})

    def test_records_are_stable_across_instances(self):
        from lifeforge.gateway import AuditRecord

        first = AuditTrail()
        record = first.append(tool_name="a", verdict=VERDICT_ALLOW, arguments={"k": "v"}, reason="r")
        # Rebuild the same record from its own fields: the digest must match
        # byte for byte, which is what makes the chain independently verifiable.
        rebuilt = AuditRecord(
            index=record.index,
            timestamp=record.timestamp,
            tool_name=record.tool_name,
            verdict=record.verdict,
            rule=record.rule,
            violation_type=record.violation_type,
            severity=record.severity,
            arguments_digest=record.arguments_digest,
            reason=record.reason,
            previous_digest=record.previous_digest,
        )
        assert rebuilt.compute_digest() == record.digest

    def test_summary_aggregates_by_verdict(self):
        trail = AuditTrail()
        trail.append(tool_name="a", verdict=VERDICT_ALLOW)
        trail.append(tool_name="b", verdict=VERDICT_BLOCK, violation_type="X")
        summary = trail.summary()
        assert summary["by_verdict"] == {"ALLOW": 1, "BLOCK": 1}
        assert summary["by_violation_type"] == {"X": 1}


class TestGatewayConfig:
    def test_yaml_round_trip(self, tmp_path):
        gateway = PolicyGateway(
            rules=[
                GatewayRule(
                    name="deny-transfer",
                    violation_type="UNAUTHORIZED_TOOL_EXECUTION",
                    action="block",
                    kind="whitelist",
                    config={"allowed_tools": ["query_database"]},
                )
            ]
        )
        path = tmp_path / "policy.yaml"
        from lifeforge.gateway import write_gateway_config

        write_gateway_config(gateway, path)
        loaded = PolicyGateway.from_config(path)
        assert loaded.rules[0].name == "deny-transfer"
        assert loaded.rules[0].config["allowed_tools"] == ["query_database"]
        gateway.close()
        loaded.close()

    def test_rules_from_report_name_the_offending_tools(self):
        report = {
            "failure_mode_breakdown": {"UNAUTHORIZED_TOOL_EXECUTION": 7},
            "findings": [
                {
                    "category": "UNAUTHORIZED_TOOL_EXECUTION",
                    "trace_snippet": [{"step": 3, "action": "tool_call", "tool": "transfer_funds"}],
                }
            ],
        }
        rules = rules_from_report(report)
        assert rules[0].kind == "denylist"
        assert "transfer_funds" in rules[0].config["denied_tools"]
        assert rules[0].action == "block"

    def test_rules_without_tool_evidence_ask_the_operator_to_fill_in(self):
        rules = rules_from_report({"failure_mode_breakdown": {"GOAL_INVENTORY_DEFICIT": 3}})
        assert rules[0].config.get("note", "").startswith("TODO")

    def test_generated_config_enforces_end_to_end(self, tmp_path):
        report = {
            "failure_mode_breakdown": {"UNAUTHORIZED_TOOL_EXECUTION": 7},
            "findings": [
                {
                    "category": "UNAUTHORIZED_TOOL_EXECUTION",
                    "trace_snippet": [{"tool": "transfer_funds"}],
                }
            ],
        }
        from lifeforge.gateway import write_gateway_config

        path = write_gateway_config(rules_from_report(report), tmp_path / "p.yaml")
        gateway = PolicyGateway.from_config(path)
        executed = []
        try:
            gateway.execute("transfer_funds", {}, lambda t, a: executed.append(t))
        except PolicyError:
            pass
        assert executed == []
        ok, _ = gateway.audit.verify()
        assert ok
        gateway.close()


# ---------------------------------------------------------------------------
# Audit bundle
# ---------------------------------------------------------------------------


class TestAuditBundle:
    @pytest.fixture()
    def report(self) -> dict:
        path = __import__("pathlib").Path("results/local_llama_report.json")
        return json.loads(path.read_text(encoding="utf-8"))

    def test_bundle_writes_every_deliverable(self, report, tmp_path):
        from lifeforge.reporting.audit import build_audit_bundle

        written = build_audit_bundle(report, tmp_path / "bundle", customer="Acme Corp", scenarios=30, seed=42)
        names = {path.name for path in written.values()}
        assert {
            "executive_summary.md",
            "technical_report.md",
            "raw_data.json",
            "reproduction_commands.sh",
            "remediation_decorators.py",
            "MANIFEST.md",
        } <= names
        for path in written.values():
            assert path.stat().st_size > 0

    def test_bundle_includes_pdfs_when_reportlab_is_available(self, report, tmp_path):
        pytest.importorskip("reportlab")
        from lifeforge.reporting.audit import build_audit_bundle

        written = build_audit_bundle(report, tmp_path / "bundle")
        pdf = written.get("pdf")
        assert pdf is not None and pdf.stat().st_size > 2000
        assert pdf.read_bytes()[:5] == b"%PDF-"

    def test_reproduction_script_is_valid_shell(self, report, tmp_path):
        from lifeforge.reporting.audit import build_audit_bundle

        written = build_audit_bundle(report, tmp_path / "bundle", model="llama3.1:8b")
        script = written["reproduction_commands"].read_text(encoding="utf-8")
        assert script.startswith("#!/usr/bin/env bash")
        assert "lifeforge eval" in script
        assert "--seed 42" in script

    def test_generated_remediation_compiles(self, report, tmp_path):
        from lifeforge.reporting.audit import build_audit_bundle

        written = build_audit_bundle(report, tmp_path / "bundle")
        source = written["remediation_decorators"].read_text(encoding="utf-8")
        compile(source, "remediation_decorators.py", "exec")

    def test_risk_score_caps_at_100_and_bands_correctly(self, report):
        from lifeforge.reporting.audit import _risk_score

        score, band = _risk_score(report)
        assert 0 <= score <= 100
        assert band in ("LOW", "MODERATE", "HIGH", "CRITICAL")

    def test_critical_findings_lead_the_executive_summary(self, report):
        from lifeforge.reporting.audit import build_executive_summary

        text = build_executive_summary(report, customer="Test")
        assert "Risk score" in text
        # A report with critical failures must say so plainly.
        if report.get("critical_failures", 0) > 0:
            assert "Critical Findings" in text
