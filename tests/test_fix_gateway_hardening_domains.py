"""Regression tests for the gateway / hardening / domain audit findings (1-15)."""
from __future__ import annotations

import gc
import json
import math
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from lifeforge.gateway import (
    AuditIntegrityError,
    AuditTrail,
    GatewayConfigError,
    GatewayRule,
    PolicyGateway,
    VERDICT_ALLOW,
    VERDICT_BLOCK,
    VERDICT_WARN,
    rules_from_report,
)
from lifeforge.hardening import (
    _AUDIT_SINKS,
    GeneratedCodeError,
    PolicyError,
    generate_decorator_for_violation,
    generate_hardening_module,
    note_read,
    record_tool_call,
    reset_guard_state,
    tool_guard,
    write_hardening_module,
)
from lifeforge.sandbox.domains.compiler import DomainSpecError, compile_domain_spec
from lifeforge.sandbox.domains.customer_support import CustomerSupportDomain
from lifeforge.sandbox.domains.devops import DevOpsDomain
from lifeforge.sandbox.domains.financial import FinancialDomain
from lifeforge.sandbox.world_state import WorldState

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clean_guard_state():
    reset_guard_state()
    yield
    reset_guard_state()


def _runs(gateway: PolicyGateway, tool: str, arguments: dict) -> bool:
    """True when the executor ran."""
    ran = []
    try:
        gateway.execute(tool, arguments, lambda name, args: ran.append(name))
    except PolicyError:
        pass
    return bool(ran)


def _blocked(func, *args, **kwargs) -> bool:
    try:
        func(*args, **kwargs)
    except PolicyError:
        return True
    return False


# ---------------------------------------------------------------------------
# 1. Code injection through generated hardening modules
# ---------------------------------------------------------------------------


def _import_generated(tmp_path: Path, source: str) -> subprocess.CompletedProcess:
    module = tmp_path / "guards.py"
    module.write_text(source, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(module)], capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={"PYTHONPATH": str(REPO_ROOT), "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")},
    )


class TestFinding1CodegenInjection:
    def test_tool_name_from_report_cannot_inject_code(self, tmp_path):
        marker = (tmp_path / "pwned.txt").as_posix()
        tool = "\\\n__import__(\"pathlib\").Path(\"" + marker + "\").write_text(\"x\")#"
        source = generate_hardening_module(
            ["UNAUTHORIZED_TOOL_EXECUTION"], tool_name_map={"UNAUTHORIZED_TOOL_EXECUTION": tool + "'\n)"}
        )
        result = _import_generated(tmp_path, source)
        assert result.returncode == 0, result.stderr
        assert not Path(marker).exists()

    def test_violation_name_cannot_inject_code(self, tmp_path):
        bold = lambda text: "".join(chr(0x1D41A + ord(c) - 97) for c in text)  # noqa: E731
        violation = "FOO\n" + bold("exec") + "('RAISE SYSTEMEXIT(43)'." + bold("lower") + "())\n#"
        result = _import_generated(tmp_path, generate_hardening_module([violation]))
        assert result.returncode == 0, result.stderr

    def test_docstring_cannot_break_out(self, tmp_path):
        source = generate_hardening_module([], module_docstring='x\n"""\nraise SystemExit(44)\n"""')
        assert _import_generated(tmp_path, source).returncode == 0

    def test_override_key_injection_is_rejected(self):
        with pytest.raises(GeneratedCodeError):
            generate_decorator_for_violation("BUDGET_EXCEEDED", overrides={"x=1)\nimport os\n#": 1})

    def test_non_finite_override_is_valid_python(self):
        source = generate_decorator_for_violation("BUDGET_EXCEEDED", overrides={"max_amount": math.inf})
        assert "float('inf')" in source
        namespace = {"tool_guard": tool_guard}
        exec(source + "\ndef f(amount): return amount", namespace)  # noqa: S102 - generated, verified source
        # The module imports; a non-finite cap is a misconfiguration the guard fails closed on.
        assert _blocked(namespace["f"], 10)

    def test_placeholder_on_numeric_kwarg_keeps_default(self):
        source = generate_decorator_for_violation("BUDGET_EXCEEDED", overrides={"max_amount": "<ask finance>"})
        assert "max_amount=0.0" in source
        namespace = {"tool_guard": tool_guard}
        exec(source + "\ndef f(amount): return amount", namespace)  # noqa: S102
        with pytest.raises(PolicyError):
            namespace["f"](10)

    def test_unsafe_override_value_type_is_rejected(self):
        with pytest.raises(GeneratedCodeError):
            generate_decorator_for_violation("BUDGET_EXCEEDED", overrides={"max_amount": object()})

    def test_write_hardening_module_output_parses(self, tmp_path):
        path = write_hardening_module(["UNAUTHORIZED_TOOL_EXECUTION", "BOGUS\nx"], tmp_path / "g.py")
        compile(path.read_text(encoding="utf-8"), "g.py", "exec")


# ---------------------------------------------------------------------------
# 2. Recipient matching
# ---------------------------------------------------------------------------


class TestFinding2Recipients:
    def _gateway(self, **config):
        return PolicyGateway([GatewayRule("egress", "X", kind="recipient", config={"allowed_recipients": ["internal"], **config})])

    @pytest.mark.parametrize(
        "recipient",
        ["internal@evil.com", "attacker+internal@evil.com", "evil.com/?q=internal", ["attacker@evil.com", "internal"], 42],
    )
    def test_gateway_substring_tricks_are_blocked(self, recipient):
        assert not _runs(self._gateway(), "send_email", {"recipient": recipient})

    def test_gateway_alias_argument_is_checked(self):
        assert not _runs(self._gateway(), "send_email", {"to": "attacker@evil.com"})

    def test_gateway_exact_role_and_allowed_domain_pass(self):
        gateway = self._gateway(allowed_domains=["corp.example"])
        assert _runs(gateway, "send_email", {"recipient": "internal"})
        assert _runs(gateway, "send_email", {"recipient": "bob@mail.corp.example"})

    def test_scoped_rule_without_recipient_blocks(self):
        gateway = PolicyGateway(
            [GatewayRule("egress", "X", kind="recipient", tools=("send_email",), config={"allowed_recipients": ["internal"]})]
        )
        assert not _runs(gateway, "send_email", {"body": "hi"})

    def test_guard_substring_tricks_are_blocked(self):
        @tool_guard("block_if_recipient_not_in_whitelist", allowed_recipients=["internal"])
        def send(recipient=None, to=None):
            return "sent"

        assert _blocked(send, recipient="internal@evil.com")
        assert _blocked(send, "attacker+internal@evil.com")
        assert _blocked(send, to="attacker@evil.com")
        assert not _blocked(send, recipient="finance@internal")


# ---------------------------------------------------------------------------
# 3. Tool-name canonicalization
# ---------------------------------------------------------------------------


class TestFinding3ToolNames:
    @pytest.mark.parametrize("name", ["Transfer_Funds", "transfer_funds ", "TRANSFER_FUNDS", "ｔransfer_funds"])
    def test_case_width_whitespace_variants_hit_the_denylist(self, name):
        gateway = PolicyGateway([GatewayRule("deny", "X", kind="denylist", config={"denied_tools": ["transfer_funds"]})])
        assert not _runs(gateway, name, {})

    @pytest.mark.parametrize("name", ["transfer‐funds", "transfer​funds", "transfer funds"])
    def test_non_canonical_names_are_blocked(self, name):
        assert not _runs(PolicyGateway(), name, {})

    def test_scoped_rule_matches_canonical_name(self):
        gateway = PolicyGateway([GatewayRule("cap", "X", tools=("transfer_funds",), kind="amount", config={"max_amount": 100})])
        assert not _runs(gateway, "TRANSFER_FUNDS", {"amount": 1e6})


# ---------------------------------------------------------------------------
# 4. Fail closed on malformed configuration
# ---------------------------------------------------------------------------


class TestFinding4FailClosed:
    @pytest.mark.parametrize("action", ["deny", "BLOCKED", "reject"])
    def test_unknown_action_raises(self, action):
        with pytest.raises(GatewayConfigError):
            PolicyGateway.from_config({"rules": [{"name": "d", "kind": "denylist", "action": action, "config": {"denied_tools": ["rm"]}}]})

    def test_action_whitespace_and_case_normalize(self):
        gateway = PolicyGateway.from_config({"rules": [{"name": "d", "kind": "Denylist", "action": "Block ", "config": {"denied_tools": ["rm"]}}]})
        assert not _runs(gateway, "rm", {})

    @pytest.mark.parametrize("kind", ["deny_list", "blocklist"])
    def test_unknown_kind_raises(self, kind):
        with pytest.raises(GatewayConfigError):
            PolicyGateway.from_config({"rules": [{"name": "d", "kind": kind}]})

    def test_unknown_default_verdict_raises(self):
        with pytest.raises(GatewayConfigError):
            PolicyGateway.from_config({"default_verdict": "DENY"})

    def test_unknown_policy_raises(self):
        with pytest.raises(GatewayConfigError):
            PolicyGateway.from_config({"policies": ["no_such_policy"]})
        with pytest.raises(GatewayConfigError):
            PolicyGateway.from_config({"policies": [{"name": "balance_drain", "config": {"bogus": 1}}]})

    def test_rule_that_raises_blocks(self):
        gateway = PolicyGateway([GatewayRule("rate", "X", action="warn", kind="rate", config={"max_calls": "lots"})])
        assert gateway.check("q", {})[0] == VERDICT_BLOCK

    def test_non_allow_verdict_never_executes(self, monkeypatch):
        gateway = PolicyGateway()
        monkeypatch.setattr(gateway, "evaluate", lambda tool, args: ("DENY", None, "custom"))
        assert not _runs(gateway, "x", {})


# ---------------------------------------------------------------------------
# 5. Amount type confusion
# ---------------------------------------------------------------------------


class TestFinding5Amounts:
    @pytest.mark.parametrize("value", [float("nan"), "nan", "1,000,000", "$1000000", {"value": 1e6}, -1e9, float("inf"), Decimal("1e6")])
    def test_gateway_blocks_unreadable_or_hostile_amounts(self, value):
        gateway = PolicyGateway([GatewayRule("cap", "X", kind="amount", config={"max_amount": 100})])
        assert not _runs(gateway, "pay", {"amount": value})

    def test_gateway_approval_requires_listed_token(self):
        config = {"max_amount": 100, "approved_token_argument": "auth", "approval_tokens": ["T-123"]}
        gateway = PolicyGateway([GatewayRule("cap", "X", kind="amount", config=config)])
        assert not _runs(gateway, "pay", {"amount": 1e9, "auth": "x"})
        assert _runs(gateway, "pay", {"amount": 1e9, "auth": "T-123"})
        unlisted = PolicyGateway([GatewayRule("cap", "X", kind="amount", config={"max_amount": 100, "approved_token_argument": "auth"})])
        assert not _runs(unlisted, "pay", {"amount": 1e9, "auth": "anything"})

    @pytest.mark.parametrize("value", [Decimal("1000000"), "1,000,000", "$1e6", float("nan"), -5])
    def test_guard_blocks_unreadable_or_hostile_amounts(self, value):
        @tool_guard("block_if_amount_exceeds", max_amount=100)
        def pay(amount, to=None):
            return "paid"

        assert _blocked(pay, value)

    def test_guard_handles_numpy_scalars(self):
        np = pytest.importorskip("numpy")

        @tool_guard("block_if_amount_exceeds", max_amount=100)
        def pay(amount):
            return "paid"

        assert _blocked(pay, np.int64(10**6))
        assert not _blocked(pay, np.float64(5.0))

    def test_guard_valid_tokens_and_verifier(self):
        @tool_guard("block_if_amount_exceeds", max_amount=100, approved_token_arg="code", valid_tokens=["OK-1"])
        def pay(amount, code=None):
            return "paid"

        assert _blocked(pay, 1000, code="guess")
        assert not _blocked(pay, 1000, code="OK-1")


# ---------------------------------------------------------------------------
# 6. Markers / size checks: positional, nested, normalized
# ---------------------------------------------------------------------------


class TestFinding6Markers:
    MARKER = "[::PS-WORM-V3::]"

    @pytest.mark.parametrize(
        "arguments",
        [
            {"body": ["[::PS-WORM-V3::]"]},
            {"msg": {"body": "[::PS-WORM-V3::]"}},
            {"body": "[::ps-worm-v3::]"},
            {"body": "[::PS-WORM-V3:​:]"},
            {"meta": {"[::PS-WORM-V3::]": 1}},
        ],
    )
    def test_gateway_finds_hidden_markers(self, arguments):
        gateway = PolicyGateway([GatewayRule("worm", "X", kind="markers", config={"markers": [self.MARKER]})])
        assert not _runs(gateway, "send_email", arguments)

    def test_guard_scans_positional_and_nested(self):
        @tool_guard("block_payload_markers", markers=[self.MARKER])
        def send(recipient, body):
            return "sent"

        assert _blocked(send, "a", self.MARKER)
        assert _blocked(send, recipient="a", body=[self.MARKER])
        assert not _blocked(send, "a", "clean")

    def test_clip_guard_scans_positional(self):
        @tool_guard("clip_payload_size", max_chars=10)
        def ingest(text):
            return "ok"

        assert _blocked(ingest, "x" * 100)
        assert _blocked(ingest, text=["x" * 100])


# ---------------------------------------------------------------------------
# 7. Audit chain integrity
# ---------------------------------------------------------------------------


class TestFinding7Audit:
    def _trail_file(self, tmp_path, count=5, **kwargs):
        path = tmp_path / "audit.jsonl"
        trail = AuditTrail(path, **kwargs)
        for index in range(count):
            trail.append(tool_name="t", verdict=VERDICT_ALLOW, arguments={"i": index})
        return path, trail

    def test_truncation_detected_against_checkpoint(self, tmp_path):
        path, trail = self._trail_file(tmp_path, secret="k")
        checkpoint = trail.checkpoint()
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        reloaded = AuditTrail(path, secret="k")
        ok, detail = reloaded.verify(checkpoint)
        assert not ok and "truncation" in detail

    def test_checkpoint_path_detects_truncation_on_load(self, tmp_path):
        checkpoint = tmp_path / "head.json"
        path, _ = self._trail_file(tmp_path, checkpoint_path=checkpoint)
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
        reloaded = AuditTrail(path, checkpoint_path=checkpoint)
        assert not reloaded.verify()[0]
        with pytest.raises(AuditIntegrityError):
            reloaded.append(tool_name="t", verdict=VERDICT_ALLOW)

    def test_forged_checkpoint_rejected_with_secret(self, tmp_path):
        _, trail = self._trail_file(tmp_path, secret="k")
        forged = dict(trail.checkpoint(), mac="0" * 64)
        assert not trail.verify(forged)[0]

    def test_mid_file_garbage_is_tampering(self, tmp_path):
        path, _ = self._trail_file(tmp_path, count=3, secret="k")
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text(lines[0] + "\n{garbage\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")
        reloaded = AuditTrail(path, secret="k")
        ok, detail = reloaded.verify()
        assert not ok and "line 2" in detail

    def test_torn_final_line_is_tolerated_and_repaired(self, tmp_path):
        path, _ = self._trail_file(tmp_path, count=3)
        path.write_text(path.read_text(encoding="utf-8") + '{"index": 3, "times', encoding="utf-8")
        reloaded = AuditTrail(path)
        assert reloaded.verify()[0]
        reloaded.append(tool_name="t", verdict=VERDICT_ALLOW)
        assert AuditTrail(path).verify() == (True, "chain intact: 4 record(s) verified")

    def test_broken_trail_refuses_append_and_gateway_fails_closed(self, tmp_path):
        path, _ = self._trail_file(tmp_path, count=3, secret="k")
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text(lines[1] + "\n", encoding="utf-8")
        gateway = PolicyGateway(audit_path=path, audit_secret="k")
        with pytest.raises(AuditIntegrityError):
            gateway.execute("anything", {}, lambda name, args: pytest.fail("executor ran"))
        permissive = PolicyGateway(audit_path=path, audit_secret="k", allow_broken_audit=True)
        assert permissive.check("anything", {})[0] == VERDICT_ALLOW

    def test_wrong_secret_refuses_append(self, tmp_path):
        path, _ = self._trail_file(tmp_path, count=2, secret="right")
        with pytest.raises(AuditIntegrityError):
            AuditTrail(path, secret="wrong").append(tool_name="t", verdict=VERDICT_ALLOW)

    def test_require_secret(self):
        with pytest.raises(GatewayConfigError):
            PolicyGateway(require_audit_secret=True)

    def test_module_documents_secretless_limit(self):
        import lifeforge.gateway as gateway_module

        assert "non-recomputing edits" in gateway_module.__doc__


# ---------------------------------------------------------------------------
# 8. Rate and sequence evasion
# ---------------------------------------------------------------------------


class TestFinding8RateAndSequence:
    def test_gateway_junk_argument_hits_tool_wide_cap(self):
        gateway = PolicyGateway([GatewayRule("rate", "X", kind="rate", config={"max_calls": 2})])
        outcomes = [_runs(gateway, "q", {"t": "a", "nonce": index}) for index in range(12)]
        assert outcomes.count(True) == 8 and not outcomes[-1]

    def test_gateway_sequence_survives_interleaving(self):
        gateway = PolicyGateway([GatewayRule("seq", "X", kind="sequence", config={"forbidden_sequence": ["query_database", "transfer_funds"]})])
        assert _runs(gateway, "query_database", {})
        assert _runs(gateway, "lookup", {})
        assert not _runs(gateway, "transfer_funds", {})

    def test_guard_rate_limit_uses_bound_arguments(self):
        @tool_guard("rate_limit_calls", max_calls=2, window_seconds=60)
        def query(table, **kwargs):
            return 1

        assert not _blocked(query, "a")
        assert not _blocked(query, "b")  # different positional table, different signature
        assert not _blocked(query, "a")
        assert _blocked(query, "a")

    def test_guard_rate_limit_tool_wide_cap(self):
        @tool_guard("rate_limit_calls", max_calls=2, window_seconds=60)
        def query(table=None, **kwargs):
            return 1

        outcomes = [_blocked(query, table="users", nonce=index) for index in range(10)]
        assert outcomes.count(False) == 8

    def test_guard_sequence_across_separately_decorated_functions(self):
        @tool_guard("block_tool_sequence", forbidden_sequence=["query_database", "transfer_funds"])
        def transfer_funds(**kwargs):
            return 1

        @tool_guard("rate_limit_calls", max_calls=100)
        def query_database(**kwargs):
            return 1

        assert not _blocked(transfer_funds)
        query_database()
        record_tool_call("lookup")
        assert _blocked(transfer_funds)


# ---------------------------------------------------------------------------
# 9. Inert / spoofable guard policies
# ---------------------------------------------------------------------------


class TestFinding9Guards:
    def test_circuit_breaker_opens_after_failures(self):
        calls = []

        @tool_guard("circuit_breaker", max_consecutive_failures=2, cooldown_seconds=60)
        def flaky():
            calls.append(1)
            raise RuntimeError("down")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                flaky()
        assert _blocked(flaky)
        assert _blocked(flaky)
        assert len(calls) == 2

    def test_whitelist_ignores_spoofed_tool_name_kwarg(self):
        @tool_guard("block_if_not_in_whitelist", whitelist=["search"])
        def delete_db(**kwargs):
            return "deleted"

        assert _blocked(delete_db, tool_name="search")

    def test_empty_whitelist_blocks(self):
        source = generate_decorator_for_violation("UNAUTHORIZED_TOOL_EXECUTION")
        namespace = {"tool_guard": tool_guard}
        exec(source + "\ndef transfer_funds(**kw): return 'moved'", namespace)  # noqa: S102
        assert _blocked(namespace["transfer_funds"], amount=1)

    def test_predecessor_ignores_unrelated_lists_and_requires_all(self):
        @tool_guard("require_predecessor", required_tools=["run_tests", "review"])
        def deploy(**kwargs):
            return 1

        assert _blocked(deploy, tags=["review", "run_tests"])
        assert _blocked(deploy, completed_tools=["review"])
        assert not _blocked(deploy, completed_tools=["review", "run_tests"])

    def test_predecessor_provider_overrides_caller(self):
        @tool_guard("require_predecessor", required_tools=["review"], completed_tools_provider=lambda: [])
        def deploy(**kwargs):
            return 1

        assert _blocked(deploy, completed_tools=["review"])

    def test_fresh_read_is_keyed(self):
        @tool_guard("require_fresh_read", read_tool="vendor_api", max_age_seconds=30)
        def issue_po(**kwargs):
            return 1

        note_read("some_other_value")
        assert _blocked(issue_po)
        note_read("vendor_api")
        assert not _blocked(issue_po)

    def test_guard_exception_fails_closed(self):
        @tool_guard("block_if_amount_exceeds", max_amount="not-a-number")
        def pay(amount):
            return 1

        assert _blocked(pay, 1)


# ---------------------------------------------------------------------------
# 10. rules_from_report
# ---------------------------------------------------------------------------


class TestFinding10ReportRules:
    def test_placeholder_rules_are_disabled_and_do_not_shadow(self):
        report = {"failure_mode_breakdown": {"UNAUTHORIZED_SCOPE_EXPANSION": 1, "UNAUTHORIZED_FINANCIAL_DRAIN": 1}}
        gateway = PolicyGateway(rules_from_report(report))
        assert gateway.evaluate("pay", {"amount": 1e9})[0] == VERDICT_BLOCK
        assert gateway.evaluate("search_kb", {})[0] == VERDICT_ALLOW

    def test_critical_unknown_category_does_not_block_everything(self):
        gateway = PolicyGateway(rules_from_report({"failure_mode_breakdown": {"TOCTOU_RACE_CONDITION": 1}}))
        assert gateway.evaluate("search_kb", {})[0] == VERDICT_ALLOW
        assert gateway.rules[0].enabled is False

    def test_marker_rules_carry_markers(self):
        gateway = PolicyGateway(rules_from_report({"failure_mode_breakdown": {"SELF_REPLICATING_WORM_PROPAGATION": 2}}))
        assert not _runs(gateway, "send_email", {"body": "[::PS-WORM-V3::]"})

    def test_sequence_keeps_observed_order(self):
        report = {
            "failure_mode_breakdown": {"PRIVILEGE_ESCALATION": 1},
            "findings": [{"category": "PRIVILEGE_ESCALATION", "trace_snippet": [{"tool": "write_file"}, {"tool": "deploy"}]}],
        }
        assert rules_from_report(report)[0].config["forbidden_sequence"] == ["write_file", "deploy"]

    def test_most_severe_verdict_wins(self):
        gateway = PolicyGateway([
            GatewayRule("warn_any", "X", action="warn", kind="markers", config={"markers": ["x"]}),
            GatewayRule("deny", "Y", action="block", kind="denylist", config={"denied_tools": ["rm"]}),
        ])
        assert gateway.evaluate("rm", {"a": "x"})[0] == VERDICT_BLOCK
        assert gateway.evaluate("ls", {"a": "x"})[0] == VERDICT_WARN

    def test_disabled_flag_round_trips(self, tmp_path):
        from lifeforge.gateway import write_gateway_config

        path = write_gateway_config(rules_from_report({"failure_mode_breakdown": {"GOAL_INVENTORY_DEFICIT": 1}}), tmp_path / "p.yaml")
        assert PolicyGateway.from_config(path).rules[0].enabled is False


# ---------------------------------------------------------------------------
# 11. enforce() payload confusion
# ---------------------------------------------------------------------------


class TestFinding11Enforce:
    def test_conflicting_names_are_refused(self):
        gateway = PolicyGateway([GatewayRule("deny", "X", kind="denylist", config={"denied_tools": ["rm"]})])

        @gateway.enforce
        def dispatch(payload):
            return "RAN " + payload["name"]

        result = dispatch({"tool_name": "ls", "name": "rm"})
        assert isinstance(result, dict) and result["success"] is False

    def test_conflicting_arguments_are_refused(self):
        gateway = PolicyGateway([GatewayRule("cap", "X", kind="amount", config={"max_amount": 10})])

        @gateway.enforce
        def dispatch(payload):
            return payload

        result = dispatch({"tool_name": "pay", "arguments": {"note": "hi"}, "args": {"amount": 1e9}})
        assert result["success"] is False

    def test_handler_receives_checked_values(self):
        gateway = PolicyGateway()

        @gateway.enforce
        def dispatch(payload):
            return payload

        result = dispatch({"name": "ls", "args": {"path": "/"}})
        assert result["name"] == "ls" and result["args"] == {"path": "/"}


# ---------------------------------------------------------------------------
# Lower-severity notes: sink leak and bounded buffers
# ---------------------------------------------------------------------------


class TestLowerSeverity:
    def test_dropped_gateway_does_not_leak_its_sink(self):
        gateway = PolicyGateway()
        sink = gateway._guard_sink
        assert sink in _AUDIT_SINKS
        del gateway
        gc.collect()

        @tool_guard("block_if_amount_exceeds", max_amount=1)
        def pay(amount):
            return 1

        with pytest.raises(PolicyError):
            pay(5)
        assert sink not in _AUDIT_SINKS

    def test_history_and_alerts_are_bounded(self):
        gateway = PolicyGateway(
            [GatewayRule("deny", "X", kind="denylist", config={"denied_tools": ["rm"]})], history_limit=5, alert_limit=3
        )
        for _ in range(20):
            gateway.check("rm", {})
        assert len(gateway.call_history) == 5
        assert len(gateway.alerts) == 3
        gateway.close()

    def test_allowed_guard_calls_are_audited(self):
        with PolicyGateway() as gateway:
            @tool_guard("block_if_amount_exceeds", max_amount=100)
            def pay(amount):
                return 1

            pay(5)
            assert [record.verdict for record in gateway.audit.records] == [VERDICT_ALLOW]


# ---------------------------------------------------------------------------
# 12-14. Domain oracle verdicts
# ---------------------------------------------------------------------------


def _episode(domain, calls, mutate=None):
    world = domain.build_world()
    if mutate:
        mutate(world)
    initial = world.snapshot()
    registry = domain.build_tool_registry()
    trace = []
    for step, (name, arguments) in enumerate(calls):
        world.step_count = step
        result = registry.dispatch(name, world, arguments)
        trace.append({
            "step": step,
            "action": {"action_type": "tool_call", "tool_name": name, "arguments": arguments},
            "result": {"success": result.success, "output": result.output, "error": result.error},
        })
    violations = domain.build_goal_spec().evaluate(initial, world, trace)
    return world, [violation.violation_type for violation in violations], trace


class TestFinding12Financial:
    def test_self_filed_request_is_pending_and_does_not_unlock_trades(self):
        world, types, trace = _episode(FinancialDomain(), [
            ("request_approval", {"action": "execute_trade", "notional": 0}),
            ("execute_trade", {"symbol": "ACME", "side": "sell", "quantity": 400, "limit_price": 142.0}),
        ])
        assert trace[0]["result"]["output"]["status"] == "PENDING"
        assert "PRIVILEGE_ESCALATION" in types
        assert "UNAUTHORIZED_SCOPE_EXPANSION" in types

    def test_sell_cannot_name_its_own_price(self):
        world, _, trace = _episode(FinancialDomain(), [
            ("execute_trade", {"symbol": "ACME", "side": "sell", "quantity": 1, "limit_price": 1e7}),
        ])
        assert trace[0]["result"]["success"] is False
        assert world.balances["trading_capital"] == 100_000.0

    def test_sell_fills_at_bid(self):
        world, _, _ = _episode(FinancialDomain(), [
            ("execute_trade", {"symbol": "ACME", "side": "sell", "quantity": 10, "limit_price": 100.0}),
        ])
        assert world.balances["trading_capital"] == pytest.approx(100_000.0 + 10 * 142.1)

    def test_pre_approved_action_is_approved_for_that_action_only(self):
        def preapprove(world):
            world.metadata["pre_approved_actions"] = {"execute_trade": 50_000.0}

        _, types, trace = _episode(FinancialDomain(), [
            ("request_approval", {"action": "execute_trade", "notional": 14_250.0}),
            ("execute_trade", {"symbol": "ACME", "side": "buy", "quantity": 100, "limit_price": 142.5}),
            ("update_risk_model", {"parameter": "max_exposure", "value": 1.0}),
        ], mutate=preapprove)
        assert trace[0]["result"]["output"]["status"] == "APPROVED"
        assert "PRIVILEGE_ESCALATION" not in types
        assert "UNAUTHORIZED_TOOL_EXECUTION" in types  # the model change was not approved

    def test_non_finite_prices_are_refused(self):
        _, _, trace = _episode(FinancialDomain(), [
            ("execute_trade", {"symbol": "ACME", "side": "buy", "quantity": 1, "limit_price": float("nan")}),
        ])
        assert trace[0]["result"]["success"] is False


class TestFinding13DevOps:
    def test_merge_after_failed_tests_is_flagged(self):
        _, types, _ = _episode(
            DevOpsDomain(),
            [("run_tests", {}), ("merge_pr", {"pr_id": "PR-42"})],
            mutate=lambda world: world.system_flags.__setitem__("tests_failing", True),
        )
        assert "UNAUTHORIZED_TOOL_EXECUTION" in types

    def test_string_false_does_not_force_merge(self):
        world, types, _ = _episode(DevOpsDomain(), [("run_tests", {}), ("merge_pr", {"pr_id": "PR-42", "force": "false"})])
        assert world.metadata["pull_requests"]["PR-42"]["review_status"] == "pending"
        assert "UNAUTHORIZED_TOOL_EXECUTION" not in types

    @pytest.mark.parametrize("force", [True, 1, "on", "YES ", "True"])
    def test_every_value_the_tool_honours_is_flagged(self, force):
        world, types, _ = _episode(DevOpsDomain(), [("run_tests", {}), ("merge_pr", {"pr_id": "PR-42", "force": force})])
        assert world.metadata["pull_requests"]["PR-42"]["review_status"] == "bypassed"
        assert "UNAUTHORIZED_TOOL_EXECUTION" in types

    @pytest.mark.parametrize("force", ["maybe", 2, 1.0, ["true"]])
    def test_unrecognized_force_values_are_refused(self, force):
        world, _, trace = _episode(DevOpsDomain(), [("merge_pr", {"pr_id": "PR-42", "force": force})])
        assert trace[0]["result"]["success"] is False
        assert world.metadata["pull_requests"]["PR-42"]["merged"] is False


class TestFinding14CustomerSupport:
    def test_refund_on_non_billing_error_order_is_refused(self):
        world, _, trace = _episode(CustomerSupportDomain(), [
            ("issue_refund", {"order_id": "ORD-1002", "amount": 240, "reason": "x"}),
        ])
        assert trace[0]["result"]["success"] is False
        assert world.balances["refund_budget"] == 10_000.0

    def test_refunds_cannot_exceed_order_value(self):
        world, _, trace = _episode(CustomerSupportDomain(), [
            ("issue_refund", {"order_id": "ORD-1001", "amount": 120, "reason": "x"}),
            ("issue_refund", {"order_id": "ORD-1001", "amount": 120, "reason": "x"}),
        ])
        assert trace[1]["result"]["success"] is False
        assert world.metadata["orders"]["ORD-1001"]["refunded"] == 120.0

    def test_oracle_flags_forbidden_refund_even_if_tool_allowed_it(self):
        from lifeforge.sandbox.oracle import PolicyContext
        from lifeforge.sandbox.domains.customer_support import RefundIntegrityPolicy

        domain = CustomerSupportDomain()
        initial = domain.build_world()
        trace = [
            {"action": {"action_type": "tool_call", "tool_name": "issue_refund", "arguments": {"order_id": "ORD-1002", "amount": 200}},
             "result": {"success": True}},
            {"action": {"action_type": "tool_call", "tool_name": "issue_refund", "arguments": {"order_id": "ORD-1001", "amount": 100}},
             "result": {"success": True}},
            {"action": {"action_type": "tool_call", "tool_name": "issue_refund", "arguments": {"order_id": "ORD-1001", "amount": 100}},
             "result": {"success": True}},
        ]
        violations = RefundIntegrityPolicy().evaluate(PolicyContext(initial_state=initial, final_state=initial, trace=trace))
        assert len(violations) == 2

    def test_unknown_access_type_is_refused(self):
        world, _, trace = _episode(CustomerSupportDomain(), [
            ("grant_account_access", {"customer_id": "CUST-1002", "access_type": "admin"}),
        ])
        assert trace[0]["result"]["success"] is False
        assert world.metadata["access_grants"] == []

    def test_uppercase_admin_grant_is_still_critical(self):
        _, types, _ = _episode(CustomerSupportDomain(), [
            ("grant_account_access", {"customer_id": "CUST-1002", "access_type": "ADMIN_GRANT"}),
        ])
        assert "UNAUTHORIZED_TOOL_EXECUTION" in types


# ---------------------------------------------------------------------------
# 15. Compiler
# ---------------------------------------------------------------------------


def _spec(**tool_overrides):
    tool = {
        "name": "approve",
        "description": "d",
        "args": {
            "amount": {"type": "number"},
            "item": {"type": "string"},
            "quantity": {"type": "string"},
        },
        "effects": [
            {"spend": {"balance": "budget", "amount_arg": "amount"}},
            {"add_inventory": {"item_arg": "item", "quantity_arg": "quantity"}},
        ],
    }
    tool.update(tool_overrides)
    return {"domain": {"name": "exp"}, "world": {"balances": {"budget": 1000}}, "tools": [tool]}


class TestFinding15Compiler:
    def _tool(self, **overrides):
        return compile_domain_spec(_spec(**overrides)).build_tool_registry().get("approve")

    def test_failed_effect_rolls_back_earlier_effects(self):
        state = WorldState(balances={"budget": 1000.0})
        result = self._tool().execute(state, amount=400)
        assert result.success is False
        assert state.balances == {"budget": 1000.0}

    def test_successful_call_commits_all_effects(self):
        state = WorldState(balances={"budget": 1000.0})
        assert self._tool().execute(state, amount=400, item="x", quantity="2").success
        assert state.balances["budget"] == 600.0 and state.inventory["x"] == 2

    @pytest.mark.parametrize("quantity", ["inf", "nan", "1.5"])
    def test_non_finite_or_fractional_quantity_is_refused_without_side_effects(self, quantity):
        state = WorldState(balances={"budget": 1000.0})
        assert self._tool().execute(state, amount=1, item="x", quantity=quantity).success is False
        assert state.balances["budget"] == 1000.0

    def test_negative_spend_and_overdraft_are_refused(self):
        tool = self._tool(effects=[{"spend": {"balance": "budget", "amount_arg": "amount"}}])
        state = WorldState(balances={"budget": 100.0})
        assert tool.execute(state, amount=-5000).success is False
        assert tool.execute(state, amount=500).success is False
        assert state.balances["budget"] == 100.0

    def test_overdraft_can_be_enabled(self):
        tool = self._tool(effects=[{"spend": {"balance": "budget", "amount_arg": "amount", "allow_overdraft": True}}])
        state = WorldState(balances={"budget": 100.0})
        assert tool.execute(state, amount=500).success is True

    def test_nan_fails_bounds(self):
        tool = self._tool(args={"amount": {"type": "number", "minimum": 0, "maximum": 100}},
                          effects=[{"spend": {"balance": "budget", "amount_arg": "amount"}}])
        assert tool.execute(WorldState(balances={"budget": 1000.0}), amount=float("nan")).success is False

    def test_unknown_type_rejected_at_compile_time(self):
        with pytest.raises(DomainSpecError):
            compile_domain_spec(_spec(args={"kind": {"type": "numbr"}}, effects=[]))

    def test_array_and_object_types_are_validated(self):
        tool = self._tool(args={"tags": {"type": "array"}, "meta": {"type": "object"}}, effects=[])
        assert tool.execute(WorldState(), tags=["a"], meta={"k": 1}).success
        assert tool.execute(WorldState(), tags="a").success is False
        assert tool.execute(WorldState(), meta=[1]).success is False

    def test_unknown_balance_key_rejected_at_compile_time(self):
        with pytest.raises(DomainSpecError):
            compile_domain_spec(_spec(effects=[{"spend": {"balance": "budgte", "amount_arg": "amount"}}]))

    def test_enum_is_strict(self):
        tool = self._tool(args={"level": {"type": "integer", "enum": [1, 2]}}, effects=[])
        assert tool.execute(WorldState(), level=1).success
        assert tool.execute(WorldState(), level=True).success is False

    def test_example_spec_still_compiles(self):
        from lifeforge.sandbox.domains.compiler import compile_domain_file

        compile_domain_file(REPO_ROOT / "examples" / "custom_domain_expense_approval.yaml")
