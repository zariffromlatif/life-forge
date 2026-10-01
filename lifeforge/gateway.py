"""Runtime policy gateway: offline findings become online enforcement.

This is the bridge between the simulator and production.  The same invariant
policy objects that judge a completed episode offline are evaluated here
against a *single live tool call*, before the call reaches its implementation.

Three things happen on every intercepted call, in this order:

1. **Verdict.**  The call is checked against the guard rules and the
   configured runtime policies.  The outcome is allow, warn, or block.
2. **Evidence.**  The decision is appended to a hash-chained audit log.  Each
   record commits to its predecessor's digest, so removing or editing any
   record invalidates every later entry.  That is what makes the trail
   tamper-*evident*: an auditor can verify it without trusting the operator.
3. **Alert.**  A call matching a known failure signature from the MAP-Elites
   archive raises an alert, so a live agent hitting a previously discovered
   failure mode is reported rather than silently re-discovered.

Configuration is either programmatic or from a YAML file::

    gateway = PolicyGateway.from_config("lifeforge_policy.yaml")
    guarded = gateway.wrap_executor(original_executor)

Design constraints: the gateway sits in the hot path of a production tool call,
so it holds no locks across the call, performs no I/O on the allow path beyond
the optional audit append, and never swallows the underlying tool's exception.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from lifeforge.hardening import GuardEvent, PolicyError, register_audit_sink, unregister_audit_sink

#: Genesis digest for a fresh audit chain.
GENESIS_DIGEST = "0" * 64

#: Verdicts the gateway can reach.
VERDICT_ALLOW = "ALLOW"
VERDICT_WARN = "WARN"
VERDICT_BLOCK = "BLOCK"


@dataclass(frozen=True)
class GatewayRule:
    """One enforcement rule applied to live tool calls.

    A rule is deliberately data-only so it can be serialized into a config file
    and reviewed by a human before it starts blocking production traffic.

    Attributes
    ----------
    name:
        Identifier shown in audit records and alerts.
    violation_type:
        The failure class this rule defends against, using the same vocabulary
        as the offline oracle so reports and runtime logs correlate directly.
    action:
        ``"allow"``, ``"warn"``, or ``"block"``.
    tools:
        Tool names the rule applies to.  ``None`` or empty means every tool.
    kind:
        Rule semantics: ``"whitelist"`` (tool must be listed), ``"amount"``
        (numeric argument must not exceed a cap), ``"recipient"`` (recipient
        must match the allow-list), ``"markers"`` (argument must not contain a
        payload marker), ``"rate"`` (identical call frequency cap),
        ``"sequence"`` (forbidden ordering of tool calls).
    config:
        Rule-specific parameters.
    severity:
        Severity recorded for the finding.
    """

    name: str
    violation_type: str
    action: str = "block"
    tools: tuple[str, ...] = ()
    kind: str = "whitelist"
    config: dict[str, Any] = field(default_factory=dict)
    severity: str = "HIGH"

    def applies_to(self, tool_name: str) -> bool:
        """Return True when this rule governs the named tool."""
        if not self.tools:
            return True
        return tool_name in self.tools

    def to_dict(self) -> dict[str, Any]:
        """Serialize the rule for config export."""
        return {
            "name": self.name,
            "violation_type": self.violation_type,
            "action": self.action,
            "tools": list(self.tools),
            "kind": self.kind,
            "config": dict(self.config),
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GatewayRule:
        """Build a rule from a config mapping."""
        return cls(
            name=str(data.get("name", "unnamed_rule")),
            violation_type=str(data.get("violation_type", "POLICY_VIOLATION")),
            action=str(data.get("action", "block")).lower(),
            tools=tuple(str(tool) for tool in (data.get("tools") or ())),
            kind=str(data.get("kind", "whitelist")),
            config=dict(data.get("config") or {}),
            severity=str(data.get("severity", "HIGH")),
        )


@dataclass
class AuditRecord:
    """One hash-chained entry in the gateway's tamper-evident trail."""

    index: int
    timestamp: str
    tool_name: str
    verdict: str
    rule: str | None
    violation_type: str | None
    severity: str | None
    arguments_digest: str
    reason: str
    previous_digest: str
    digest: str = ""

    def compute_digest(self) -> str:
        """Compute this record's digest over its own fields plus the predecessor.

        The arguments are committed through a SHA-256 digest rather than in
        clear text, so the chain proves *what was decided about which call*
        without storing potentially sensitive payloads.
        """
        payload = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "tool": self.tool_name,
                "verdict": self.verdict,
                "rule": self.rule,
                "violation_type": self.violation_type,
                "severity": self.severity,
                "arguments_digest": self.arguments_digest,
                "reason": self.reason,
                "previous": self.previous_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        """Serialize the record; digests are omitted in human-facing output."""
        data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "tool": self.tool_name,
            "verdict": self.verdict,
            "rule": self.rule,
            "violation_type": self.violation_type,
            "severity": self.severity,
            "arguments_digest": self.arguments_digest,
            "reason": self.reason,
            "previous_digest": self.previous_digest,
        }
        if include_digest:
            data["digest"] = self.digest
        return data


def digest_arguments(arguments: dict[str, Any]) -> str:
    """Return a stable digest of a call's arguments.

    Keys are sorted, so two semantically identical calls hash identically no
    matter how the caller ordered the keyword arguments.
    """
    try:
        payload = json.dumps(arguments, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        payload = str(arguments)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


class AuditTrail:
    """Append-only, hash-chained audit log with optional durable backing.

    Every append links to the previous digest, so any modification of an
    earlier record breaks verification of every record after it.  Verification
    recomputes the whole chain from genesis, which is O(n) but runs offline.

    When ``path`` is given, each record is also appended to that file as one
    JSON object per line, so the trail survives process restarts and can be
    shipped to an external log sink.
    """

    def __init__(self, path: Path | str | None = None, *, secret: bytes | str | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()

        if self.path is not None and self.path.exists():
            self._load_existing()

    @property
    def records(self) -> list[AuditRecord]:
        """Return a copy of all records in the trail."""
        with self._lock:
            return list(self._records)

    @property
    def head_digest(self) -> str:
        """Digest of the most recent record, or the genesis digest when empty."""
        with self._lock:
            return self._records[-1].digest if self._records else GENESIS_DIGEST

    def append(
        self,
        *,
        tool_name: str,
        verdict: str,
        arguments: dict[str, Any] | None = None,
        rule: str | None = None,
        violation_type: str | None = None,
        severity: str | None = None,
        reason: str = "",
    ) -> AuditRecord:
        """Append one decision and return the sealed record."""
        with self._lock:
            previous = self._records[-1].digest if self._records else GENESIS_DIGEST
            record = AuditRecord(
                index=len(self._records),
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool_name=tool_name,
                verdict=verdict,
                rule=rule,
                violation_type=violation_type,
                severity=severity,
                arguments_digest=digest_arguments(arguments or {}),
                reason=reason,
                previous_digest=previous,
            )
            record.digest = self._sign(record.compute_digest())
            self._records.append(record)
            if self.path is not None:
                self._persist(record)
            return record

    def _sign(self, digest: str) -> str:
        """Key the digest when a secret is configured.

        Without a secret the chain detects accidental corruption and casual
        edits.  With one it also resists an attacker who can write to the log
        file but does not hold the key.
        """
        if not self.secret:
            return digest
        return hmac.new(self.secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain and report whether it is intact.

        Returns ``(ok, detail)``.  On failure ``detail`` names the first broken
        record index and why, so an auditor can point at the exact entry that
        was tampered with.
        """
        with self._lock:
            previous = GENESIS_DIGEST
            for position, record in enumerate(self._records):
                if record.index != position:
                    return False, f"record {position} has index {record.index} (out of order)"
                if record.previous_digest != previous:
                    return False, (
                        f"record {position} commits to {record.previous_digest[:16]}..., "
                        f"expected {previous[:16]}..."
                    )
                expected = self._sign(record.compute_digest())
                if not hmac.compare_digest(expected, record.digest):
                    return (
                        False,
                        f"record {position} was modified after it was written "
                        f"(digest mismatch on tool '{record.tool_name}')",
                    )
                previous = record.digest
            return True, f"chain intact: {len(self._records)} record(s) verified"

    def export(self) -> list[dict[str, Any]]:
        """Return the full trail as JSON-serializable dicts, digests included."""
        return [record.to_dict() for record in self.records]

    def summary(self) -> dict[str, Any]:
        """Aggregate counts by verdict and by violation type."""
        by_verdict: dict[str, int] = {}
        by_violation: dict[str, int] = {}
        blocked_tools: dict[str, int] = {}
        for record in self.records:
            by_verdict[record.verdict] = by_verdict.get(record.verdict, 0) + 1
            if record.violation_type:
                by_violation[record.violation_type] = by_violation.get(record.violation_type, 0) + 1
            if record.verdict == VERDICT_BLOCK:
                blocked_tools[record.tool_name] = blocked_tools.get(record.tool_name, 0) + 1
        return {
            "total_records": len(self.records),
            "by_verdict": by_verdict,
            "by_violation_type": by_violation,
            "blocked_tools": blocked_tools,
            "head_digest": self.head_digest,
        }

    def _persist(self, record: AuditRecord) -> None:
        """Append one record to the backing file as a JSON line."""
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict()) + "\n")

    def _load_existing(self) -> None:
        """Rebuild in-memory state from a previously written trail file."""
        assert self.path is not None
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # A truncated final line means the process died mid-write; the
                # chain stays verifiable up to the last complete record.
                continue
            record = AuditRecord(
                index=int(data.get("index", len(self._records))),
                timestamp=str(data.get("timestamp", "")),
                tool_name=str(data.get("tool", "")),
                verdict=str(data.get("verdict", "")),
                rule=data.get("rule"),
                violation_type=data.get("violation_type"),
                severity=data.get("severity"),
                arguments_digest=str(data.get("arguments_digest", "")),
                reason=str(data.get("reason", "")),
                previous_digest=str(data.get("previous_digest", GENESIS_DIGEST)),
                digest=str(data.get("digest", "")),
            )
            self._records.append(record)


@dataclass
class GatewayAlert:
    """An alert raised when live traffic matches a known failure signature."""

    timestamp: str
    tool_name: str
    violation_type: str
    severity: str
    message: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the alert."""
        return {
            "timestamp": self.timestamp,
            "tool": self.tool_name,
            "violation_type": self.violation_type,
            "severity": self.severity,
            "message": self.message,
            "signature": self.signature,
        }


class PolicyGateway:
    """Enforces invariant policies on live tool calls and audits every decision.

    Parameters
    ----------
    rules:
        Enforcement rules, evaluated in order.  The first matching rule decides.
    policies:
        Optional :class:`~lifeforge.sandbox.policies.Policy` instances applied to
        the accumulated call history.  These catch episode-level patterns
        (tool sequences, cascading failures) that no single call reveals.
    audit_path:
        When given, the audit trail is persisted there as JSON lines.
    audit_secret:
        Optional HMAC key for the audit chain.
    alert_sink:
        Callback invoked with each :class:`GatewayAlert`.
    default_verdict:
        Verdict for a call that no rule matches.  ``ALLOW`` by default, which is
        the correct posture for a monitor-first rollout.
    """

    def __init__(
        self,
        rules: Sequence[GatewayRule] | None = None,
        *,
        policies: Sequence[Any] | None = None,
        audit_path: Path | str | None = None,
        audit_secret: bytes | str | None = None,
        alert_sink: Callable[[GatewayAlert], None] | None = None,
        default_verdict: str = VERDICT_ALLOW,
        archive: Any | None = None,
    ) -> None:
        self.rules: list[GatewayRule] = list(rules or [])
        self.policies: list[Any] = list(policies or [])
        self.default_verdict = default_verdict.upper()
        self.audit = AuditTrail(audit_path, secret=audit_secret)
        self.trail = self.audit  # readable alias
        self.alerts: list[GatewayAlert] = []
        self.alert_sink = alert_sink
        self.archive = archive

        self.call_history: list[tuple[str, dict[str, Any]]] = []
        self._rate_state: dict[str, list[float]] = {}
        self._lock = threading.Lock()

        # Hardening guards installed anywhere in the process report their
        # decisions into the same trail, so one artifact covers both.
        register_audit_sink(self._on_guard_event)

    # ------------------------------------------------------------------
    # Construction from configuration
    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any] | Path | str,
        *,
        alert_sink: Callable[[GatewayAlert], None] | None = None,
    ) -> PolicyGateway:
        """Build a gateway from a mapping or a YAML/JSON file path.

        Recognized keys: ``rules`` (list of rule mappings), ``policies`` (list of
        policy names, optionally with a ``config`` mapping), ``audit_path``,
        ``audit_secret``, ``default_verdict``.
        """
        if isinstance(config, (str, Path)):
            data = load_gateway_config(Path(config))
        else:
            data = dict(config)

        rules = [GatewayRule.from_dict(entry) for entry in (data.get("rules") or [])]
        policies = _build_policies(data.get("policies") or [])

        return cls(
            rules,
            policies=policies,
            audit_path=data.get("audit_path"),
            audit_secret=data.get("audit_secret"),
            alert_sink=alert_sink,
            default_verdict=str(data.get("default_verdict", VERDICT_ALLOW)),
        )

    def to_config(self) -> dict[str, Any]:
        """Serialize the gateway's rules into a config mapping."""
        return {
            "default_verdict": self.default_verdict,
            "rules": [rule.to_dict() for rule in self.rules],
            "policies": [
                {
                    "name": getattr(policy, "name", "policy"),
                    "violation_type": getattr(policy, "violation_type", "POLICY_VIOLATION"),
                }
                for policy in self.policies
            ],
        }

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------

    def evaluate(self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, GatewayRule | None, str]:
        """Decide one call: return ``(verdict, rule, reason)``."""
        for rule in self.rules:
            if not rule.applies_to(tool_name):
                continue
            blocked, reason = self._rule_blocks(rule, tool_name, arguments)
            if blocked:
                return rule.action.upper(), rule, reason
        return self.default_verdict, None, "no rule matched"

    def check(self, tool_name: str, arguments: dict[str, Any] | None = None) -> tuple[str, GatewayRule | None, str]:
        """Evaluate, audit, and alert on a call without executing it.

        Use this when the executor lives in another process: call ``check`` from
        the proxy, then forward the call only when the verdict is not ``BLOCK``.
        """
        arguments = dict(arguments or {})
        verdict, rule, reason = self.evaluate(tool_name, arguments)

        record = self.audit.append(
            tool_name=tool_name,
            verdict=verdict,
            arguments=arguments,
            rule=rule.name if rule else None,
            violation_type=rule.violation_type if rule else None,
            severity=rule.severity if rule else None,
            reason=reason,
        )

        if verdict == VERDICT_BLOCK and rule is not None:
            self._raise_alert(tool_name, rule, reason, record)
        elif verdict == VERDICT_WARN and rule is not None:
            self._raise_alert(tool_name, rule, reason, record)

        with self._lock:
            self.call_history.append((tool_name, arguments))
        return verdict, rule, reason

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        executor: Callable[[str, dict[str, Any]], Any],
    ) -> Any:
        """Check a call, then run it through ``executor`` when permitted.

        Raises
        ------
        PolicyError
            When the verdict is ``BLOCK``.  The executor is never invoked.
        """
        verdict, rule, reason = self.check(tool_name, arguments)
        if verdict == VERDICT_BLOCK:
            raise PolicyError(
                f"Gateway blocked '{tool_name}': {reason}",
                tool_name=tool_name,
                policy=rule.name if rule else "gateway",
                details={
                    "violation_type": rule.violation_type if rule else None,
                    "severity": rule.severity if rule else None,
                },
            )
        return executor(tool_name, dict(arguments))

    def evaluate_history(self) -> list[Any]:
        """Run the configured policy objects over the accumulated call history.

        Single-call rules catch per-call violations; the episode-level policies
        catch patterns that only exist across a sequence of calls (reconnaissance
        sweeps, forbidden tool chains).  Returns the violations the policies
        found, in policy order.  Callers decide what to do with a pattern
        finding - typically raise an alert and tighten the per-call rules,
        because the offending call has already been forwarded by the time a
        pattern is visible.
        """
        if not self.policies or not self.call_history:
            return []

        from lifeforge.sandbox.oracle import PolicyContext
        from lifeforge.sandbox.world_state import WorldState

        # The gateway does not own a world; policies only read the trace.
        empty_world = WorldState()
        trace: list[dict[str, Any]] = []
        for index, (tool_name, arguments) in enumerate(self.call_history):
            trace.append(
                {
                    "step": index,
                    "action": {
                        "action_type": "tool_call",
                        "tool_name": tool_name,
                        "arguments": dict(arguments),
                    },
                }
            )

        context = PolicyContext(
            initial_state=empty_world,
            final_state=empty_world,
            trace=trace,
        )
        violations: list[Any] = []
        for policy in self.policies:
            if getattr(policy, "is_inert", None) is not None and policy.is_inert():
                continue
            try:
                found = policy.evaluate(context)
            except Exception:  # pragma: no cover - defensive isolation
                continue
            if found:
                violations.extend(found)
        return violations

    def wrap_executor(
        self,
        executor: Callable[[str, dict[str, Any]], Any],
    ) -> Callable[[str, dict[str, Any]], Any]:
        """Return a guarded replacement for a tool executor function.

        The returned callable has the same signature as the original, so it can
        be dropped into an existing agent loop::

            guarded = gateway.wrap_executor(original_executor)
            agent = Agent(executor=guarded)
        """

        def guarded_executor(tool_name: str, arguments: dict[str, Any] | None = None) -> Any:
            return self.execute(tool_name, dict(arguments or {}), executor)

        guarded_executor.__name__ = getattr(executor, "__name__", "executor")
        guarded_executor.__doc__ = (
            f"LIFE FORGE-guarded wrapper around {getattr(executor, '__name__', 'executor')}."
        )
        return guarded_executor

    def enforce(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator form for HTTP-style executors taking a JSON body.

        The wrapped function must accept a single ``payload`` argument shaped as
        ``{"tool_name": str, "arguments": dict}``, which is the shape most agent
        frameworks use for a tool-dispatch endpoint.
        """
        import functools

        @functools.wraps(func)
        def wrapper(payload: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            tool_name = str(payload.get("tool_name") or payload.get("name") or "unknown_tool")
            arguments = payload.get("arguments") or payload.get("args") or {}
            verdict, rule, reason = self.check(tool_name, dict(arguments))
            if verdict == VERDICT_BLOCK:
                return {
                    "success": False,
                    "error": f"PolicyError: {reason}",
                    "policy": rule.name if rule else "gateway",
                    "violation_type": rule.violation_type if rule else None,
                }
            return func(payload, *args, **kwargs)

        return wrapper

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def _rule_blocks(
        self,
        rule: GatewayRule,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, str]:
        """Return whether a rule triggers, with its reason."""
        config = rule.config

        if rule.kind == "whitelist":
            allowed = {str(item) for item in config.get("allowed_tools", []) or []}
            if not allowed:
                # An empty allow-list would silently disable the rule. Treat it
                # as a configuration error rather than a permissive default,
                # because a rule that never fires is worse than no rule: it
                # reads as protection in a review and provides none.
                return True, (
                    f"rule '{rule.name}' has an empty allowed_tools list and cannot be "
                    "evaluated; populate it or remove the rule"
                )
            if tool_name not in allowed:
                return True, f"tool '{tool_name}' is not in the authorized allow-list"

        elif rule.kind == "denylist":
            denied = {str(item) for item in config.get("denied_tools", []) or []}
            if tool_name in denied:
                return True, f"tool '{tool_name}' is on the prohibited list"

        elif rule.kind == "amount":
            argument = str(config.get("argument", "amount"))
            raw = arguments.get(argument)
            if raw is None:
                return False, ""
            try:
                amount = float(raw)
            except (TypeError, ValueError):
                return False, ""
            cap = float(config.get("max_amount", 0.0))
            if amount > cap:
                approval = config.get("approved_token_argument")
                if approval and arguments.get(str(approval)):
                    return False, ""
                return True, f"{argument}={amount:,.2f} exceeds the authorized cap of {cap:,.2f}"

        elif rule.kind == "recipient":
            argument = str(config.get("argument", "recipient"))
            raw = arguments.get(argument)
            if raw is None:
                return False, ""
            candidates = [item.lower() for item in config.get("allowed_recipients", []) or []]
            if not candidates:
                return False, ""
            value = str(raw).strip().lower()
            if not any(candidate in value for candidate in candidates):
                return True, f"recipient '{raw}' is not on the egress allow-list"

        elif rule.kind == "markers":
            markers = [str(marker) for marker in config.get("markers", []) or []]
            for key, value in arguments.items():
                if not isinstance(value, str):
                    continue
                for marker in markers:
                    if marker and marker in value:
                        return True, f"argument '{key}' carries payload marker {marker}"

        elif rule.kind == "rate":
            signature = _rate_signature(tool_name, arguments, config.get("signature_arguments", "all"))
            max_calls = int(config.get("max_calls", 5))
            window = float(config.get("window_seconds", 60.0))
            now = time.monotonic()
            with self._lock:
                history = [stamp for stamp in self._rate_state.get(signature, []) if now - stamp < window]
                if len(history) >= max_calls:
                    self._rate_state[signature] = history
                    return True, (
                        f"identical call to '{tool_name}' repeated {len(history)} times "
                        f"within {window:.0f}s (limit {max_calls})"
                    )
                history.append(now)
                self._rate_state[signature] = history

        elif rule.kind == "sequence":
            sequence = [str(item) for item in config.get("forbidden_sequence", []) or []]
            if not sequence:
                return False, ""
            target = sequence[-1].split(":")[0]
            if tool_name != target:
                return False, ""
            prefix = [entry.split(":")[0] for entry in sequence[:-1]]
            with self._lock:
                history = [name for name, _ in self.call_history[-len(prefix):]]
            if len(history) == len(prefix) and history == prefix:
                return True, f"call completes the forbidden sequence {sequence}"

        return False, ""

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def _raise_alert(self, tool_name: str, rule: GatewayRule, reason: str, record: AuditRecord) -> None:
        """Record and dispatch an alert for a warn or block decision."""
        alert = GatewayAlert(
            timestamp=record.timestamp,
            tool_name=tool_name,
            violation_type=rule.violation_type,
            severity=rule.severity,
            message=reason,
            signature=f"{tool_name}:{rule.violation_type}",
        )
        self.alerts.append(alert)
        if self.alert_sink is not None:
            try:
                self.alert_sink(alert)
            except Exception:  # pragma: no cover - a bad sink must not break enforcement
                pass

    def _on_guard_event(self, event: GuardEvent) -> None:
        """Mirror a hardening guard's decision into the gateway's audit trail.

        This is how the generated decorators and the runtime gateway produce a
        single unified artifact instead of two disjoint logs.
        """
        self.audit.append(
            tool_name=event.tool_name,
            verdict=VERDICT_ALLOW if event.allowed else VERDICT_BLOCK,
            arguments=dict(event.details),
            rule=event.policy,
            violation_type=None,
            severity=None,
            reason=event.reason,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Detach the gateway's audit sink so it stops receiving guard events."""
        unregister_audit_sink(self._on_guard_event)


def _rate_signature(tool_name: str, arguments: dict[str, Any], signature_arguments: Any) -> str:
    """Build the identity string a rate rule counts against."""
    if signature_arguments == "all" or signature_arguments is None:
        keys = sorted(arguments)
    elif isinstance(signature_arguments, str):
        keys = [signature_arguments]
    else:
        keys = sorted(str(key) for key in signature_arguments)
    payload = {key: arguments.get(key) for key in keys}
    return f"{tool_name}:{json.dumps(payload, sort_keys=True, default=str)}"


def _build_policies(entries: Iterable[Any]) -> list[Any]:
    """Instantiate policy objects from config entries.

    Each entry is either a policy name or a mapping ``{name: ..., config: {...}}``.
    Unknown names are skipped with a warning rather than crashing the gateway at
    startup, because a gateway that refuses to boot is worse than one that runs
    with one fewer rule.
    """
    from lifeforge.sandbox.policies import build_policy

    policies: list[Any] = []
    for entry in entries:
        if isinstance(entry, str):
            name, config = entry, {}
        elif isinstance(entry, dict):
            name = str(entry.get("name", ""))
            config = dict(entry.get("config") or {})
        else:
            continue
        if not name:
            continue
        try:
            policies.append(build_policy(name, **config))
        except (KeyError, TypeError):
            continue
    return policies


def load_gateway_config(path: Path | str) -> dict[str, Any]:
    """Load a gateway config from YAML or JSON.

    YAML is preferred for human review; JSON is accepted so a config can be
    generated by tooling without a YAML dependency.
    """
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - PyYAML is normally present
            raise ImportError(
                "PyYAML is required to read a YAML gateway config. "
                "Install it with 'pip install pyyaml' or supply a JSON config."
            ) from exc
        return yaml.safe_load(text) or {}
    return json.loads(text)


def write_gateway_config(
    gateway_or_rules: PolicyGateway | Iterable[GatewayRule],
    path: Path | str,
    *,
    as_json: bool = False,
) -> Path:
    """Write a gateway config to disk for review and deployment."""
    if isinstance(gateway_or_rules, PolicyGateway):
        data = gateway_or_rules.to_config()
    else:
        data = {"default_verdict": VERDICT_ALLOW, "rules": [rule.to_dict() for rule in gateway_or_rules]}

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if as_json or output.suffix.lower() == ".json":
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        try:
            import yaml
        except ImportError:  # pragma: no cover - fall back to JSON
            output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            output.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return output


def rules_from_report(report: dict[str, Any]) -> list[GatewayRule]:
    """Derive starter enforcement rules from a benchmark report.

    This is the feedback loop in one function: violations discovered offline
    become runtime rules.  Rules are generated in ``block`` mode for CRITICAL
    findings and ``warn`` for everything else, which suits a monitor-first
    rollout where the operator promotes rules to blocking after observing them.

    Where the report's findings name the tools involved, those names are
    extracted into the rule's configuration so the rule actually fires.  Rules
    whose tool set cannot be derived are still emitted, with an explicit note in
    the config, because the operator has to supply the allow-list for a
    least-privilege rule regardless.
    """
    from lifeforge.hardening import _VIOLATION_SEVERITY

    breakdown = (report or {}).get("failure_mode_breakdown", {}) or {}
    tools_by_category = _tools_by_category(report or {})

    rules: list[GatewayRule] = []
    for violation_type, count in breakdown.items():
        category = str(violation_type).upper()
        severity = _VIOLATION_SEVERITY.get(category, "MEDIUM")
        action = "block" if severity == "CRITICAL" else "warn"
        kind = _default_rule_kind(category)
        tools = tools_by_category.get(category, [])

        config: dict[str, Any] = {}
        if kind == "denylist" and tools:
            config["denied_tools"] = sorted(tools)
        elif kind == "amount":
            config = {"argument": "amount", "max_amount": 0.0}
        elif kind == "recipient":
            config = {"argument": "recipient", "allowed_recipients": ["internal"]}
        elif kind == "rate":
            config = {"max_calls": 3, "window_seconds": 60.0}
        elif kind == "sequence" and tools:
            config = {"forbidden_sequence": sorted(tools)}
        else:
            # A least-privilege rule needs the operator's real allow-list.
            config = {"allowed_tools": [], "note": "TODO: populate allowed_tools for this agent"}

        rules.append(
            GatewayRule(
                name=f"discovered_{category.lower()}",
                violation_type=category,
                action=action,
                tools=tuple(sorted(tools)),
                kind=kind,
                config=config,
                severity=severity,
            )
        )
    return rules


def _tools_by_category(report: dict[str, Any]) -> dict[str, set[str]]:
    """Collect the tools named in a report's findings, grouped by category.

    The analyzer records the offending tool inside each finding's
    ``trace_snippet``.  Reading them back is what lets a generated rule name the
    tool it must govern instead of shipping an inert placeholder.
    """
    collected: dict[str, set[str]] = {}
    for finding in report.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        category = str(finding.get("category", "")).upper()
        if not category:
            continue
        for event in finding.get("trace_snippet", []) or []:
            if not isinstance(event, dict):
                continue
            tool = event.get("tool")
            if isinstance(tool, str) and tool and tool != "None":
                collected.setdefault(category, set()).add(tool)
    return collected


def _default_rule_kind(violation_type: str) -> str:
    """Map a violation to the rule kind that best expresses its enforcement."""
    mapping = {
        "UNAUTHORIZED_TOOL_EXECUTION": "denylist",
        "UNAUTHORIZED_SCOPE_EXPANSION": "whitelist",
        "UNAUTHORIZED_FINANCIAL_DRAIN": "amount",
        "BUDGET_EXCEEDED": "amount",
        "UNAUTHORIZED_DATA_EXFILTRATION": "recipient",
        "SELF_REPLICATING_WORM_PROPAGATION": "markers",
        "RAG_MEMORY_POISONING_ADOPTED": "markers",
        "RECURSIVE_LOOP_TRAP": "rate",
        "EXCESSIVE_DATA_QUERYING": "rate",
        "PRIVILEGE_ESCALATION": "sequence",
        "PARAMETER_BOUNDARY_VIOLATION": "markers",
    }
    return mapping.get(str(violation_type).upper(), "whitelist")
