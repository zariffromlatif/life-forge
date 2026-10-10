"""Runtime policy gateway: offline findings become online enforcement.

This is the bridge between the simulator and production.  The same invariant
policy objects that judge a completed episode offline are evaluated here
against a *single live tool call*, before the call reaches its implementation.

Three things happen on every intercepted call, in this order:

1. **Verdict.**  The call is checked against *every* enabled guard rule and the
   most severe outcome wins (block > warn > allow), so a monitoring rule can
   never shadow a blocking one.  Tool names are canonicalized (NFKC,
   casefolded, invisible characters stripped) before matching, and a name
   that is not a plain identifier after canonicalization is blocked outright.
2. **Evidence.**  The decision is appended to a hash-chained audit log.  Each
   record commits to its predecessor's digest, so removing or editing any
   record invalidates every later entry.
3. **Alert.**  A warn or block decision raises an alert, so a live agent
   hitting a previously discovered failure mode is reported rather than
   silently re-discovered.

The gateway fails closed: an unknown rule ``action``/``kind`` or
``default_verdict`` is rejected when the config loads, a rule that raises
while evaluating blocks the call, any verdict other than ALLOW/WARN is treated
as a block, and an audit trail that fails verification on load refuses new
records (and therefore new calls) unless explicitly told otherwise.

What the audit chain does and does not prove
--------------------------------------------
*Without* ``audit_secret`` the chain is a plain SHA-256 chain.  It detects
accidental corruption and edits made by someone who does not recompute the
digests - but anyone who can write the file can rewrite a record and
recompute every later digest, and the result verifies.  It is tamper-evident
only against non-recomputing edits.  *With* a secret, each digest is an HMAC,
so rewriting requires the key.

Neither mode alone detects deletion of the *newest* records (truncation),
because a shorter chain is still internally consistent.  For that, export a
checkpoint (record count + head digest, HMAC'd when a secret is configured)
with :meth:`AuditTrail.checkpoint` - or set ``audit_checkpoint_path`` - and
keep it somewhere the log writer cannot modify; :meth:`AuditTrail.verify`
accepts it and reports any record missing past it.

Configuration is either programmatic or from a YAML file::

    gateway = PolicyGateway.from_config("lifeforge_policy.yaml")
    guarded = gateway.wrap_executor(original_executor)
"""
from __future__ import annotations

import copy
import functools
import hashlib
import hmac
import json
import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from lifeforge.hardening import (
    RECIPIENT_ARGUMENT_ALIASES,
    VIOLATION_GUARDS,
    GuardEvent,
    PolicyError,
    canonical_tool_name,
    coerce_amount,
    is_canonical_tool_name,
    iter_strings,
    normalize_text,
    recipient_value_allowed,
    register_audit_sink,
    unregister_audit_sink,
)

#: Genesis digest for a fresh audit chain.
GENESIS_DIGEST = "0" * 64

#: Verdicts the gateway can reach.
VERDICT_ALLOW = "ALLOW"
VERDICT_WARN = "WARN"
VERDICT_BLOCK = "BLOCK"
VERDICTS: tuple[str, ...] = (VERDICT_ALLOW, VERDICT_WARN, VERDICT_BLOCK)
_VERDICT_RANK = {VERDICT_ALLOW: 0, VERDICT_WARN: 1, VERDICT_BLOCK: 2}

#: Accepted rule actions and kinds.  Anything else is a configuration error.
RULE_ACTIONS: tuple[str, ...] = ("allow", "warn", "block")
RULE_KINDS: tuple[str, ...] = ("whitelist", "denylist", "amount", "recipient", "markers", "rate", "sequence")


class GatewayConfigError(ValueError):
    """Raised when a gateway configuration is invalid.

    The gateway refuses to start rather than run with a rule it cannot
    interpret: a misspelled ``action: deny`` that silently allows traffic is
    worse than a deployment that fails loudly.
    """


class AuditIntegrityError(RuntimeError):
    """Raised when appending to an audit trail that failed verification."""


def _normalize_action(action: Any) -> str:
    value = str(action).strip().lower()
    if value not in RULE_ACTIONS:
        raise GatewayConfigError(f"unknown rule action {str(action)!r}; expected one of {', '.join(RULE_ACTIONS)}")
    return value


def _normalize_kind(kind: Any) -> str:
    value = str(kind).strip().lower()
    if value not in RULE_KINDS:
        raise GatewayConfigError(f"unknown rule kind {str(kind)!r}; expected one of {', '.join(RULE_KINDS)}")
    return value


def _normalize_verdict(verdict: Any) -> str:
    value = str(verdict).strip().upper()
    if value not in VERDICTS:
        raise GatewayConfigError(f"unknown verdict {str(verdict)!r}; expected one of {', '.join(VERDICTS)}")
    return value


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
        ``"allow"``, ``"warn"``, or ``"block"``.  Anything else raises
        :class:`GatewayConfigError`.
    tools:
        Tool names the rule applies to.  ``None`` or empty means every tool.
        Matched after canonicalization.
    kind:
        Rule semantics: ``"whitelist"`` (tool must be listed), ``"denylist"``
        (tool must not be listed), ``"amount"`` (numeric argument must not
        exceed a cap), ``"recipient"`` (recipient must match the allow-list),
        ``"markers"`` (no argument, at any depth, may contain a payload
        marker), ``"rate"`` (call frequency cap), ``"sequence"`` (forbidden
        ordering of tool calls).
    config:
        Rule-specific parameters.
    severity:
        Severity recorded for the finding.
    enabled:
        Disabled rules are carried in the config for review but never
        evaluated.  Generated placeholder rules start disabled.
    """

    name: str
    violation_type: str
    action: str = "block"
    tools: tuple[str, ...] = ()
    kind: str = "whitelist"
    config: dict[str, Any] = field(default_factory=dict)
    severity: str = "HIGH"
    enabled: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _normalize_action(self.action))
        object.__setattr__(self, "kind", _normalize_kind(self.kind))
        object.__setattr__(self, "tools", tuple(str(tool) for tool in (self.tools or ())))
        if not isinstance(self.config, dict):
            raise GatewayConfigError(f"rule {self.name!r}: config must be a mapping")

    def applies_to(self, tool_name: str) -> bool:
        """Return True when this rule governs the named tool (canonical comparison)."""
        if not self.tools:
            return True
        canonical = canonical_tool_name(tool_name)
        return any(canonical_tool_name(tool) == canonical for tool in self.tools)

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
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GatewayRule:
        """Build a rule from a config mapping; raises GatewayConfigError when invalid."""
        if not isinstance(data, dict):
            raise GatewayConfigError(f"each rule must be a mapping, got {type(data).__name__}")
        tools = data.get("tools") or ()
        if isinstance(tools, str):
            tools = [tools]
        config = data.get("config") or {}
        if not isinstance(config, dict):
            raise GatewayConfigError(f"rule {data.get('name')!r}: config must be a mapping")
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise GatewayConfigError(f"rule {data.get('name')!r}: enabled must be true or false")
        return cls(
            name=str(data.get("name", "unnamed_rule")),
            violation_type=str(data.get("violation_type", "POLICY_VIOLATION")),
            action=data.get("action", "block"),
            tools=tuple(str(tool) for tool in tools),
            kind=data.get("kind", "whitelist"),
            config=dict(config),
            severity=str(data.get("severity", "HIGH")),
            enabled=enabled,
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

    Security properties (see the module docstring for detail):

    * Without ``secret`` the chain only detects edits that do not recompute
      the digests.  Configure a secret (``require_secret=True`` enforces it)
      for resistance against an attacker with write access to the file.
    * Truncation of the newest records is only detectable against a
      checkpoint kept elsewhere: pass ``checkpoint_path`` (refreshed on every
      append) or export :meth:`checkpoint` yourself and give it to
      :meth:`verify`.
    * An existing file is verified on load.  A line in the middle of the file
      that is not a valid record is treated as tampering.  A torn final line
      (a crash mid-write) is tolerated and removed before the next append.
      If verification fails, :meth:`append` raises
      :class:`AuditIntegrityError` unless ``allow_broken_chain=True``.
    """

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        secret: bytes | str | None = None,
        checkpoint_path: Path | str | None = None,
        allow_broken_chain: bool = False,
        require_secret: bool = False,
    ) -> None:
        self.path = Path(path) if path is not None else None
        self.secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        if require_secret and not self.secret:
            raise GatewayConfigError("an audit secret is required (require_secret=True) but none was configured")
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path is not None else None
        self.allow_broken_chain = bool(allow_broken_chain)
        self.integrity_error: str | None = None
        self._partial_tail = False
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()

        if self.path is not None and self.path.exists():
            self._load_existing()
        if self.integrity_error is None and self._records:
            ok, detail = self._verify_locked(None)
            if not ok:
                self.integrity_error = detail
        if self.integrity_error is None and self.checkpoint_path is not None and self.checkpoint_path.exists():
            try:
                checkpoint = self.load_checkpoint(self.checkpoint_path)
            except (OSError, ValueError) as exc:
                self.integrity_error = f"checkpoint file is unreadable: {exc}"
            else:
                ok, detail = self._verify_locked(checkpoint)
                if not ok:
                    self.integrity_error = detail

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

    @property
    def is_intact(self) -> bool:
        """False when the trail failed verification on load."""
        return self.integrity_error is None

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
        """Append one decision and return the sealed record.

        Raises
        ------
        AuditIntegrityError
            When the trail failed verification on load and
            ``allow_broken_chain`` is False.  Extending a broken chain would
            launder the break into an apparently continuous history.
        """
        with self._lock:
            if self.integrity_error is not None and not self.allow_broken_chain:
                raise AuditIntegrityError(
                    f"audit trail failed verification ({self.integrity_error}); refusing to append. "
                    "Investigate the log, or construct the trail with allow_broken_chain=True."
                )
            previous = self._records[-1].digest if self._records else GENESIS_DIGEST
            record = AuditRecord(
                index=len(self._records),
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool_name=str(tool_name),
                verdict=verdict,
                rule=rule,
                violation_type=violation_type,
                severity=severity,
                arguments_digest=digest_arguments(arguments or {}),
                reason=reason,
                previous_digest=previous,
            )
            record.digest = self._sign(record.compute_digest())
            if self.path is not None:
                self._persist(record)
            self._records.append(record)
            if self.checkpoint_path is not None:
                self._write_checkpoint_locked(self.checkpoint_path)
            return record

    def _sign(self, digest: str) -> str:
        """Key the digest when a secret is configured.

        Without a secret the chain detects accidental corruption and edits
        that do not recompute the digests.  With one it also resists an
        attacker who can write to the log file but does not hold the key.
        """
        if not self.secret:
            return digest
        return hmac.new(self.secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Verification and checkpoints
    # ------------------------------------------------------------------

    def verify(self, checkpoint: dict[str, Any] | None = None) -> tuple[bool, str]:
        """Recompute the chain and report whether it is intact.

        Returns ``(ok, detail)``.  On failure ``detail`` names the first broken
        record index and why, so an auditor can point at the exact entry that
        was tampered with.  When ``checkpoint`` (from :meth:`checkpoint`) is
        given, the trail must also still contain every record the checkpoint
        covered, ending in the same digest - which is what detects truncation.
        """
        with self._lock:
            return self._verify_locked(checkpoint)

    def _verify_locked(self, checkpoint: dict[str, Any] | None) -> tuple[bool, str]:
        if self.integrity_error is not None:
            # Failures found at load time (malformed lines, checkpoint
            # mismatch, broken chain) stay failures for the life of the trail.
            return False, self.integrity_error
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
        if checkpoint is not None:
            ok, detail = self._check_checkpoint(checkpoint)
            if not ok:
                return False, detail
            return True, f"chain intact: {len(self._records)} record(s) verified against checkpoint"
        return True, f"chain intact: {len(self._records)} record(s) verified"

    def _checkpoint_mac(self, count: int, head: str) -> str | None:
        if not self.secret:
            return None
        return hmac.new(self.secret, f"checkpoint:{count}:{head}".encode("utf-8"), hashlib.sha256).hexdigest()

    def _check_checkpoint(self, checkpoint: dict[str, Any]) -> tuple[bool, str]:
        try:
            count = int(checkpoint["count"])
            head = str(checkpoint["head_digest"])
        except (KeyError, TypeError, ValueError):
            return False, "checkpoint is malformed (needs 'count' and 'head_digest')"
        expected_mac = self._checkpoint_mac(count, head)
        if expected_mac is not None:
            mac = checkpoint.get("mac")
            if not isinstance(mac, str) or not hmac.compare_digest(mac, expected_mac):
                return False, "checkpoint signature does not verify (forged checkpoint or wrong secret)"
        if count > len(self._records):
            return False, (
                f"trail holds {len(self._records)} record(s) but the checkpoint covers {count}; "
                f"{count - len(self._records)} record(s) were removed (truncation)"
            )
        actual_head = self._records[count - 1].digest if count > 0 else GENESIS_DIGEST
        if not hmac.compare_digest(actual_head, head):
            return False, f"record {count - 1} does not match the checkpoint head digest (history rewritten)"
        return True, "checkpoint matches"

    def checkpoint(self) -> dict[str, Any]:
        """Return a checkpoint (record count + head digest) to store out of band."""
        with self._lock:
            return self._checkpoint_locked()

    def _checkpoint_locked(self) -> dict[str, Any]:
        count = len(self._records)
        head = self._records[-1].digest if self._records else GENESIS_DIGEST
        data: dict[str, Any] = {
            "count": count,
            "head_digest": head,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        mac = self._checkpoint_mac(count, head)
        if mac is not None:
            data["mac"] = mac
        return data

    def write_checkpoint(self, path: Path | str) -> Path:
        """Write the current checkpoint to ``path`` as JSON."""
        with self._lock:
            return self._write_checkpoint_locked(Path(path))

    def _write_checkpoint_locked(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(self._checkpoint_locked()), encoding="utf-8")
        temporary.replace(path)
        return path

    @staticmethod
    def load_checkpoint(path: Path | str) -> dict[str, Any]:
        """Read a checkpoint written by :meth:`write_checkpoint`."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("checkpoint must be a JSON object")
        return data

    def export(self) -> list[dict[str, Any]]:
        """Return the full trail as JSON-serializable dicts, digests included."""
        return [record.to_dict() for record in self.records]

    def summary(self) -> dict[str, Any]:
        """Aggregate counts by verdict and by violation type."""
        records = self.records
        by_verdict: dict[str, int] = {}
        by_violation: dict[str, int] = {}
        blocked_tools: dict[str, int] = {}
        for record in records:
            by_verdict[record.verdict] = by_verdict.get(record.verdict, 0) + 1
            if record.violation_type:
                by_violation[record.violation_type] = by_violation.get(record.violation_type, 0) + 1
            if record.verdict == VERDICT_BLOCK:
                blocked_tools[record.tool_name] = blocked_tools.get(record.tool_name, 0) + 1
        return {
            "total_records": len(records),
            "by_verdict": by_verdict,
            "by_violation_type": by_violation,
            "blocked_tools": blocked_tools,
            "head_digest": self.head_digest,
            "intact": self.integrity_error is None,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self, record: AuditRecord) -> None:
        """Append one record to the backing file as a JSON line."""
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._partial_tail:
            self._drop_partial_tail()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict()) + "\n")

    def _drop_partial_tail(self) -> None:
        """Remove a torn final line (crash mid-write) before appending after it."""
        assert self.path is not None
        data = self.path.read_bytes()
        cut = data.rfind(b"\n") + 1
        with self.path.open("r+b") as handle:
            handle.truncate(cut)
        self._partial_tail = False

    def _load_existing(self) -> None:
        """Rebuild in-memory state from a previously written trail file."""
        assert self.path is not None
        try:
            text = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            self.integrity_error = f"line 0: trail file is unreadable ({exc})"
            return
        lines = text.split("\n")
        ends_with_newline = text.endswith("\n")
        last_content = max((i for i, line in enumerate(lines) if line.strip()), default=-1)
        for number, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ValueError("record is not an object")
                record = AuditRecord(
                    index=int(data["index"]),
                    timestamp=str(data["timestamp"]),
                    tool_name=str(data["tool"]),
                    verdict=str(data["verdict"]),
                    rule=data.get("rule"),
                    violation_type=data.get("violation_type"),
                    severity=data.get("severity"),
                    arguments_digest=str(data["arguments_digest"]),
                    reason=str(data.get("reason", "")),
                    previous_digest=str(data["previous_digest"]),
                    digest=str(data["digest"]),
                )
            except (ValueError, KeyError, TypeError) as exc:
                if number == last_content and not ends_with_newline:
                    # A torn final line means the process died mid-write; the
                    # chain stays verifiable up to the last complete record.
                    self._partial_tail = True
                    continue
                self.integrity_error = (
                    f"line {number + 1} is not a valid audit record ({type(exc).__name__}); "
                    "a malformed line inside the trail is treated as tampering"
                )
                return
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


def _copy_arguments(arguments: Any) -> dict[str, Any]:
    """Deep-copy call arguments so the checked value is the executed value."""
    if arguments is None:
        return {}
    if not isinstance(arguments, dict):
        raise PolicyError(
            f"tool arguments must be a mapping, got {type(arguments).__name__}",
            policy="gateway",
        )
    try:
        return copy.deepcopy(arguments)
    except Exception:  # pragma: no cover - uncopyable objects fall back to shallow
        return dict(arguments)


class PolicyGateway:
    """Enforces invariant policies on live tool calls and audits every decision.

    Parameters
    ----------
    rules:
        Enforcement rules.  Every enabled rule is evaluated and the most severe
        verdict wins (block > warn > allow); ties go to the earliest rule.
    policies:
        Optional :class:`~lifeforge.sandbox.policies.Policy` instances applied to
        the accumulated call history.  These catch episode-level patterns
        (tool sequences, cascading failures) that no single call reveals.
    audit_path:
        When given, the audit trail is persisted there as JSON lines.
    audit_secret:
        Optional HMAC key for the audit chain.  Without it the chain is only
        tamper-evident against edits that do not recompute digests.
    audit_checkpoint_path:
        When given, a checkpoint (count + head digest) is rewritten there on
        every append and checked on load, which detects truncation.
    allow_broken_audit:
        Keep appending to a trail that failed verification on load.  Off by
        default: the gateway refuses calls instead.
    require_audit_secret:
        Refuse to start without ``audit_secret``.
    alert_sink:
        Callback invoked with each :class:`GatewayAlert`.
    default_verdict:
        Verdict for a call that no rule matches.  ``ALLOW`` by default, which is
        the correct posture for a monitor-first rollout.
    enforce_canonical_tool_names:
        Block tool names that are not plain identifiers after canonicalization
        (confusable hyphens, embedded whitespace, control characters).
    history_limit / alert_limit:
        Bounds on the in-memory call history and alert buffer.
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
        audit_checkpoint_path: Path | str | None = None,
        allow_broken_audit: bool = False,
        require_audit_secret: bool = False,
        enforce_canonical_tool_names: bool = True,
        history_limit: int = 10_000,
        alert_limit: int = 10_000,
    ) -> None:
        resolved_rules: list[GatewayRule] = []
        for rule in rules or []:
            if isinstance(rule, dict):
                rule = GatewayRule.from_dict(rule)
            if not isinstance(rule, GatewayRule):
                raise GatewayConfigError(f"rules must be GatewayRule instances, got {type(rule).__name__}")
            resolved_rules.append(rule)
        self.rules: list[GatewayRule] = resolved_rules
        self.policies: list[Any] = list(policies or [])
        self.default_verdict = _normalize_verdict(default_verdict)
        self.enforce_canonical_tool_names = bool(enforce_canonical_tool_names)
        self.audit = AuditTrail(
            audit_path,
            secret=audit_secret,
            checkpoint_path=audit_checkpoint_path,
            allow_broken_chain=allow_broken_audit,
            require_secret=require_audit_secret,
        )
        self.trail = self.audit  # readable alias
        self.alerts: deque[GatewayAlert] = deque(maxlen=max(1, int(alert_limit)))
        self.alert_sink = alert_sink
        self.archive = archive

        self.call_history: deque[tuple[str, dict[str, Any]]] = deque(maxlen=max(1, int(history_limit)))
        self._rate_state: dict[str, list[float]] = {}
        self._lock = threading.Lock()

        # Hardening guards installed anywhere in the process report their
        # decisions into the same trail, so one artifact covers both.  The
        # sink holds only a weak reference, so a gateway that is dropped
        # without close() is collected and its sink removes itself.
        self_ref = weakref.ref(self)

        def _guard_sink(event: GuardEvent) -> None:
            gateway = self_ref()
            if gateway is None:
                unregister_audit_sink(_guard_sink)
                return
            gateway._on_guard_event(event)

        self._guard_sink = _guard_sink
        register_audit_sink(_guard_sink)

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
        ``audit_secret``, ``audit_checkpoint_path``, ``allow_broken_audit``,
        ``require_audit_secret``, ``default_verdict``.  Any invalid entry raises
        :class:`GatewayConfigError`.
        """
        if isinstance(config, (str, Path)):
            data = load_gateway_config(Path(config))
        elif isinstance(config, dict):
            data = dict(config)
        else:
            raise GatewayConfigError(f"gateway config must be a mapping or a path, got {type(config).__name__}")

        raw_rules = data.get("rules") or []
        if not isinstance(raw_rules, list):
            raise GatewayConfigError("'rules' must be a list")
        rules = [GatewayRule.from_dict(entry) for entry in raw_rules]
        raw_policies = data.get("policies") or []
        if not isinstance(raw_policies, list):
            raise GatewayConfigError("'policies' must be a list")
        policies = _build_policies(raw_policies)

        return cls(
            rules,
            policies=policies,
            audit_path=data.get("audit_path"),
            audit_secret=data.get("audit_secret"),
            audit_checkpoint_path=data.get("audit_checkpoint_path"),
            allow_broken_audit=bool(data.get("allow_broken_audit", False)),
            require_audit_secret=bool(data.get("require_audit_secret", False)),
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
        """Decide one call: return ``(verdict, rule, reason)``.

        Every enabled rule that applies is evaluated; the most severe verdict
        wins, ties going to the earliest rule.  A rule that raises blocks.
        """
        if self.enforce_canonical_tool_names and not is_canonical_tool_name(tool_name):
            return VERDICT_BLOCK, None, (
                f"tool name {str(tool_name)[:80]!r} is not a canonical identifier "
                "(confusable, invisible, or whitespace characters)"
            )
        canonical = canonical_tool_name(tool_name)
        best: tuple[int, str, GatewayRule | None, str] | None = None
        for rule in self.rules:
            if not rule.enabled or not rule.applies_to(canonical):
                continue
            try:
                triggered, reason = self._rule_blocks(rule, canonical, arguments)
                verdict = rule.action.upper()
            except Exception as exc:  # fail closed on a rule that cannot decide
                triggered = True
                verdict = VERDICT_BLOCK
                reason = f"rule '{rule.name}' failed to evaluate ({type(exc).__name__}: {exc}); failing closed"
            if not triggered:
                continue
            rank = _VERDICT_RANK.get(verdict, _VERDICT_RANK[VERDICT_BLOCK])
            if best is None or rank > best[0]:
                best = (rank, verdict, rule, reason)
        if best is None:
            return self.default_verdict, None, "no rule matched"
        return best[1], best[2], best[3]

    def check(self, tool_name: str, arguments: dict[str, Any] | None = None) -> tuple[str, GatewayRule | None, str]:
        """Evaluate, audit, and alert on a call without executing it.

        Use this when the executor lives in another process: call ``check`` from
        the proxy, then forward the call only when the verdict is ALLOW or WARN.
        """
        arguments = dict(arguments or {})
        verdict, rule, reason = self.evaluate(tool_name, arguments)
        if verdict not in (VERDICT_ALLOW, VERDICT_WARN):
            verdict = VERDICT_BLOCK

        record = self.audit.append(
            tool_name=tool_name,
            verdict=verdict,
            arguments=arguments,
            rule=rule.name if rule else None,
            violation_type=rule.violation_type if rule else None,
            severity=rule.severity if rule else None,
            reason=reason,
        )

        if verdict in (VERDICT_BLOCK, VERDICT_WARN):
            self._raise_alert(tool_name, rule, reason, record)

        with self._lock:
            self.call_history.append((canonical_tool_name(tool_name), arguments))
        return verdict, rule, reason

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        executor: Callable[[str, dict[str, Any]], Any],
    ) -> Any:
        """Check a call, then run it through ``executor`` when permitted.

        The executor receives a deep copy of exactly the arguments that were
        checked, so a caller cannot mutate a nested value between the check
        and the call.

        Raises
        ------
        PolicyError
            When the verdict is anything other than ALLOW or WARN.  The
            executor is never invoked.
        """
        checked = _copy_arguments(arguments)
        verdict, rule, reason = self.check(tool_name, checked)
        if verdict not in (VERDICT_ALLOW, VERDICT_WARN):
            raise PolicyError(
                f"Gateway blocked '{tool_name}': {reason}",
                tool_name=tool_name,
                policy=rule.name if rule else "gateway",
                details={
                    "violation_type": rule.violation_type if rule else None,
                    "severity": rule.severity if rule else None,
                },
            )
        return executor(tool_name, checked)

    def evaluate_history(self) -> list[Any]:
        """Run the configured policy objects over the accumulated call history.

        Single-call rules catch per-call violations; the episode-level policies
        catch patterns that only exist across a sequence of calls (reconnaissance
        sweeps, forbidden tool chains).  Returns the violations the policies
        found, in policy order.
        """
        with self._lock:
            history = list(self.call_history)
        if not self.policies or not history:
            return []

        from lifeforge.sandbox.oracle import PolicyContext
        from lifeforge.sandbox.world_state import WorldState

        # The gateway does not own a world; policies only read the trace.
        empty_world = WorldState()
        trace: list[dict[str, Any]] = []
        for index, (tool_name, arguments) in enumerate(history):
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
            return self.execute(tool_name, arguments or {}, executor)

        guarded_executor.__name__ = getattr(executor, "__name__", "executor")
        guarded_executor.__doc__ = (
            f"LIFE FORGE-guarded wrapper around {getattr(executor, '__name__', 'executor')}."
        )
        return guarded_executor

    def enforce(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator form for HTTP-style executors taking a JSON body.

        The wrapped function must accept a single ``payload`` argument shaped as
        ``{"tool_name": str, "arguments": dict}`` (``name`` / ``args`` are
        accepted aliases).  A payload whose aliases disagree - ``tool_name``
        naming one tool and ``name`` another - is refused, and the handler
        receives a normalized copy in which every name/argument field holds
        exactly the values that were checked.
        """

        def _refuse(tool: str, reason: str) -> dict[str, Any]:
            self.audit.append(tool_name=tool, verdict=VERDICT_BLOCK, rule="gateway", reason=reason)
            return {"success": False, "error": f"PolicyError: {reason}", "policy": "gateway", "violation_type": None}

        @functools.wraps(func)
        def wrapper(payload: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            if not isinstance(payload, dict):
                return _refuse("unknown_tool", "payload must be a JSON object")
            names = {key: payload[key] for key in ("tool_name", "name") if payload.get(key) not in (None, "")}
            if not names:
                return _refuse("unknown_tool", "payload names no tool")
            distinct_names = {str(value) for value in names.values()}
            if len(distinct_names) > 1:
                return _refuse(
                    str(names.get("tool_name", "unknown_tool")),
                    f"payload names conflicting tools {sorted(distinct_names)}",
                )
            tool_name = distinct_names.pop()
            argument_fields = {key: payload[key] for key in ("arguments", "args") if payload.get(key) is not None}
            values = list(argument_fields.values())
            if len(values) > 1 and values[0] != values[1]:
                return _refuse(tool_name, "payload carries conflicting 'arguments' and 'args'")
            raw_arguments = values[0] if values else {}
            if not isinstance(raw_arguments, dict):
                return _refuse(tool_name, "payload arguments must be a JSON object")
            checked = _copy_arguments(raw_arguments)
            verdict, rule, reason = self.check(tool_name, checked)
            if verdict not in (VERDICT_ALLOW, VERDICT_WARN):
                return {
                    "success": False,
                    "error": f"PolicyError: {reason}",
                    "policy": rule.name if rule else "gateway",
                    "violation_type": rule.violation_type if rule else None,
                }
            normalized = dict(payload)
            for key in names:
                normalized[key] = tool_name
            if argument_fields:
                for key in argument_fields:
                    normalized[key] = checked
            else:
                normalized["arguments"] = checked
            return func(normalized, *args, **kwargs)

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
        """Return whether a rule triggers, with its reason.

        ``tool_name`` is already canonical.  Rules whose configuration leaves
        them unable to fire are reported as triggering, because a rule that
        never fires reads as protection in a review and provides none.
        """
        config = rule.config
        kind = rule.kind

        if kind == "whitelist":
            allowed = {canonical_tool_name(item) for item in config.get("allowed_tools", []) or []}
            if not allowed:
                return True, (
                    f"rule '{rule.name}' has an empty allowed_tools list and cannot be "
                    "evaluated; populate it or remove the rule"
                )
            if tool_name not in allowed:
                return True, f"tool '{tool_name}' is not in the authorized allow-list"
            return False, ""

        if kind == "denylist":
            denied = {canonical_tool_name(item) for item in config.get("denied_tools", []) or []}
            if not denied:
                return True, (
                    f"rule '{rule.name}' has an empty denied_tools list and cannot be "
                    "evaluated; populate it, disable it, or remove the rule"
                )
            if tool_name in denied:
                return True, f"tool '{tool_name}' is on the prohibited list"
            return False, ""

        if kind == "amount":
            argument = str(config.get("argument", "amount"))
            cap, cap_error = coerce_amount(config.get("max_amount", 0.0))
            if cap is None:
                return True, f"rule '{rule.name}' has an invalid max_amount ({cap_error})"
            raw = arguments.get(argument)
            amount, error = coerce_amount(raw)
            if error is not None:
                return True, f"{argument} could not be validated: {error}"
            if amount is None:
                return False, ""
            if amount < 0 and not config.get("allow_negative", False):
                return True, f"{argument}={amount:,.2f} is negative"
            if amount > cap:
                approval = config.get("approved_token_argument")
                tokens = config.get("approval_tokens")
                if approval and tokens:
                    token = arguments.get(str(approval))
                    if isinstance(token, str) and any(
                        hmac.compare_digest(token, str(candidate)) for candidate in tokens
                    ):
                        return False, ""
                return True, f"{argument}={amount:,.2f} exceeds the authorized cap of {cap:,.2f}"
            return False, ""

        if kind == "recipient":
            argument = str(config.get("argument", "recipient"))
            allowed = list(config.get("allowed_recipients", []) or [])
            domains = list(config.get("allowed_domains", []) or [])
            if not allowed and not domains:
                return True, f"rule '{rule.name}' has no allowed_recipients or allowed_domains"
            candidates = [argument, *config.get("recipient_arguments", RECIPIENT_ARGUMENT_ALIASES)]
            present = False
            for name in dict.fromkeys(str(candidate) for candidate in candidates):
                value = arguments.get(name)
                if value is None:
                    continue
                present = True
                if not recipient_value_allowed(value, allowed, domains):
                    return True, f"recipient {str(value)[:120]!r} is not on the egress allow-list"
            if not present and rule.tools:
                return True, f"tool '{tool_name}' is governed by an egress rule but names no recipient"
            return False, ""

        if kind == "markers":
            markers = [str(marker) for marker in config.get("markers", []) or [] if str(marker).strip()]
            if not markers:
                return True, f"rule '{rule.name}' has no markers configured"
            needles = [(marker, normalize_text(marker)) for marker in markers]
            for key, value in arguments.items():
                for path, text in iter_strings(value):
                    haystack = normalize_text(text)
                    for marker, needle in needles:
                        if needle in haystack:
                            return True, f"argument '{key}{path}' carries payload marker {marker}"
            return False, ""

        if kind == "rate":
            max_calls = int(config.get("max_calls", 5))
            window = float(config.get("window_seconds", 60.0))
            # The identical-call cap alone is evaded by varying a junk
            # argument, so a tool-wide cap always applies as well.
            max_tool_calls = int(config.get("max_tool_calls", max_calls * 4))
            signature = _rate_signature(tool_name, arguments, config.get("signature_arguments", "all"))
            tool_key = f"{rule.name}\x00tool:{tool_name}"
            signature_key = f"{rule.name}\x00{signature}"
            now = time.monotonic()
            with self._lock:
                for key in list(self._rate_state):
                    kept = [stamp for stamp in self._rate_state[key] if now - stamp < window]
                    if kept:
                        self._rate_state[key] = kept
                    else:
                        del self._rate_state[key]
                history = self._rate_state.get(signature_key, [])
                tool_history = self._rate_state.get(tool_key, [])
                if len(history) >= max_calls:
                    return True, (
                        f"identical call to '{tool_name}' repeated {len(history)} times "
                        f"within {window:.0f}s (limit {max_calls})"
                    )
                if len(tool_history) >= max_tool_calls:
                    return True, (
                        f"'{tool_name}' called {len(tool_history)} times within {window:.0f}s "
                        f"(tool-wide limit {max_tool_calls})"
                    )
                self._rate_state[signature_key] = history + [now]
                self._rate_state[tool_key] = tool_history + [now]
            return False, ""

        if kind == "sequence":
            sequence = [str(item) for item in config.get("forbidden_sequence", []) or []]
            if len(sequence) < 2:
                return True, f"rule '{rule.name}' needs a forbidden_sequence of at least two tools"
            target = canonical_tool_name(sequence[-1].split(":")[0])
            if tool_name != target:
                return False, ""
            prefix = [canonical_tool_name(entry.split(":")[0]) for entry in sequence[:-1]]
            window = int(config.get("window", 50))
            with self._lock:
                names = [name for name, _ in self.call_history]
            if window > 0:
                names = names[-window:]
            position = 0
            for name in names:
                if position < len(prefix) and name == prefix[position]:
                    position += 1
            if position == len(prefix):
                return True, f"call completes the forbidden sequence {sequence}"
            return False, ""

        raise GatewayConfigError(f"unknown rule kind {kind!r}")  # pragma: no cover - validated at load

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def _raise_alert(self, tool_name: str, rule: GatewayRule | None, reason: str, record: AuditRecord) -> None:
        """Record and dispatch an alert for a warn or block decision."""
        violation_type = rule.violation_type if rule else "GATEWAY_REFUSAL"
        alert = GatewayAlert(
            timestamp=record.timestamp,
            tool_name=tool_name,
            violation_type=violation_type,
            severity=rule.severity if rule else "HIGH",
            message=reason,
            signature=f"{tool_name}:{violation_type}",
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
        unregister_audit_sink(self._guard_sink)

    def __enter__(self) -> PolicyGateway:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


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
    An unknown name or invalid configuration raises :class:`GatewayConfigError`:
    a gateway that silently drops a policy reads as protected in a review and
    is not.
    """
    from lifeforge.sandbox.policies import build_policy

    policies: list[Any] = []
    for index, entry in enumerate(entries):
        if isinstance(entry, str):
            name, config = entry, {}
        elif isinstance(entry, dict):
            name = str(entry.get("name", ""))
            config = entry.get("config") or {}
            if not isinstance(config, dict):
                raise GatewayConfigError(f"policies[{index}]: config must be a mapping")
        else:
            raise GatewayConfigError(f"policies[{index}]: expected a name or a mapping")
        if not name:
            raise GatewayConfigError(f"policies[{index}]: missing policy name")
        try:
            policies.append(build_policy(name, **dict(config)))
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayConfigError(f"policies[{index}]: cannot build policy {name!r}: {exc}") from exc
    return policies


def load_gateway_config(path: Path | str) -> dict[str, Any]:
    """Load a gateway config from YAML or JSON (YAML via ``safe_load``)."""
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
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise GatewayConfigError(f"gateway config {config_path} must contain a mapping at the top level")
    return data


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
    extracted into the rule's configuration (in the order they were observed)
    so the rule actually fires.  A rule whose configuration cannot be derived
    - an allow-list the operator must supply, a deny-list or sequence with no
    tool evidence - is still emitted for review but **disabled**, with a TODO
    note, so it can neither block every call nor read as active protection.
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
        tools = list(tools_by_category.get(category, []))
        markers = list((VIOLATION_GUARDS.get(category, {}).get("kwargs", {}) or {}).get("markers", []) or [])

        config: dict[str, Any]
        enabled = True
        rule_tools: tuple[str, ...] = tuple(tools)
        if kind == "denylist" and tools:
            config = {"denied_tools": sorted(tools)}
            rule_tools = ()
        elif kind == "amount":
            config = {"argument": "amount", "max_amount": 0.0}
        elif kind == "recipient":
            config = {"argument": "recipient", "allowed_recipients": ["internal"]}
        elif kind == "rate":
            config = {"max_calls": 3, "window_seconds": 60.0}
        elif kind == "sequence" and len(tools) >= 2:
            config = {"forbidden_sequence": tools}
            rule_tools = ()
        elif kind == "markers" and markers:
            config = {"markers": markers}
        else:
            # The operator has to supply the real list for this rule.
            enabled = False
            rule_tools = ()
            if kind == "denylist":
                config = {"denied_tools": [], "note": "TODO: populate denied_tools, then enable this rule"}
            elif kind == "sequence":
                config = {"forbidden_sequence": tools, "note": "TODO: populate forbidden_sequence, then enable this rule"}
            elif kind == "markers":
                config = {"markers": [], "note": "TODO: populate markers, then enable this rule"}
            else:
                kind = "whitelist"
                config = {"allowed_tools": [], "note": "TODO: populate allowed_tools for this agent, then enable this rule"}

        rules.append(
            GatewayRule(
                name=f"discovered_{category.lower()}",
                violation_type=category,
                action=action,
                tools=rule_tools,
                kind=kind,
                config=config,
                severity=severity,
                enabled=enabled,
            )
        )
    return rules


def _tools_by_category(report: dict[str, Any]) -> dict[str, list[str]]:
    """Collect the tools named in a report's findings, grouped by category.

    Tools are kept in first-observed order (sequence rules depend on it).
    Names are taken from agent traces and are therefore untrusted: anything
    that is not a canonical tool identifier is dropped.
    """
    collected: dict[str, list[str]] = {}
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
            if not isinstance(tool, str) or not tool or tool == "None" or not is_canonical_tool_name(tool):
                continue
            bucket = collected.setdefault(category, [])
            if tool not in bucket:
                bucket.append(tool)
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
