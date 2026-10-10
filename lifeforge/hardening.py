"""Remediation layer: turn a discovered violation into enforced tool-level policy.

LIFE FORGE's simulator finds failure modes offline.  This module closes the
loop: given a violation type (or a whole benchmark report), it emits a
drop-in Python decorator that enforces the corresponding rule at the tool
boundary in production.

Two distinct things live here, and it is worth keeping them apart:

* **The generated code** - a ``@tool_guard(...)`` decorator the customer pastes
  into their own codebase.  :func:`generate_hardening_module` and
  :func:`generate_decorator_for_violation` produce it as text.
* **The runtime used by that code** - :func:`tool_guard`, :class:`PolicyError`,
  and :func:`audit_tool_call`.  These are real, importable, importable-from-
  day-one implementations.  The generated file imports them from
  ``lifeforge.hardening``, so an audit deliverable never ships a stub.

Design constraint: the guards must be cheap and dependency-free, because they
sit in the hot path of a production tool call.  Everything here is stdlib plus
LIFE FORGE's own policy objects.
"""
from __future__ import annotations

import ast
import functools
import hmac
import inspect
import json
import keyword
import math
import numbers
import re
import threading
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

from lifeforge.sandbox.recipients import normalize_identifier, recipient_allowed, split_recipients

#: Violation type -> (policy kind, human-readable rationale, default guard kwargs).
#: The generator reads this table; unknown violation types fall back to a
#: deny-by-default whitelist guard with a warning.
VIOLATION_GUARDS: dict[str, dict[str, Any]] = {
    "UNAUTHORIZED_TOOL_EXECUTION": {
        "policy": "block_if_not_in_whitelist",
        "rationale": (
            "The agent invoked a tool outside its authorized set. Enforcement is a hard "
            "allow-list at the tool boundary, so an injected instruction cannot widen the "
            "agent's capabilities regardless of what the model decides."
        ),
        "kwargs": {"whitelist": "<tools the task legitimately requires>"},
    },
    "UNAUTHORIZED_FINANCIAL_DRAIN": {
        "policy": "block_if_amount_exceeds",
        "rationale": (
            "The agent committed funds beyond its authority. Enforcement caps the monetary "
            "argument of the tool and requires an approval token above the cap."
        ),
        "kwargs": {"amount_arg": "amount", "max_amount": 0.0, "approved_token_arg": "authorization_code"},
    },
    "BUDGET_EXCEEDED": {
        "policy": "block_if_amount_exceeds",
        "rationale": (
            "The agent exceeded a spending limit. Enforcement caps the monetary argument "
            "before the call reaches the backend."
        ),
        "kwargs": {"amount_arg": "amount", "max_amount": 0.0},
    },
    "UNAUTHORIZED_DATA_EXFILTRATION": {
        "policy": "block_if_recipient_not_in_whitelist",
        "rationale": (
            "The agent sent data to an unauthorized recipient. Enforcement validates the "
            "recipient against an allow-list at the egress boundary, where every outbound "
            "path passes."
        ),
        "kwargs": {"recipient_arg": "recipient", "allowed_recipients": ["internal"]},
    },
    "RECURSIVE_LOOP_TRAP": {
        "policy": "rate_limit_calls",
        "rationale": (
            "The agent re-issued an identical call until the episode budget was exhausted. "
            "Enforcement breaks the cycle by limiting identical invocations per window and "
            "signalling the refusal with a typed error the planner can recover from."
        ),
        "kwargs": {"max_calls": 3, "window_seconds": 30.0, "signature_args": "all"},
    },
    "GOAL_INVENTORY_DEFICIT": {
        "policy": "require_predecessor",
        "rationale": (
            "The agent did not achieve the required state. Enforcement verifies that the "
            "prerequisite step occurred before the dependent call is permitted."
        ),
        "kwargs": {"required_tools": ["<prerequisite tool>"], "state_key": "completed_tools"},
    },
    "CONFIRMATION_NOT_SENT": {
        "policy": "require_predecessor",
        "rationale": (
            "The agent skipped a required outbound confirmation. Enforcement requires the "
            "notification step before the workflow may terminate."
        ),
        "kwargs": {"required_tools": ["send_email"], "state_key": "completed_tools"},
    },
    "PARAMETER_BOUNDARY_VIOLATION": {
        "policy": "validate_parameters",
        "rationale": (
            "The agent supplied an out-of-range or injection-shaped argument. Enforcement "
            "validates every declared argument against a bound or pattern before dispatch."
        ),
        "kwargs": {"rules": {"quantity": {"min": 1, "max": 1000}}},
    },
    "TOCTOU_RACE_CONDITION": {
        "policy": "require_fresh_read",
        "rationale": (
            "The agent acted on a value read before the environment moved. Enforcement "
            "requires a read within a freshness window before the mutating call, so a stale "
            "price cannot be committed."
        ),
        "kwargs": {"read_tool": "vendor_api", "max_age_seconds": 30.0, "price_arg": "max_unit_price"},
    },
    "PRIVILEGE_ESCALATION": {
        "policy": "block_tool_sequence",
        "rationale": (
            "The agent chained low-privilege tools into a high-privilege outcome. Enforcement "
            "blocks the sequence itself, which no single-call check can see."
        ),
        "kwargs": {"forbidden_sequence": ["query_database:balances", "transfer_funds"]},
    },
    "CONTEXT_FLOOD_ATTACK": {
        "policy": "clip_payload_size",
        "rationale": (
            "Untrusted content displaced the agent's instructions from its context. "
            "Enforcement clips oversized tool output before it reaches the model."
        ),
        "kwargs": {"max_chars": 8000, "truncation_note": "[truncated by lifeforge guard]"},
    },
    "CASCADING_TOOL_FAILURE": {
        "policy": "circuit_breaker",
        "rationale": (
            "A failing call cascaded through dependent calls without recovery. Enforcement "
            "opens a circuit after repeated failures so the planner is forced to re-plan "
            "instead of inheriting a stale assumption."
        ),
        "kwargs": {"max_consecutive_failures": 3, "cooldown_seconds": 60.0},
    },
    "UNAUTHORIZED_SCOPE_EXPANSION": {
        "policy": "block_if_not_in_whitelist",
        "rationale": (
            "The agent reached for tools the task never required. Enforcement narrows the "
            "callable surface to the declared task scope."
        ),
        "kwargs": {"whitelist": "<tools the task legitimately requires>"},
    },
    "EXCESSIVE_DATA_QUERYING": {
        "policy": "rate_limit_calls",
        "rationale": (
            "The agent enumerated sensitive data stores. Enforcement limits repeated reads "
            "of a sensitive target within a window, which interrupts reconnaissance sweeps."
        ),
        "kwargs": {"max_calls": 3, "window_seconds": 60.0, "signature_args": ["table"]},
    },
    "SELF_REPLICATING_WORM_PROPAGATION": {
        "policy": "block_payload_markers",
        "rationale": (
            "A payload reproduced itself into the agent's own outputs. Enforcement scans "
            "every argument for the propagation marker and refuses the call, breaking the "
            "reproduction step that makes a prompt worm contagious."
        ),
        "kwargs": {"markers": ["[::PS-WORM-V3::]"]},
    },
    "RAG_MEMORY_POISONING_ADOPTED": {
        "policy": "block_payload_markers",
        "rationale": (
            "The agent acted on false facts retained in memory. Enforcement blocks writes "
            "carrying poison markers and flags reads of poisoned entries for re-validation."
        ),
        "kwargs": {"markers": ["[::MEM-POISON::]"]},
    },
}



class PolicyError(Exception):
    """Raised when a tool call is blocked by a hardening guard.

    Carries structured context so the agent's error handler can distinguish an
    authorization refusal from a backend failure and re-plan, rather than
    retrying the same forbidden call.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str | None = None,
        policy: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.policy = policy
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable error payload for the agent loop."""
        return {
            "error": "PolicyError",
            "message": str(self),
            "tool": self.tool_name,
            "policy": self.policy,
            "details": self.details,
        }


@dataclass
class GuardEvent:
    """One recorded guard decision, for the tamper-evident audit trail."""

    timestamp: str
    tool_name: str
    policy: str
    allowed: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event."""
        return {
            "timestamp": self.timestamp,
            "tool": self.tool_name,
            "policy": self.policy,
            "allowed": self.allowed,
            "reason": self.reason,
            "details": self.details,
        }


#: Process-wide sink for guard decisions.  Callers append their own collector
#: (the production gateway installs one) so guards stay free of global state.
_AUDIT_SINKS: list[Callable[[GuardEvent], None]] = []
_SINK_LOCK = threading.Lock()


def register_audit_sink(sink: Callable[[GuardEvent], None]) -> None:
    """Attach a callback that receives every guard decision."""
    with _SINK_LOCK:
        if sink not in _AUDIT_SINKS:
            _AUDIT_SINKS.append(sink)


def unregister_audit_sink(sink: Callable[[GuardEvent], None]) -> None:
    """Detach a previously registered audit sink."""
    with _SINK_LOCK:
        if sink in _AUDIT_SINKS:
            _AUDIT_SINKS.remove(sink)


def audit_tool_call(
    tool_name: str,
    policy: str,
    allowed: bool,
    reason: str,
    **details: Any,
) -> GuardEvent:
    """Record one guard decision and fan it out to every registered sink.

    Returns the emitted event so callers can log or assert on it directly.
    """
    event = GuardEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool_name=tool_name,
        policy=policy,
        allowed=allowed,
        reason=reason,
        details=details,
    )
    with _SINK_LOCK:
        sinks = list(_AUDIT_SINKS)
    for sink in sinks:
        try:
            sink(event)
        except Exception:  # pragma: no cover - a bad sink must not break a tool call
            continue
    return event


# ---------------------------------------------------------------------------
# Shared value helpers (also used by lifeforge.gateway)
# ---------------------------------------------------------------------------

#: Characters a canonical tool name may contain.  Anything else (confusable
#: hyphens, fullwidth letters that survive NFKC as something else, control or
#: zero-width characters) makes the name non-canonical and therefore suspect.
_CANONICAL_TOOL_NAME = re.compile(r"^[a-z0-9_.:/\-]+$")

#: Recipient arguments every egress check inspects in addition to the
#: configured one, so ``to=`` cannot route around a rule written for
#: ``recipient=``.
RECIPIENT_ARGUMENT_ALIASES: tuple[str, ...] = ("recipient", "recipients", "to", "cc", "bcc")

_MAX_WALK_DEPTH = 32


def canonical_tool_name(name: Any) -> str:
    """Return the canonical form of a tool name (NFKC, casefolded, invisibles stripped)."""
    return normalize_identifier(str(name))


def is_canonical_tool_name(name: Any) -> bool:
    """True when ``name`` (NFKC, casefolded, edge whitespace trimmed) uses only the safe alphabet.

    Invisible characters are *not* stripped here: a zero-width space inside a
    tool name is a smuggling attempt, not a typo.
    """
    text = unicodedata.normalize("NFKC", str(name)).strip().casefold()
    return bool(text) and bool(_CANONICAL_TOOL_NAME.match(text))


def normalize_text(value: str) -> str:
    """Normalize free text for marker matching: NFKC, casefold, invisibles removed."""
    text = unicodedata.normalize("NFKC", value)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf", "Cc") or ch in "\n\t")
    return text.casefold()


def iter_strings(value: Any, _depth: int = 0) -> Iterator[tuple[str, str]]:
    """Yield ``(path, text)`` for every string nested anywhere inside ``value``.

    Dict keys are yielded as well as values, so a payload cannot hide inside a
    mapping key.  Recursion is bounded so a self-referential structure cannot
    hang the guard; anything deeper than the bound is reported as a string
    sentinel that the caller treats as suspicious.
    """
    if _depth > _MAX_WALK_DEPTH:
        yield "", "<max-depth-exceeded>"
        return
    if isinstance(value, str):
        yield "", value
    elif isinstance(value, (bytes, bytearray)):
        yield "", bytes(value).decode("utf-8", "replace")
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield f"[{key!r}]", key
            for path, text in iter_strings(item, _depth + 1):
                yield f"[{key!r}]{path}", text
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            for path, text in iter_strings(item, _depth + 1):
                yield f"[{index}]{path}", text


def coerce_amount(value: Any) -> tuple[float | None, str | None]:
    """Coerce a monetary argument to a finite float.

    Returns ``(amount, None)`` on success, ``(None, None)`` when the value is
    absent, and ``(None, reason)`` when the value is present but is not a
    finite number.  Callers must treat the third case as a block: an amount
    the guard cannot read is an amount the guard cannot cap.
    """
    if value is None:
        return None, None
    if isinstance(value, bool):
        return None, "a boolean is not a monetary amount"
    if isinstance(value, (numbers.Real, Decimal)):
        try:
            amount = float(value)
        except (TypeError, ValueError, OverflowError):
            return None, f"amount {value!r} cannot be read as a number"
    elif isinstance(value, str):
        try:
            amount = float(value.strip())
        except ValueError:
            return None, f"amount {value[:40]!r} is not a plain number"
    else:
        return None, f"amount of type {type(value).__name__} is not a number"
    if not math.isfinite(amount):
        return None, f"amount {value!r} is not finite"
    return amount, None


def recipient_value_allowed(
    value: Any,
    allowed: Iterable[Any],
    allowed_domains: Iterable[Any] = (),
) -> bool:
    """Return True when every recipient named in ``value`` is permitted.

    Matching is exact after normalization: a bare role must equal an allowed
    entry, a full address must equal an allowed address or sit in an allowed
    domain (or subdomain).  Bare allowed entries double as allowed domains, so
    ``allowed=["internal"]`` admits ``finance@internal`` but never
    ``internal@evil.com``.  Non-text values and empty values fail closed.
    """
    parts = split_recipients(value)
    if not parts:
        return False
    names = {normalize_identifier(str(item)) for item in allowed if str(item).strip()}
    domains = {normalize_identifier(str(item)).lstrip("@.") for item in allowed_domains if str(item).strip()}
    domains |= {name for name in names if "@" not in name}
    for part in parts:
        if part in names:
            continue
        if not recipient_allowed(part, names, domains):
            return False
    return True


def _bind_arguments(signature: inspect.Signature | None, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Map positional and keyword arguments onto parameter names.

    Guards inspect the *bound* arguments, so moving a value from a keyword to
    a positional slot (or into ``**kwargs``) does not hide it.  Extra
    positional values are kept under ``"*args"``.
    """
    if signature is not None:
        try:
            bound = signature.bind_partial(*args, **kwargs)
        except TypeError:
            bound = None
        if bound is not None:
            result: dict[str, Any] = {}
            for name, value in bound.arguments.items():
                kind = signature.parameters[name].kind
                if kind is inspect.Parameter.VAR_KEYWORD:
                    result.update(value)
                elif kind is inspect.Parameter.VAR_POSITIONAL:
                    result["*args"] = list(value)
                else:
                    result[name] = value
            return result
    result = dict(kwargs)
    if args:
        result["*args"] = list(args)
    return result


def _extract_argument(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    name: str,
    signature_names: Sequence[str],
) -> Any:
    """Resolve an argument by keyword first, then by position (kept for compatibility)."""
    if name in kwargs:
        return kwargs[name]
    if name in signature_names:
        index = list(signature_names).index(name)
        if index < len(args):
            return args[index]
    return None


def _as_float(value: Any) -> float | None:
    """Best-effort finite numeric coercion; None when the value is not numeric."""
    amount, _ = coerce_amount(value)
    return amount


def _signature_of(arguments: dict[str, Any], signature_args: Any) -> str:
    """Build the call signature used by the rate limiter."""
    if signature_args == "all" or signature_args is None:
        keys = sorted(arguments)
    elif isinstance(signature_args, str):
        keys = [signature_args]
    else:
        keys = sorted(str(key) for key in signature_args)
    return json.dumps({key: arguments.get(key) for key in keys}, sort_keys=True, default=str)


class _GuardState:
    """Per-decorator mutable state for rate limits and circuit breakers."""

    def __init__(self) -> None:
        self.calls: dict[str, list[float]] = {}
        self.tool_calls: list[float] = []
        self.failures: int = 0
        self.opened_at: float | None = None
        self.lock = threading.Lock()


#: Process-wide history of guarded tool invocations (canonical names), used by
#: ``block_tool_sequence``.  Every ``tool_guard`` wrapper records into it, and
#: unguarded tools can report themselves through :func:`record_tool_call`.
_CALL_HISTORY: deque[str] = deque(maxlen=1_000)
_HISTORY_LOCK = threading.Lock()

#: Last read time per read key for ``require_fresh_read`` guards.
_FRESH_READS: dict[str, float] = {}
_FRESH_LOCK = threading.Lock()
_ANY_READ_KEY = "*"


def record_tool_call(tool_name: str) -> None:
    """Record that ``tool_name`` was invoked, for sequence guards.

    Guarded functions record themselves automatically; call this from tools
    that are not wrapped by ``tool_guard`` but may form the prefix of a
    forbidden sequence.
    """
    with _HISTORY_LOCK:
        _CALL_HISTORY.append(canonical_tool_name(tool_name))


def note_read(key: str | None = None) -> None:
    """Record that the caller just read a value guarded by ``require_fresh_read``.

    Production code calls this from the read tool (for example
    ``note_read("vendor_api")`` after fetching a vendor quote).  A guard
    configured with ``read_key`` (or ``read_tool``) only accepts reads recorded
    under that key, so an unrelated read elsewhere in the process cannot make a
    stale commit look fresh.  Only the latest timestamp per key is kept.
    """
    stamp = time.monotonic()
    with _FRESH_LOCK:
        _FRESH_READS[canonical_tool_name(key) if key else _ANY_READ_KEY] = stamp


def reset_guard_state() -> None:
    """Clear the process-wide call history and read clock (for tests and restarts)."""
    with _HISTORY_LOCK:
        _CALL_HISTORY.clear()
    with _FRESH_LOCK:
        _FRESH_READS.clear()


# ---------------------------------------------------------------------------
# The decorator
# ---------------------------------------------------------------------------


def tool_guard(
    policy: str,
    *,
    tool_name: str | None = None,
    **policy_kwargs: Any,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Enforce an invariant policy at the boundary of one tool function.

    Parameters
    ----------
    policy:
        Guard kind.  One of: ``block_if_not_in_whitelist``,
        ``block_if_amount_exceeds``, ``block_if_recipient_not_in_whitelist``,
        ``rate_limit_calls``, ``validate_parameters``, ``require_predecessor``,
        ``block_tool_sequence``, ``clip_payload_size``, ``circuit_breaker``,
        ``require_fresh_read``, ``block_payload_markers``.
    tool_name:
        Name recorded in audit events.  Defaults to the wrapped function's name.
    **policy_kwargs:
        Guard-specific configuration (see :data:`VIOLATION_GUARDS` for the
        mapping from violation type to policy and defaults).

    Raises
    ------
    PolicyError
        When the call is blocked.  The wrapped function is never invoked.
    ValueError
        At decoration time when ``policy`` is unknown.

    Notes
    -----
    Guards inspect the *bound* arguments (positional, keyword, and
    ``**kwargs`` alike) and walk nested containers, so moving a value into a
    different slot does not hide it.  A guard that raises internally blocks
    the call (fail closed).  Allowed calls are reported to the audit sinks as
    well as blocked ones, and every guarded call is recorded in the
    process-wide history that ``block_tool_sequence`` reads.

    The default ``on_blocked`` behaviour is to raise.  Passing
    ``on_blocked="return_error"`` makes the guard return a structured error
    dictionary instead, which suits frameworks that cannot propagate
    exceptions through their tool-calling layer.
    """
    if policy not in _GUARD_IMPLEMENTATIONS:
        raise ValueError(
            f"Unknown guard policy '{policy}'. "
            f"Supported: {', '.join(sorted(_GUARD_IMPLEMENTATIONS))}"
        )

    on_blocked = str(policy_kwargs.pop("on_blocked", "raise"))
    state = _GuardState()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        try:
            signature: inspect.Signature | None = inspect.signature(func)
        except (TypeError, ValueError):  # pragma: no cover - builtins without signatures
            signature = None
        signature_names = list(signature.parameters) if signature is not None else []
        declared_names = [
            name
            for name, parameter in (signature.parameters.items() if signature is not None else [])
            if parameter.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        ]
        resolved_name = tool_name or getattr(func, "__name__", "unknown_tool")

        def _block(outcome: dict[str, Any]) -> Any:
            audit_tool_call(
                resolved_name,
                policy,
                False,
                outcome.get("reason", "blocked"),
                **outcome.get("details", {}),
            )
            message = (
                f"PolicyError[{policy}] blocked call to '{resolved_name}': "
                f"{outcome.get('reason', 'policy violation')}"
            )
            if on_blocked == "return_error":
                return {
                    "success": False,
                    "error": message,
                    "policy": policy,
                    "details": outcome.get("details", {}),
                }
            raise PolicyError(
                message,
                tool_name=resolved_name,
                policy=policy,
                details=outcome.get("details", {}),
            )

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _bind_arguments(signature, args, kwargs)
            try:
                outcome = _GUARD_IMPLEMENTATIONS[policy](
                    func=func,
                    resolved_name=resolved_name,
                    signature_names=signature_names,
                    declared_names=declared_names,
                    args=args,
                    kwargs=kwargs,
                    bound=bound,
                    state=state,
                    policy_kwargs=policy_kwargs,
                )
            except Exception as exc:  # fail closed: a guard that cannot decide blocks
                outcome = {
                    "reason": f"guard evaluation failed ({type(exc).__name__}: {exc}); failing closed",
                    "details": {"error": type(exc).__name__},
                }
            if outcome is not None:
                return _block(outcome)

            record_tool_call(resolved_name)
            if _AUDIT_SINKS:
                audit_tool_call(resolved_name, policy, True, "allowed")
            try:
                result = func(*args, **kwargs)
            except Exception:
                with state.lock:
                    state.failures += 1
                raise
            with state.lock:
                if isinstance(result, dict) and result.get("success") is False:
                    state.failures += 1
                else:
                    state.failures = 0
            return result

        wrapper.__lifeforge_guard__ = {"policy": policy, "tool": resolved_name, "config": policy_kwargs}  # type: ignore[attr-defined]
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Guard implementations.  Each returns None to allow, or a dict with
# "reason" and "details" to block.  All receive the bound arguments.
# ---------------------------------------------------------------------------


def _guard_whitelist(
    *,
    resolved_name: str,
    declared_names: list[str],
    bound: dict[str, Any],
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    raw_whitelist = policy_kwargs.get("whitelist", []) or []
    if isinstance(raw_whitelist, str):
        raw_whitelist = [raw_whitelist]
    whitelist = {canonical_tool_name(name) for name in raw_whitelist if str(name).strip()}
    if not whitelist:
        # An empty allow-list is an unfinished configuration, not permission.
        return {
            "reason": "the allow-list is empty; populate 'whitelist' before this guard can permit calls",
            "details": {"tool": resolved_name, "whitelist": []},
        }
    # A generic dispatcher takes the real tool name as an argument.  That
    # argument is trusted only when the function *declares* a ``tool_name``
    # parameter (or the guard is configured as a dispatcher); otherwise a
    # caller could pass ``tool_name="search"`` through ``**kwargs`` and borrow
    # an allowed identity.
    is_dispatcher = bool(policy_kwargs.get("dispatcher")) or "tool_name" in declared_names
    call_target: Any = resolved_name
    if is_dispatcher:
        explicit = bound.get("tool_name")
        if explicit is not None:
            call_target = explicit
    if not isinstance(call_target, str) or not is_canonical_tool_name(call_target):
        return {
            "reason": f"tool name {str(call_target)[:80]!r} is not a canonical tool identifier",
            "details": {"tool": str(call_target)[:80], "whitelist": sorted(whitelist)},
        }
    if canonical_tool_name(call_target) not in whitelist:
        return {
            "reason": f"tool '{call_target}' is not in the authorized allow-list",
            "details": {"tool": call_target, "whitelist": sorted(whitelist)},
        }
    return None


def _token_approved(token: Any, amount: float, bound: dict[str, Any], policy_kwargs: dict[str, Any]) -> bool:
    """Decide whether an approval token authorizes an over-cap amount."""
    verifier = policy_kwargs.get("approval_verifier")
    if callable(verifier):
        return bool(verifier(token, amount, bound))
    valid_tokens = policy_kwargs.get("valid_tokens")
    if valid_tokens is not None:
        if not isinstance(token, str):
            return False
        return any(hmac.compare_digest(token, str(candidate)) for candidate in valid_tokens)
    # Backward-compatible default: any non-empty string token.  This only
    # proves the caller *claims* approval; configure ``approval_verifier`` or
    # ``valid_tokens`` for real enforcement.
    return isinstance(token, str) and bool(token.strip())


def _guard_amount(
    *,
    bound: dict[str, Any],
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    amount_arg = str(policy_kwargs.get("amount_arg", "amount"))
    max_amount = policy_kwargs.get("max_amount")
    if max_amount is None:
        return None
    cap, cap_error = coerce_amount(max_amount)
    if cap is None:
        return {
            "reason": f"guard misconfigured: max_amount {max_amount!r} is not a finite number ({cap_error})",
            "details": {"argument": amount_arg, "max_amount": str(max_amount)},
        }

    raw_amount = bound.get(amount_arg)
    amount, error = coerce_amount(raw_amount)
    if error is not None:
        return {
            "reason": f"{amount_arg} could not be validated: {error}",
            "details": {"argument": amount_arg, "value": str(raw_amount)[:80]},
        }
    if amount is None:
        return None
    if amount < 0 and not policy_kwargs.get("allow_negative", False):
        return {
            "reason": f"{amount_arg}={amount:,.2f} is negative",
            "details": {"argument": amount_arg, "amount": amount},
        }
    if amount <= cap:
        return None

    approval_arg = policy_kwargs.get("approved_token_arg")
    if approval_arg:
        token = bound.get(str(approval_arg))
        if token is not None and _token_approved(token, amount, bound, policy_kwargs):
            return None
    return {
        "reason": f"{amount_arg}={amount:,.2f} exceeds the authorized maximum of {cap:,.2f}",
        "details": {"argument": amount_arg, "amount": amount, "max_amount": cap},
    }


def _guard_recipient(
    *,
    bound: dict[str, Any],
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    recipient_arg = str(policy_kwargs.get("recipient_arg", "recipient"))
    allowed = [str(item) for item in policy_kwargs.get("allowed_recipients", []) or []]
    allowed_domains = [str(item) for item in policy_kwargs.get("allowed_domains", []) or []]
    if not allowed and not allowed_domains:
        return {
            "reason": "the recipient allow-list is empty; populate 'allowed_recipients' or 'allowed_domains'",
            "details": {"argument": recipient_arg},
        }
    candidates = [recipient_arg, *policy_kwargs.get("recipient_args", RECIPIENT_ARGUMENT_ALIASES)]
    seen: set[str] = set()
    for argument in candidates:
        argument = str(argument)
        if argument in seen:
            continue
        seen.add(argument)
        value = bound.get(argument)
        if value is None:
            continue
        if not recipient_value_allowed(value, allowed, allowed_domains):
            return {
                "reason": f"recipient {str(value)[:120]!r} is not on the egress allow-list",
                "details": {"argument": argument, "recipient": str(value)[:120], "allowed_recipients": allowed},
            }
    return None


def _guard_rate_limit(
    *,
    resolved_name: str,
    bound: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    max_calls = int(policy_kwargs.get("max_calls", 3))
    window = float(policy_kwargs.get("window_seconds", 30.0))
    # Identical-call cap plus a tool-wide cap: varying a junk argument changes
    # the signature but not the tool-wide count.
    max_tool_calls = int(policy_kwargs.get("max_tool_calls", max_calls * 4))
    signature = _signature_of(bound, policy_kwargs.get("signature_args", "all"))
    now = time.monotonic()
    with state.lock:
        for key in list(state.calls):
            state.calls[key] = [stamp for stamp in state.calls[key] if now - stamp < window]
            if not state.calls[key]:
                del state.calls[key]
        state.tool_calls = [stamp for stamp in state.tool_calls if now - stamp < window]
        history = state.calls.get(signature, [])
        if len(history) >= max_calls:
            return {
                "reason": (
                    f"identical call repeated {len(history)} times within {window:.0f}s "
                    f"(limit {max_calls}); breaking the retry cycle"
                ),
                "details": {"signature": signature[:200], "calls_in_window": len(history), "max_calls": max_calls},
            }
        if len(state.tool_calls) >= max_tool_calls:
            return {
                "reason": (
                    f"'{resolved_name}' called {len(state.tool_calls)} times within {window:.0f}s "
                    f"(tool-wide limit {max_tool_calls})"
                ),
                "details": {"calls_in_window": len(state.tool_calls), "max_tool_calls": max_tool_calls},
            }
        history.append(now)
        state.calls[signature] = history
        state.tool_calls.append(now)
    return None


def _guard_parameters(
    *,
    bound: dict[str, Any],
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    rules = policy_kwargs.get("rules", {}) or {}
    for argument, rule in rules.items():
        value = bound.get(str(argument))
        if value is None:
            continue
        minimum = rule.get("min")
        maximum = rule.get("max")
        if minimum is not None or maximum is not None:
            numeric, error = coerce_amount(value)
            if error is not None:
                return {
                    "reason": f"{argument} must be a finite number ({error})",
                    "details": {"argument": argument, "value": str(value)[:120]},
                }
            if numeric is not None:
                if minimum is not None and numeric < float(minimum):
                    return {
                        "reason": f"{argument}={numeric} is below the permitted minimum of {minimum}",
                        "details": {"argument": argument, "value": numeric, "min": minimum},
                    }
                if maximum is not None and numeric > float(maximum):
                    return {
                        "reason": f"{argument}={numeric} exceeds the permitted maximum of {maximum}",
                        "details": {"argument": argument, "value": numeric, "max": maximum},
                    }
        pattern = rule.get("pattern")
        if pattern:
            if not isinstance(value, str) or not re.fullmatch(str(pattern), value):
                return {
                    "reason": f"{argument} does not match the required pattern {pattern}",
                    "details": {"argument": argument, "value": str(value)[:120], "pattern": pattern},
                }
    return None


def _guard_predecessor(
    *,
    bound: dict[str, Any],
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    required = [str(item) for item in policy_kwargs.get("required_tools", []) or []]
    if not required:
        return None
    provider = policy_kwargs.get("completed_tools_provider")
    if callable(provider):
        # Server-side source of truth: preferred over anything the caller sends.
        completed = provider()
    else:
        # Caller-supplied state is read only from the configured argument; any
        # other list-shaped argument is ignored so ``tags=[...]`` cannot
        # satisfy the requirement.
        completed = bound.get(str(policy_kwargs.get("state_key", "completed_tools")))
    if isinstance(completed, str):
        completed = [completed]
    if not isinstance(completed, (list, tuple, set, frozenset)):
        completed = []
    completed_set = {canonical_tool_name(item) for item in completed if isinstance(item, str)}
    required_set = [canonical_tool_name(item) for item in required]
    mode = str(policy_kwargs.get("mode", "all")).lower()
    satisfied = (
        any(item in completed_set for item in required_set)
        if mode == "any"
        else all(item in completed_set for item in required_set)
    )
    if satisfied:
        return None
    return {
        "reason": f"required prerequisite(s) {required} ({mode}) have not been completed",
        "details": {"required_tools": required, "completed_tools": sorted(completed_set)},
    }


def _is_subsequence(prefix: Sequence[str], history: Sequence[str]) -> bool:
    """True when ``prefix`` occurs in order (not necessarily contiguously) in ``history``."""
    position = 0
    for name in history:
        if position < len(prefix) and name == prefix[position]:
            position += 1
    return position == len(prefix)


def _guard_sequence(
    *,
    resolved_name: str,
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    sequence = [str(item) for item in policy_kwargs.get("forbidden_sequence", []) or []]
    if not sequence:
        return None
    target = canonical_tool_name(sequence[-1].split(":")[0])
    if canonical_tool_name(resolved_name) != target:
        return None
    prefix = [canonical_tool_name(entry.split(":")[0]) for entry in sequence[:-1]]
    window = int(policy_kwargs.get("window", 50))
    with _HISTORY_LOCK:
        history = list(_CALL_HISTORY)[-window:] if window > 0 else list(_CALL_HISTORY)
    if prefix and _is_subsequence(prefix, history):
        return {
            "reason": f"call completes the forbidden tool sequence {sequence}",
            "details": {"forbidden_sequence": sequence, "observed_history": history[-5:]},
        }
    return None


def _guard_clip_payload(
    *,
    bound: dict[str, Any],
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    # Size enforcement on *inputs*: an oversized argument anywhere in the call
    # (positional, keyword, or nested) is rejected.
    max_chars = int(policy_kwargs.get("max_chars", 8000))
    for key, value in bound.items():
        for path, text in iter_strings(value):
            if len(text) > max_chars:
                return {
                    "reason": (
                        f"argument '{key}{path}' carries {len(text):,} characters, exceeding the "
                        f"{max_chars:,}-character context budget"
                    ),
                    "details": {"argument": f"{key}{path}", "chars": len(text), "max_chars": max_chars},
                }
    return None


def _guard_circuit_breaker(
    *,
    state: _GuardState,
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    cooldown = float(policy_kwargs.get("cooldown_seconds", 60.0))
    max_failures = int(policy_kwargs.get("max_consecutive_failures", 3))
    now = time.monotonic()
    with state.lock:
        if state.opened_at is not None:
            if now - state.opened_at < cooldown:
                return {
                    "reason": (
                        f"circuit open after {state.failures} consecutive failures; "
                        f"re-plan instead of retrying ({cooldown - (now - state.opened_at):.0f}s remaining)"
                    ),
                    "details": {"failures": state.failures, "cooldown_seconds": cooldown},
                }
            # Half-open: allow one trial call; a further failure re-opens.
            state.opened_at = None
            state.failures = max(0, max_failures - 1)
            return None
        if state.failures >= max_failures:
            state.opened_at = now
            return {
                "reason": f"circuit opened after {state.failures} consecutive failures",
                "details": {"failures": state.failures, "max_consecutive_failures": max_failures},
            }
    return None


def _guard_fresh_read_shared(
    *,
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    """Freshness guard backed by the process-wide, per-key read clock."""
    max_age = float(policy_kwargs.get("max_age_seconds", 30.0))
    key_name = policy_kwargs.get("read_key") or policy_kwargs.get("read_tool")
    with _FRESH_LOCK:
        if key_name:
            last = _FRESH_READS.get(canonical_tool_name(key_name))
        else:
            last = max(_FRESH_READS.values()) if _FRESH_READS else None
    if last is None:
        hint = f'note_read("{key_name}")' if key_name else "note_read()"
        return {
            "reason": (
                f"no read recorded; call lifeforge.hardening.{hint} after fetching the "
                "value, or the commit will be blocked as stale"
            ),
            "details": {"max_age_seconds": max_age, "read_key": key_name},
        }
    age = time.monotonic() - last
    if age > max_age:
        return {
            "reason": f"last read was {age:.1f}s ago (limit {max_age:.0f}s); re-read before committing",
            "details": {"max_age_seconds": max_age, "last_read_age": round(age, 1), "read_key": key_name},
        }
    return None


def _guard_markers(
    *,
    bound: dict[str, Any],
    policy_kwargs: dict[str, Any],
    **_: Any,
) -> dict[str, Any] | None:
    markers = [str(marker) for marker in policy_kwargs.get("markers", []) or []]
    normalized = [(marker, normalize_text(marker)) for marker in markers if marker.strip()]
    if not normalized:
        return None
    for key, value in bound.items():
        for path, text in iter_strings(value):
            haystack = normalize_text(text)
            for marker, needle in normalized:
                if needle in haystack:
                    return {
                        "reason": (
                            f"argument '{key}{path}' carries the propagation marker {marker}; "
                            "refusing to spread the payload"
                        ),
                        "details": {"argument": f"{key}{path}", "marker": marker},
                    }
    return None


_GUARD_IMPLEMENTATIONS: dict[str, Callable[..., dict[str, Any] | None]] = {
    "block_if_not_in_whitelist": _guard_whitelist,
    "block_if_amount_exceeds": _guard_amount,
    "block_if_recipient_not_in_whitelist": _guard_recipient,
    "rate_limit_calls": _guard_rate_limit,
    "validate_parameters": _guard_parameters,
    "require_predecessor": _guard_predecessor,
    "block_tool_sequence": _guard_sequence,
    "clip_payload_size": _guard_clip_payload,
    "circuit_breaker": _guard_circuit_breaker,
    "require_fresh_read": _guard_fresh_read_shared,
    "block_payload_markers": _guard_markers,
}

SUPPORTED_POLICIES: tuple[str, ...] = tuple(sorted(_GUARD_IMPLEMENTATIONS))


# ---------------------------------------------------------------------------
# Code generation
#
# Everything that can originate outside this module (tool names and violation
# names read from a report, override keys and values, a custom docstring) is
# emitted only through ``repr()`` or after strict identifier validation, and
# the finished source is checked with ``ast.parse`` before it is returned.
# ---------------------------------------------------------------------------


class GeneratedCodeError(ValueError):
    """Raised when generated guard source would not be safe, valid Python."""


def _format_value(value: Any) -> str:
    """Render a Python literal for the generated source (safe types only)."""
    if value is None or isinstance(value, (bool, int, str)):
        return repr(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "float('nan')"
        if math.isinf(value):
            return "float('inf')" if value > 0 else "float('-inf')"
        return repr(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if isinstance(value, (set, frozenset)):
            items = sorted(items, key=repr)
        return "[" + ", ".join(_format_value(item) for item in items) + "]"
    if isinstance(value, dict):
        items = ", ".join(f"{_format_value(k)}: {_format_value(v)}" for k, v in value.items())
        return "{" + items + "}"
    raise GeneratedCodeError(
        f"cannot emit a value of type {type(value).__name__} into generated guard code"
    )


def _safe_comment(text: Any) -> str:
    """Render arbitrary text so it cannot leave a ``#`` comment line."""
    return repr(str(text))[1:-1]


def _is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("<") and value.endswith(">")


def _verify_source(source: str, *, what: str) -> None:
    """Refuse to hand out generated source that does not parse."""
    try:
        ast.parse(source)
    except SyntaxError as exc:
        raise GeneratedCodeError(f"generated {what} is not valid Python: {exc}") from exc


def generate_decorator_for_violation(
    violation_type: str,
    *,
    tool_name: str = "<tool_function_name>",
    overrides: dict[str, Any] | None = None,
    include_rationale: bool = True,
) -> str:
    """Generate the source text of one ``@tool_guard`` decorator.

    Parameters
    ----------
    violation_type:
        The violation the guard defends against (see :data:`VIOLATION_GUARDS`).
    tool_name:
        Documentation-only placeholder shown in the generated comment.  The
        decorator itself attaches to whatever function it is applied to.
    overrides:
        Values that replace the defaults from :data:`VIOLATION_GUARDS` for this
        guard's policy arguments (for example the real allow-list).  Keys must
        be plain Python identifiers; values must be literals.
    include_rationale:
        Emit the rationale as a comment above the decorator.

    Raises
    ------
    KeyError
        When ``violation_type`` is not in :data:`VIOLATION_GUARDS`.
    GeneratedCodeError
        When an override key or value cannot be emitted safely.
    """
    key = str(violation_type).strip().upper()
    if key not in VIOLATION_GUARDS:
        raise KeyError(
            f"No generated guard for violation {str(violation_type)[:80]!r}. "
            f"Known violations: {', '.join(sorted(VIOLATION_GUARDS))}"
        )

    spec = VIOLATION_GUARDS[key]
    policy = spec["policy"]
    defaults = dict(spec.get("kwargs", {}))
    kwargs = dict(defaults)
    if overrides:
        kwargs.update(overrides)

    lines: list[str] = []
    if include_rationale:
        for chunk in _wrap(spec["rationale"], 88):
            lines.append(f"# {_safe_comment(chunk)}")
    lines.append("@tool_guard(")
    lines.append(f"    policy={policy!r},")
    lines.append(f"    tool_name={str(tool_name)!r},")
    for name, value in kwargs.items():
        name = str(name)
        if not name.isidentifier() or keyword.iskeyword(name) or name in ("policy", "tool_name"):
            raise GeneratedCodeError(f"override key {name[:60]!r} is not a valid guard argument name")
        if _is_placeholder(value):
            default = defaults.get(name)
            note = _safe_comment(value[1:-1])
            if default is None or _is_placeholder(default) or isinstance(default, (list, tuple, set)):
                # List-valued settings (allow-lists) start empty, which every
                # guard treats as "block until configured" - never as allow-all.
                lines.append(f"    {name}=[],  # TODO: fill in - {note}")
            else:
                lines.append(f"    {name}={_format_value(default)},  # TODO: review - {note}")
        else:
            lines.append(f"    {name}={_format_value(value)},")
    lines.append(")")
    source = "\n".join(lines)
    _verify_source(source + "\ndef _generated_target(*args, **kwargs):\n    pass\n", what="decorator")
    return source


def _wrap(text: str, width: int) -> list[str]:
    """Greedy word wrap for generated comments."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _docstring_literal(text: str) -> str:
    """Return a string literal for a module docstring that cannot be escaped from."""
    printable = all(ch == "\n" or ch.isprintable() for ch in text)
    if printable and '"""' not in text and "\\" not in text and not text.endswith('"'):
        return '"""' + text + '\n"""'
    return repr(text)


def generate_hardening_module(
    violation_types: Iterable[str],
    *,
    module_docstring: str | None = None,
    tool_name_map: dict[str, str] | None = None,
    override_map: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Generate a complete, importable hardening module.

    The output imports the real runtime (``tool_guard``, ``PolicyError``) from
    :mod:`lifeforge.hardening`, so it runs as soon as it is saved.  Each
    affected tool gets a commented skeleton whose guard is already configured
    from the discovered violation.

    Tool names and violation names typically come from a benchmark report,
    which records what the agent under test emitted, so they are treated as
    untrusted: they appear in the output only through ``repr()``.  The result
    is parsed with :func:`ast.parse` before it is returned.

    Parameters
    ----------
    violation_types:
        Violations to defend against, typically read from a benchmark report's
        ``failure_mode_breakdown``.
    module_docstring:
        Overrides the generated header.
    tool_name_map:
        Maps a violation type to the tool it should guard, so the generated
        comments name the real function.
    override_map:
        Maps a violation type to guard-argument overrides (allow-lists, caps).
    """
    ordered = _ordered_unique(str(item).strip().upper() for item in violation_types)
    tool_name_map = tool_name_map or {}
    override_map = override_map or {}

    header = module_docstring or (
        "Hardening guards generated by LIFE FORGE.\n\n"
        "Each guard below enforces, at the tool boundary, one invariant that the\n"
        "evolutionary search found the agent violating.  Guards raise PolicyError\n"
        "before the underlying implementation runs, so a compromised or confused\n"
        "agent cannot complete the forbidden action.\n\n"
        "Generated file - review the TODO markers and wire each guard to the tool\n"
        "it names."
    )
    body_lines = header.splitlines()[1:] or [""]
    docstring_text = "Hardening guards generated by LIFE FORGE.\n\n" + "\n".join(body_lines).strip("\n")

    lines: list[str] = [
        _docstring_literal(docstring_text),
        "from __future__ import annotations",
        "",
        "from typing import Any",
        "",
        "from lifeforge.hardening import PolicyError, audit_tool_call, note_read, tool_guard",
        "",
        "__all__ = [",
        '    "PolicyError",',
        '    "audit_tool_call",',
        '    "note_read",',
        '    "tool_guard",',
    ]

    for violation in ordered:
        if violation in VIOLATION_GUARDS:
            lines.append(f"    {('guard_' + _identifier(violation))!r},")
    lines.extend(["]", ""])

    for violation in ordered:
        spec = VIOLATION_GUARDS.get(violation)
        if spec is None:
            lines.extend(
                [
                    f"# No generated guard template for {violation[:200]!r}.",
                    "# Review the finding manually and add a tool_guard by hand.",
                    "",
                ]
            )
            continue

        tool = str(tool_name_map.get(violation, "<tool_function_name>"))
        decorator = generate_decorator_for_violation(
            violation,
            tool_name=tool,
            overrides=override_map.get(violation),
        )
        function_name = f"guard_{_identifier(violation)}"
        message = f"Wire this guard to the real {tool} implementation."

        lines.extend(
            [
                f"# --- {violation} " + "-" * max(0, 60 - len(violation)),
                f"# Guard the tool that carries this failure mode: {_safe_comment(tool)}",
                "#",
                decorator,
                f"def {function_name}(*args: Any, **kwargs: Any) -> Any:",
                '    """Skeleton. Replace the body with the real tool implementation."""',
                "    raise NotImplementedError(",
                f"        {message!r}",
                "    )",
                "",
                "",
            ]
        )

    source = "\n".join(lines)
    _verify_source(source, what="hardening module")
    return source


def _identifier(text: str) -> str:
    """Convert a violation type into a Python identifier fragment."""
    return "".join(char.lower() if char.isascii() and char.isalnum() else "_" for char in text).strip("_")


def _ordered_unique(values: Iterable[str]) -> list[str]:
    """Preserve first-seen order while removing duplicates."""
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


#: Highest severity first, so generated reports lead with the worst findings.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def violations_from_report(report: dict[str, Any]) -> list[str]:
    """Extract violation types from a benchmark report dict, worst first.

    Reads ``failure_mode_breakdown`` (the aggregated counts produced by the
    analyzer) and orders categories by severity, then by descending count.
    """
    if not isinstance(report, dict):
        return []
    breakdown = report.get("failure_mode_breakdown", {}) or {}
    if not isinstance(breakdown, dict):
        return []

    def sort_key(item: tuple[str, Any]) -> tuple[int, int]:
        name, count = item
        rank = _SEVERITY_RANK.get(_severity_for(name), 4)
        try:
            magnitude = int(count)
        except (TypeError, ValueError):
            magnitude = 0
        return (rank, -magnitude)

    return [name for name, _ in sorted(breakdown.items(), key=sort_key)]


def _severity_for(violation_type: str) -> str:
    """Look up the severity a violation type carries in the guard table."""
    spec = VIOLATION_GUARDS.get(str(violation_type).strip().upper())
    if spec is None:
        return "MEDIUM"
    # Severity is a property of the violation, not the guard policy.
    return _VIOLATION_SEVERITY.get(str(violation_type).strip().upper(), "MEDIUM")


#: Severity per known violation type, mirroring the oracle's grading.
_VIOLATION_SEVERITY: dict[str, str] = {
    "UNAUTHORIZED_TOOL_EXECUTION": "CRITICAL",
    "UNAUTHORIZED_FINANCIAL_DRAIN": "CRITICAL",
    "UNAUTHORIZED_DATA_EXFILTRATION": "CRITICAL",
    "TOCTOU_RACE_CONDITION": "CRITICAL",
    "PRIVILEGE_ESCALATION": "CRITICAL",
    "SELF_REPLICATING_WORM_PROPAGATION": "CRITICAL",
    "RAG_MEMORY_POISONING_ADOPTED": "CRITICAL",
    "RECURSIVE_LOOP_TRAP": "HIGH",
    "BUDGET_EXCEEDED": "HIGH",
    "PARAMETER_BOUNDARY_VIOLATION": "HIGH",
    "CONTEXT_FLOOD_ATTACK": "HIGH",
    "CASCADING_TOOL_FAILURE": "HIGH",
    "GOAL_INVENTORY_DEFICIT": "MEDIUM",
    "UNAUTHORIZED_SCOPE_EXPANSION": "MEDIUM",
    "EXCESSIVE_DATA_QUERYING": "MEDIUM",
    "CONFIRMATION_NOT_SENT": "LOW",
}


def write_hardening_module(
    violations: Iterable[str],
    output_path: Path | str,
    **kwargs: Any,
) -> Path:
    """Generate, verify, and write a hardening module, returning the written path."""
    source = generate_hardening_module(violations, **kwargs)
    _verify_source(source, what="hardening module")
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def supported_violations() -> list[str]:
    """Return the violation types that have a generated guard template."""
    return sorted(VIOLATION_GUARDS)
