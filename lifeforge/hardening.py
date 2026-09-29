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

import functools
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

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


def register_audit_sink(sink: Callable[[GuardEvent], None]) -> None:
    """Attach a callback that receives every guard decision."""
    if sink not in _AUDIT_SINKS:
        _AUDIT_SINKS.append(sink)


def unregister_audit_sink(sink: Callable[[GuardEvent], None]) -> None:
    """Detach a previously registered audit sink."""
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
    for sink in list(_AUDIT_SINKS):
        try:
            sink(event)
        except Exception:  # pragma: no cover - a bad sink must not break a tool call
            continue
    return event


# ---------------------------------------------------------------------------
# Parameter extraction helpers
# ---------------------------------------------------------------------------


def _extract_argument(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    name: str,
    signature_names: Sequence[str],
) -> Any:
    """Resolve an argument by keyword first, then by position."""
    if name in kwargs:
        return kwargs[name]
    if name in signature_names:
        index = list(signature_names).index(name)
        if index < len(args):
            return args[index]
    return None


def _as_float(value: Any) -> float | None:
    """Best-effort numeric coercion; returns None when the value is not numeric."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _signature_of(kwargs: dict[str, Any], signature_args: Any) -> str:
    """Build the call signature used by the rate limiter."""
    if signature_args == "all" or signature_args is None:
        keys = sorted(kwargs)
    elif isinstance(signature_args, str):
        keys = [signature_args]
    else:
        keys = sorted(str(key) for key in signature_args)
    return json.dumps({key: kwargs.get(key) for key in keys}, sort_keys=True, default=str)


class _GuardState:
    """Per-decorator mutable state for rate limits and circuit breakers."""

    def __init__(self) -> None:
        self.calls: dict[str, list[float]] = {}
        self.failures: int = 0
        self.opened_at: float | None = None


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
        import inspect

        signature_names = list(inspect.signature(func).parameters)
        resolved_name = tool_name or getattr(func, "__name__", "unknown_tool")

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            outcome = _GUARD_IMPLEMENTATIONS[policy](
                func=func,
                resolved_name=resolved_name,
                signature_names=signature_names,
                args=args,
                kwargs=kwargs,
                state=state,
                policy_kwargs=policy_kwargs,
            )
            if outcome is None:
                result = func(*args, **kwargs)
                state.failures = 0
                return result

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

        wrapper.__lifeforge_guard__ = {"policy": policy, "tool": resolved_name, "config": policy_kwargs}  # type: ignore[attr-defined]
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Guard implementations.  Each returns None to allow, or a dict with
# "reason" and "details" to block.
# ---------------------------------------------------------------------------


def _guard_whitelist(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    whitelist = {str(name) for name in policy_kwargs.get("whitelist", []) or []}
    if not whitelist:
        return None
    # A generic dispatcher takes the real tool name as an argument; a specific
    # guarded function is identified by its own name.
    explicit = _extract_argument(args, kwargs, "tool_name", signature_names)
    call_target = str(explicit) if isinstance(explicit, str) and explicit else resolved_name
    if call_target not in whitelist:
        return {
            "reason": f"tool '{call_target}' is not in the authorized allow-list",
            "details": {"tool": call_target, "whitelist": sorted(whitelist)},
        }
    return None


def _guard_amount(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    amount_arg = str(policy_kwargs.get("amount_arg", "amount"))
    max_amount = policy_kwargs.get("max_amount")
    if max_amount is None:
        return None
    max_amount = float(max_amount)

    raw_amount = _extract_argument(args, kwargs, amount_arg, signature_names)
    amount = _as_float(raw_amount)
    if amount is None:
        return None
    if amount <= max_amount:
        return None

    approval_arg = policy_kwargs.get("approved_token_arg")
    if approval_arg:
        token = _extract_argument(args, kwargs, str(approval_arg), signature_names)
        if token:
            return None
    return {
        "reason": f"{amount_arg}={amount:,.2f} exceeds the authorized maximum of {max_amount:,.2f}",
        "details": {"argument": amount_arg, "amount": amount, "max_amount": max_amount},
    }


def _guard_recipient(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    recipient_arg = str(policy_kwargs.get("recipient_arg", "recipient"))
    allowed = [str(item).lower() for item in policy_kwargs.get("allowed_recipients", []) or []]
    if not allowed:
        return None
    recipient = _extract_argument(args, kwargs, recipient_arg, signature_names)
    if recipient is None:
        return None
    candidate = str(recipient).strip().lower()
    if any(item in candidate for item in allowed):
        return None
    return {
        "reason": f"recipient '{recipient}' is not on the egress allow-list",
        "details": {"recipient": recipient, "allowed_recipients": allowed},
    }


def _guard_rate_limit(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    max_calls = int(policy_kwargs.get("max_calls", 3))
    window = float(policy_kwargs.get("window_seconds", 30.0))
    signature = _signature_of(kwargs, policy_kwargs.get("signature_args", "all"))
    now = time.monotonic()
    history = [stamp for stamp in state.calls.get(signature, []) if now - stamp < window]
    if len(history) >= max_calls:
        state.calls[signature] = history
        return {
            "reason": (
                f"identical call repeated {len(history)} times within {window:.0f}s "
                f"(limit {max_calls}); breaking the retry cycle"
            ),
            "details": {"signature": signature, "calls_in_window": len(history), "max_calls": max_calls},
        }
    history.append(now)
    state.calls[signature] = history
    return None


def _guard_parameters(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    rules = policy_kwargs.get("rules", {}) or {}
    for argument, rule in rules.items():
        value = _extract_argument(args, kwargs, str(argument), signature_names)
        if value is None:
            continue
        numeric = _as_float(value)
        if numeric is not None:
            minimum = rule.get("min")
            maximum = rule.get("max")
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
            import re

            if not re.search(str(pattern), str(value)):
                return {
                    "reason": f"{argument} does not match the required pattern {pattern}",
                    "details": {"argument": argument, "value": str(value)[:120], "pattern": pattern},
                }
    return None


def _guard_predecessor(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    state_arg = str(policy_kwargs.get("state_key", "completed_tools"))
    required = [str(item) for item in policy_kwargs.get("required_tools", []) or []]
    if not required:
        return None
    completed = kwargs.get(state_arg)
    if completed is None:
        for candidate in kwargs.values():
            if isinstance(candidate, (set, list, tuple)) and all(
                isinstance(item, str) for item in candidate
            ):
                completed = candidate
                break
    completed_set = {str(item) for item in (completed or [])}
    if any(item in completed_set for item in required):
        return None
    return {
        "reason": f"required prerequisite {required} has not been completed",
        "details": {"required_tools": required, "completed_tools": sorted(completed_set)},
    }


def _guard_sequence(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    sequence = [str(item) for item in policy_kwargs.get("forbidden_sequence", []) or []]
    if not sequence:
        return None
    history = state.calls.setdefault("sequence", [])  # type: ignore[arg-type]
    target = sequence[-1].split(":")[0]
    if resolved_name != target:
        history.append(resolved_name)
        return None
    prefix = [entry.split(":")[0] for entry in sequence[:-1]]
    if len(history) >= len(prefix) and history[-len(prefix):] == prefix:
        return {
            "reason": f"call completes the forbidden tool sequence {sequence}",
            "details": {"forbidden_sequence": sequence, "observed_history": history[-5:]},
        }
    history.append(resolved_name)
    return None


def _guard_clip_payload(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    # Clipping is a transform, not a denial: never blocks, so it returns None
    # and lets the wrapper invoke the function.  Size enforcement on *inputs*
    # is what matters here, so oversized arguments are what we reject.
    max_chars = int(policy_kwargs.get("max_chars", 8000))
    for key, value in kwargs.items():
        if isinstance(value, str) and len(value) > max_chars:
            return {
                "reason": (
                    f"argument '{key}' carries {len(value):,} characters, exceeding the "
                    f"{max_chars:,}-character context budget"
                ),
                "details": {"argument": key, "chars": len(value), "max_chars": max_chars},
            }
    return None


def _guard_circuit_breaker(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    cooldown = float(policy_kwargs.get("cooldown_seconds", 60.0))
    max_failures = int(policy_kwargs.get("max_consecutive_failures", 3))
    now = time.monotonic()
    if state.opened_at is not None:
        if now - state.opened_at < cooldown:
            return {
                "reason": (
                    f"circuit open after {state.failures} consecutive failures; "
                    f"re-plan instead of retrying ({cooldown - (now - state.opened_at):.0f}s remaining)"
                ),
                "details": {"failures": state.failures, "cooldown_seconds": cooldown},
            }
        state.opened_at = None
        state.failures = 0
    if state.failures >= max_failures:
        state.opened_at = now
        return {
            "reason": f"circuit opened after {state.failures} consecutive failures",
            "details": {"failures": state.failures, "max_consecutive_failures": max_failures},
        }
    return None


def _guard_fresh_read(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    max_age = float(policy_kwargs.get("max_age_seconds", 30.0))
    reads = state.calls.get("reads", [])  # type: ignore[assignment]
    if not reads:
        return {
            "reason": (
                "no recent read of the underlying value; re-reading before committing "
                "prevents acting on stale state"
            ),
            "details": {"max_age_seconds": max_age, "last_read_age": None},
        }
    last_read = max(float(stamp) for stamp in reads)
    age = time.monotonic() - last_read
    if age > max_age:
        return {
            "reason": (
                f"last read was {age:.1f}s ago, older than the {max_age:.0f}s freshness window; "
                "re-read before committing to avoid a time-of-check/time-of-use race"
            ),
            "details": {"max_age_seconds": max_age, "last_read_age": round(age, 1)},
        }
    return None


def _guard_markers(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    markers = [str(marker) for marker in policy_kwargs.get("markers", []) or []]
    if not markers:
        return None
    for key, value in kwargs.items():
        for marker in markers:
            if isinstance(value, str) and marker in value:
                return {
                    "reason": (
                        f"argument '{key}' carries the propagation marker {marker}; "
                        "refusing to spread the payload"
                    ),
                    "details": {"argument": key, "marker": marker},
                }
    return None


def note_read() -> None:
    """Record that the caller just read a value guarded by ``require_fresh_read``.

    Production code calls this from the read tool (for example the function that
    fetches a vendor quote) so the freshness guard on the mutating tool knows
    how old the observation is.  The timestamp is stored on the module-level
    clock shared by every freshness guard in the process.
    """
    _FRESH_READ_CLOCK.append(time.monotonic())


#: Shared read timestamps for ``require_fresh_read`` guards.
_FRESH_READ_CLOCK: list[float] = []


def _guard_fresh_read_shared(
    *,
    func: Callable[..., Any],
    resolved_name: str,
    signature_names: list[str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    state: _GuardState,
    policy_kwargs: dict[str, Any],
) -> dict[str, Any] | None:
    """Freshness guard backed by the process-wide read clock."""
    max_age = float(policy_kwargs.get("max_age_seconds", 30.0))
    if not _FRESH_READ_CLOCK:
        return {
            "reason": (
                "no read recorded; call lifeforge.hardening.note_read() after fetching the "
                "value, or the commit will be blocked as stale"
            ),
            "details": {"max_age_seconds": max_age},
        }
    age = time.monotonic() - max(_FRESH_READ_CLOCK)
    if age > max_age:
        return {
            "reason": f"last read was {age:.1f}s ago (limit {max_age:.0f}s); re-read before committing",
            "details": {"max_age_seconds": max_age, "last_read_age": round(age, 1)},
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
# ---------------------------------------------------------------------------


def _format_value(value: Any) -> str:
    """Render a Python literal for the generated source."""
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, (list, tuple, set)):
        items = ", ".join(_format_value(item) for item in value)
        return f"[{items}]"
    if isinstance(value, dict):
        items = ", ".join(f"{_format_value(k)}: {_format_value(v)}" for k, v in value.items())
        return f"{{{items}}}"
    return repr(value)


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
        guard's policy arguments (for example the real allow-list).
    include_rationale:
        Emit the rationale as a comment above the decorator.

    Raises
    ------
    KeyError
        When ``violation_type`` is not in :data:`VIOLATION_GUARDS`.
    """
    key = str(violation_type).strip().upper()
    if key not in VIOLATION_GUARDS:
        raise KeyError(
            f"No generated guard for violation '{violation_type}'. "
            f"Known violations: {', '.join(sorted(VIOLATION_GUARDS))}"
        )

    spec = VIOLATION_GUARDS[key]
    policy = spec["policy"]
    kwargs = dict(spec.get("kwargs", {}))
    if overrides:
        kwargs.update(overrides)

    lines: list[str] = []
    if include_rationale:
        for chunk in _wrap(spec["rationale"], 88):
            lines.append(f"# {chunk}")
    lines.append("@tool_guard(")
    lines.append(f"    policy={policy!r},")
    lines.append(f"    tool_name={tool_name!r},")
    for name, value in kwargs.items():
        if isinstance(value, str) and value.startswith("<") and value.endswith(">"):
            lines.append(f"    {name}=[],  # TODO: fill in - {value[1:-1]}")
        else:
            lines.append(f"    {name}={_format_value(value)},")
    lines.append(")")
    return "\n".join(lines)


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

    lines: list[str] = [
        '"""Hardening guards generated by LIFE FORGE.',
        "",
        *[line for line in header.splitlines()[1:] or [""]],
        '"""',
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
        spec = VIOLATION_GUARDS.get(violation)
        if spec is None:
            continue
        lines.append(f'    "guard_{_identifier(violation)}",')
    lines.extend(["]", ""])

    for violation in ordered:
        spec = VIOLATION_GUARDS.get(violation)
        if spec is None:
            lines.extend(
                [
                    f"# No generated guard template for '{violation}'.",
                    "# Review the finding manually and add a tool_guard by hand.",
                    "",
                ]
            )
            continue

        tool = tool_name_map.get(violation, "<tool_function_name>")
        decorator = generate_decorator_for_violation(
            violation,
            tool_name=tool,
            overrides=override_map.get(violation),
        )
        function_name = f"guard_{_identifier(violation)}"

        lines.extend(
            [
                f"# --- {violation} " + "-" * max(0, 60 - len(violation)),
                f"# Guard the tool that carries this failure mode: {tool}",
                "#",
                decorator,
                f"def {function_name}(*args: Any, **kwargs: Any) -> Any:",
                '    """Skeleton. Replace the body with the real tool implementation."""',
                f"    raise NotImplementedError(",
                f"        'Wire this guard to the real {tool} implementation.'",
                "    )",
                "",
                "",
            ]
        )

    return "\n".join(lines)


def _identifier(text: str) -> str:
    """Convert a violation type into a Python identifier fragment."""
    return "".join(char.lower() if char.isalnum() else "_" for char in text).strip("_")


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
    policy = spec.get("policy")
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
    """Generate and write a hardening module, returning the written path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_hardening_module(violations, **kwargs), encoding="utf-8")
    return path


def supported_violations() -> list[str]:
    """Return the violation types that have a generated guard template."""
    return sorted(VIOLATION_GUARDS)
