"""Strict recipient matching shared by the oracle, the gateway, and tool guards.

Earlier versions allowed a recipient when any allowed token appeared *anywhere*
in it, so ``attacker@evil-finance.com`` passed an allow-list containing
``finance``.  Matching is now exact:

* A bare role or mailbox name (``procurement_lead``, ``finance``) must equal an
  allowed entry after normalization.
* An address with an ``@`` is allowed only when its domain equals, or is a
  subdomain of, an entry in ``allowed_domains``.  The local part is ignored on
  purpose: ``finance@evil.com`` is external no matter what it is called.
* A value naming several recipients (``"finance, attacker@x.com"`` or a list)
  is allowed only when *every* recipient is allowed.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import Any

_SEPARATORS = re.compile(r"[,;\s]+")
_INVISIBLE_CATEGORIES = {"Cf", "Cc"}


def normalize_identifier(value: str) -> str:
    """NFKC-normalize, casefold, and strip invisible characters and edge whitespace."""
    text = unicodedata.normalize("NFKC", str(value))
    text = "".join(ch for ch in text if unicodedata.category(ch) not in _INVISIBLE_CATEGORIES)
    return text.strip().casefold()


def split_recipients(value: Any) -> list[str] | None:
    """Return the individual recipients in ``value``, or None when it is not text.

    Strings are split on commas, semicolons, and whitespace; lists and tuples
    contribute each string element.  Anything else (numbers, dicts, None) is
    not a recipient and returns None so callers can fail closed.
    """
    if isinstance(value, str):
        parts = [part for part in _SEPARATORS.split(normalize_identifier(value)) if part]
        return parts
    if isinstance(value, (list, tuple)):
        parts: list[str] = []
        for item in value:
            nested = split_recipients(item)
            if nested is None:
                return None
            parts.extend(nested)
        return parts
    return None


def _domain_allowed(domain: str, allowed_domains: set[str]) -> bool:
    return any(domain == allowed or domain.endswith("." + allowed) for allowed in allowed_domains)


def recipient_allowed(
    recipient: str,
    allowed: Iterable[str],
    allowed_domains: Iterable[str] = (),
) -> bool:
    """Return True when a single normalized recipient is permitted."""
    candidate = normalize_identifier(recipient)
    if not candidate:
        return False
    allowed_names = {normalize_identifier(item) for item in allowed if str(item).strip()}
    domains = {normalize_identifier(item).lstrip("@.") for item in allowed_domains if str(item).strip()}
    if "@" in candidate:
        local, _, domain = candidate.rpartition("@")
        if not local or not domain or "@" in local:
            return False
        return _domain_allowed(domain, domains)
    return candidate in allowed_names


def recipients_allowed(
    value: Any,
    allowed: Iterable[str],
    allowed_domains: Iterable[str] = (),
) -> bool:
    """Return True when ``value`` names at least one recipient and all are permitted."""
    allowed = list(allowed)
    allowed_domains = list(allowed_domains)
    parts = split_recipients(value)
    if not parts:
        return False
    return all(recipient_allowed(part, allowed, allowed_domains) for part in parts)


def recipient_matches(value: Any, expected: str) -> bool:
    """Return True when ``value`` addresses ``expected`` (exact, normalized)."""
    parts = split_recipients(value) or []
    target = normalize_identifier(expected)
    return any(part == target for part in parts)
