"""Scenario domain registry.

A domain bundles the world state, tool suite, invariant policies, and
adversarial mutators for one business environment.  The evaluation engine,
CLI, and benchmark runner all resolve domains through :func:`get_domain`, so
adding an environment is a new module plus one registry entry.
"""
from __future__ import annotations

from lifeforge.sandbox.domains.base import ScenarioDomain
from lifeforge.sandbox.domains.customer_support import CustomerSupportDomain
from lifeforge.sandbox.domains.devops import DevOpsDomain
from lifeforge.sandbox.domains.financial import FinancialDomain
from lifeforge.sandbox.domains.procurement import ProcurementDomain

DOMAIN_REGISTRY: dict[str, type[ScenarioDomain]] = {
    ProcurementDomain.name: ProcurementDomain,
    CustomerSupportDomain.name: CustomerSupportDomain,
    DevOpsDomain.name: DevOpsDomain,
    FinancialDomain.name: FinancialDomain,
}


def get_domain(name: str) -> ScenarioDomain:
    """Instantiate a registered domain by name.

    Registered domains: ``procurement`` (the original enterprise benchmark
    environment), ``customer_support``, ``devops``, and ``financial``.  Unknown
    names raise :class:`KeyError` listing what is available.
    """
    key = str(name).strip().lower()
    try:
        domain_cls = DOMAIN_REGISTRY[key]
    except KeyError as exc:
        raise KeyError(
            f"Unknown domain '{name}'. Registered domains: {', '.join(sorted(DOMAIN_REGISTRY))}"
        ) from exc
    return domain_cls()


def list_domains() -> list[str]:
    """Return the sorted names of all registered domains."""
    return sorted(DOMAIN_REGISTRY)


__all__ = [
    "ScenarioDomain",
    "ProcurementDomain",
    "CustomerSupportDomain",
    "DevOpsDomain",
    "FinancialDomain",
    "DOMAIN_REGISTRY",
    "get_domain",
    "list_domains",
]
