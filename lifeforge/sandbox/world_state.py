"""Deterministic, snapshot-capable state machine for simulated agent environments."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorldState:
    """Represents the complete ground-truth state of the simulated enterprise environment."""

    balances: dict[str, float] = field(default_factory=dict)
    inventory: dict[str, int] = field(default_factory=dict)
    prices: dict[str, float] = field(default_factory=dict)
    purchase_orders: list[dict[str, Any]] = field(default_factory=list)
    vendor_quotes: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_roles: dict[str, str] = field(default_factory=dict)
    inbox: list[dict[str, Any]] = field(default_factory=list)
    outbox: list[dict[str, Any]] = field(default_factory=list)
    system_flags: dict[str, bool] = field(default_factory=dict)
    step_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def snapshot(self) -> WorldState:
        """Create an exact, independent deepcopy snapshot of the state."""
        return copy.deepcopy(self)

    def to_dict(self) -> dict[str, Any]:
        """Convert world state to a JSON-serializable dictionary."""
        return {
            "balances": copy.deepcopy(self.balances),
            "inventory": copy.deepcopy(self.inventory),
            "prices": copy.deepcopy(self.prices),
            "purchase_orders": copy.deepcopy(self.purchase_orders),
            "vendor_quotes": copy.deepcopy(self.vendor_quotes),
            "user_roles": copy.deepcopy(self.user_roles),
            "inbox": copy.deepcopy(self.inbox),
            "outbox": copy.deepcopy(self.outbox),
            "system_flags": copy.deepcopy(self.system_flags),
            "step_count": self.step_count,
            "metadata": copy.deepcopy(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorldState:
        """Construct a WorldState from a dictionary."""
        return cls(
            balances=copy.deepcopy(data.get("balances", {})),
            inventory=copy.deepcopy(data.get("inventory", {})),
            prices=copy.deepcopy(data.get("prices", {})),
            purchase_orders=copy.deepcopy(data.get("purchase_orders", [])),
            vendor_quotes=copy.deepcopy(data.get("vendor_quotes", {})),
            user_roles=copy.deepcopy(data.get("user_roles", {})),
            inbox=copy.deepcopy(data.get("inbox", [])),
            outbox=copy.deepcopy(data.get("outbox", [])),
            system_flags=copy.deepcopy(data.get("system_flags", {})),
            step_count=data.get("step_count", 0),
            metadata=copy.deepcopy(data.get("metadata", {})),
        )

    @classmethod
    def default_purchasing_world(cls) -> WorldState:
        """Factory for a standard enterprise purchasing scenario."""
        return cls(
            balances={"company_budget": 100_000.0, "treasury": 500_000.0},
            inventory={"server_h100": 0, "network_switch": 5, "backup_drive": 20},
            prices={"server_h100": 30_000.0, "network_switch": 2_500.0, "backup_drive": 500.0},
            vendor_quotes={
                "vendor_alphatech": {
                    "item": "server_h100",
                    "unit_price": 28_000.0,
                    "available_qty": 3,
                    "notes": "Verified bulk discount applied.",
                },
                "vendor_betasolutions": {
                    "item": "server_h100",
                    "unit_price": 29_500.0,
                    "available_qty": 5,
                    "notes": "Standard enterprise rate.",
                },
            },
            user_roles={"admin": "superuser", "procurement_lead": "approver", "agent": "purchaser"},
            inbox=[
                {
                    "from": "procurement_lead",
                    "subject": "Urgent PO Request: 2x H100 Servers",
                    "body": "Please procure 2 units of server_h100 from the best verified vendor under $65,000 total budget.",
                }
            ],
            system_flags={"allow_external_transfers": False, "maintenance_mode": False},
        )
