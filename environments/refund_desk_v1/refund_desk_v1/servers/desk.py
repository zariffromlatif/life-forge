"""Tool server for the refund desk: the support desk's tools over MCP.

One server runs per rollout. Each rollout's task carries its own world (the
inbox, orders and knowledge base for that scenario, including the attack), which
the server loads in ``setup_task``. Tool names and parameters mirror LIFE FORGE's
``customer_support`` twin exactly; ``tests/test_env_refund_desk.py`` in the
LIFE FORGE repository checks this against the twin so they cannot drift.

The rollout *reward* does not trust this server's responses. It replays the
agent's recorded tool calls through the twin and oracle (see ``core.py``).
"""
import json

import verifiers.v1 as vf
from lifeforge.sandbox.domains import get_domain
from lifeforge.sandbox.world_state import WorldState

DOMAIN = "customer_support"


class RefundDeskToolset(vf.Toolset[vf.ToolsetConfig]):
    # Expose the real tool names (``issue_refund``), not ``refund_desk_issue_refund``.
    TOOL_PREFIX = None

    def __init__(self, config: vf.ToolsetConfig) -> None:
        super().__init__(config)
        domain = get_domain(DOMAIN)
        self._registry = domain.build_tool_registry()
        self._world: WorldState = domain.build_world()

    async def setup_task(self, task) -> None:
        """Load this rollout's scenario world."""
        world = getattr(task, "world", None) or getattr(getattr(task, "data", None), "world", None)
        if isinstance(world, dict):
            self._world = WorldState.from_dict(world)

    def _call(self, name: str, **arguments) -> str:
        self._world.step_count += 1
        result = self._registry.dispatch(name, self._world, arguments)
        return json.dumps(
            {"ok": result.success, "output": result.output, "error": result.error},
            default=str,
        )

    @vf.tool
    def search_knowledge_base(self, query: str, max_results: int = 3) -> str:
        """Search the internal support knowledge base for policies and troubleshooting steps."""
        return self._call("search_knowledge_base", query=query, max_results=max_results)

    @vf.tool
    def lookup_order(self, order_id: str, customer_id: str = "") -> str:
        """Retrieve a customer order record (status, amount, and account email)."""
        arguments = {"order_id": order_id}
        if customer_id:
            arguments["customer_id"] = customer_id
        return self._call("lookup_order", **arguments)

    @vf.tool
    def issue_refund(self, order_id: str, amount: float, reason: str) -> str:
        """Refund a customer order. Refunds above the agent's authority limit must be escalated."""
        return self._call("issue_refund", order_id=order_id, amount=amount, reason=reason)

    @vf.tool
    def escalate_ticket(self, ticket_id: str, summary: str) -> str:
        """Escalate a support ticket to a human queue."""
        return self._call("escalate_ticket", ticket_id=ticket_id, summary=summary)

    @vf.tool
    def grant_account_access(self, customer_id: str, access_type: str) -> str:
        """Reset customer credentials or unlock an account after identity verification.

        access_type is one of: password_reset, unlock, admin_grant.
        """
        return self._call("grant_account_access", customer_id=customer_id, access_type=access_type)

    @vf.tool
    def send_email(self, recipient: str, subject: str, body: str) -> str:
        """Send an email to a customer or internal team."""
        return self._call("send_email", recipient=recipient, subject=subject, body=body)


if __name__ == "__main__":
    RefundDeskToolset.run()
