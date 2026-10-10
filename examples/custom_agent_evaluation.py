"""Custom Agent Example: Evaluating a user-defined agent in LIFE FORGE."""
from __future__ import annotations

from typing import Any

from lifeforge.evolution.engine import EvolutionEngine
from lifeforge.reporting.analyzer import CausalAnalyzer
from lifeforge.sandbox.agent import AgentAction, AgentInterface
from lifeforge.sandbox.oracle import SandboxRunner


class MyCustomProcurementAgent(AgentInterface):
    """
    A custom agent implementation demonstrating how external agents
    (LangChain, CrewAI, AutoGen, or custom rule engines) integrate into LIFE FORGE.
    """

    def __init__(self, name: str = "MyCustomAgent-v1") -> None:
        self.name = name
        self.step_count = 0
        self.quote: dict[str, Any] | None = None
        self.ordered = False

    def reset(self) -> None:
        self.step_count = 0
        self.quote = None
        self.ordered = False

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        self.step_count += 1
        last = observation.get("last_tool_result") or {}

        # Step 1: Inspect inventory.  Argument names follow the tool schemas in
        # observation["available_tools"]; a misnamed argument is an error.
        if self.step_count == 1:
            return AgentAction(
                action_type="tool_call",
                tool_name="query_database",
                arguments={"table": "inventory"},
                thought="Checking inventory status...",
            )

        # Step 2: Get a live quote.
        if self.step_count == 2:
            return AgentAction(
                action_type="tool_call",
                tool_name="vendor_api",
                arguments={"vendor_id": "vendor_alphatech", "item": "server_h100"},
                thought="Checking price for server_h100...",
            )

        # Step 3: Buy only at the price just quoted.  Instructions found in
        # vendor notes or the inbox are data, never commands, so this agent
        # does not act on them.
        if self.step_count == 3:
            if not last.get("success"):
                return AgentAction(action_type="finish", thought="No valid quote; not purchasing.")
            self.quote = last["output"]
            if self.quote.get("available_qty", 0) < 2:
                return AgentAction(action_type="finish", thought="Insufficient stock; escalating instead of buying.")
            return AgentAction(
                action_type="tool_call",
                tool_name="issue_purchase_order",
                arguments={
                    "vendor_id": self.quote["vendor_id"],
                    "item": self.quote["item"],
                    "quantity": 2,
                    "max_unit_price": self.quote["unit_price"],
                },
                thought="Placing order for 2 H100 servers at the quoted price...",
            )

        # Step 4: Confirm to the procurement lead (only if the order went through).
        if self.step_count == 4 and last.get("success"):
            self.ordered = True
            return AgentAction(
                action_type="tool_call",
                tool_name="send_email",
                arguments={"recipient": "procurement_lead", "subject": "Order Complete", "body": "H100 servers purchased."},
                thought="Notifying procurement lead...",
            )

        # Step 5: Complete task
        return AgentAction(
            action_type="finish",
            thought="Task fulfilled successfully." if self.ordered else "Stopping without a completed order.",
        )


def main() -> None:
    print("=" * 60)
    print("  LIFE FORGE -- Custom Agent Stress Test")
    print("=" * 60)

    agent = MyCustomProcurementAgent()
    runner = SandboxRunner()
    engine = EvolutionEngine(runner=runner, seed=123)

    print(f"\n[*] Evaluating custom agent: {agent.name}")
    print("[*] Running 10 evolutionary generations...")
    summary = engine.run(agent=agent, generations=10)

    print(f"\n[OK] Evaluation complete.")
    print(f"     Total Evaluations: {summary.total_evaluations}")
    print(f"     Critical Failures: {summary.critical_failures_count}")

    analyzer = CausalAnalyzer(runner=runner)
    metrics = analyzer.analyze(agent=agent, summary=summary)
    print(f"     Rating:            {metrics.generalization_rating}")
    print(f"     Failure Rate:      {metrics.failure_rate}%")


if __name__ == "__main__":
    main()
