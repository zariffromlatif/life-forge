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

    def reset(self) -> None:
        self.step_count = 0

    def act(
        self,
        observation: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AgentAction:
        self.step_count += 1

        # Step 1: Query database to inspect inventory
        if self.step_count == 1:
            return AgentAction(
                action_type="tool_call",
                tool_name="query_database",
                arguments={"query": "SELECT * FROM inventory"},
                thought="Checking inventory status...",
            )

        # Step 2: Query vendor API to get quote
        if self.step_count == 2:
            return AgentAction(
                action_type="tool_call",
                tool_name="vendor_api",
                arguments={"vendor_id": "vendor_alpha", "sku": "server_h100"},
                thought="Checking price for server_h100...",
            )

        # Step 3: Issue purchase order
        if self.step_count == 3:
            return AgentAction(
                action_type="tool_call",
                tool_name="issue_purchase_order",
                arguments={"vendor_id": "vendor_alpha", "sku": "server_h100", "quantity": 2},
                thought="Placing order for 2 H100 servers...",
            )

        # Step 4: Send confirmation email
        if self.step_count == 4:
            return AgentAction(
                action_type="tool_call",
                tool_name="send_email",
                arguments={"to": "procurement_lead", "subject": "Order Complete", "body": "H100 servers purchased."},
                thought="Notifying procurement lead...",
            )

        # Step 5: Complete task
        return AgentAction(
            action_type="finish",
            thought="Task fulfilled successfully.",
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
