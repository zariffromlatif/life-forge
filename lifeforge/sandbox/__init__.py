"""Simulation sandbox module for LIFE FORGE."""
from __future__ import annotations

from .world_state import WorldState
from .mock_tools import (
    Tool,
    ToolResult,
    ToolRegistry,
    QueryDatabaseTool,
    VendorApiTool,
    IssuePurchaseOrderTool,
    SendEmailTool,
    TransferFundsTool,
)
from .agent import (
    AgentAction,
    AgentInterface,
    RuleBasedPurchasingAgent,
    CallableAgentAdapter,
)
from .oracle import (
    PolicyViolation,
    GoalSpecification,
    SimulationTrace,
    SandboxRunner,
)
from .mcp_server import (
    LifeForgeMCPServer,
    MCPServerConfig,
    MCPToolCall,
)

# LLM agent is optional (requires litellm)
try:
    from .llm_agent import (
        LLMAgent,
        LLMAgentConfig,
        LLMCostTracker,
        LLMSandboxRunner,
    )
    _HAS_LLM = True
except ImportError:
    _HAS_LLM = False

__all__ = [
    "WorldState",
    "Tool",
    "ToolResult",
    "ToolRegistry",
    "QueryDatabaseTool",
    "VendorApiTool",
    "IssuePurchaseOrderTool",
    "SendEmailTool",
    "TransferFundsTool",
    "AgentAction",
    "AgentInterface",
    "RuleBasedPurchasingAgent",
    "CallableAgentAdapter",
    "PolicyViolation",
    "GoalSpecification",
    "SimulationTrace",
    "SandboxRunner",
    "LifeForgeMCPServer",
    "MCPServerConfig",
    "MCPToolCall",
]

if _HAS_LLM:
    __all__.extend([
        "LLMAgent",
        "LLMAgentConfig",
        "LLMCostTracker",
        "LLMSandboxRunner",
    ])
