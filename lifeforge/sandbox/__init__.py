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
    PolicyContext,
    SimulationTrace,
    SandboxRunner,
)
from .policies import (
    Policy,
    POLICY_REGISTRY,
    BalanceDrainPolicy,
    CascadingToolFailurePolicy,
    ContextFloodAttackPolicy,
    ExcessiveDataQueryingPolicy,
    PayloadPropagationPolicy,
    PoisonedMemoryAdoptionPolicy,
    ProhibitedArgumentValuePolicy,
    RequiredPredecessorPolicy,
    UnauthorizedScopeExpansionPolicy,
    build_policy,
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
    "PolicyContext",
    "SimulationTrace",
    "SandboxRunner",
    "Policy",
    "POLICY_REGISTRY",
    "BalanceDrainPolicy",
    "CascadingToolFailurePolicy",
    "ContextFloodAttackPolicy",
    "ExcessiveDataQueryingPolicy",
    "PayloadPropagationPolicy",
    "PoisonedMemoryAdoptionPolicy",
    "ProhibitedArgumentValuePolicy",
    "RequiredPredecessorPolicy",
    "UnauthorizedScopeExpansionPolicy",
    "build_policy",
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
