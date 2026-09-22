from __future__ import annotations

# Scientific Universe Substrates
from .substrates import (
    Substrate,
    ElementaryCA,
    OuterTotalisticCA,
    MultiStateCA,
)

# MODES Measurement Suite & Basic Metrics
from .metrics import (
    population,
    density,
    activity,
    ActivityMetrics,
    compute_bedau_packard_activity,
    ComplexityMetrics,
    compute_shannon_entropy,
    compute_compressibility_ratio,
    compute_complexity_metrics,
    NoveltyMetrics,
    compute_novelty_metrics,
    EcologyMetrics,
    label_connected_components,
    compute_ecology_metrics,
    MODESSummary,
    analyze_modes,
    classify_dynamic_regime,
)

# Experiment Database
from .experiments.database import (
    ExperimentDatabase,
    ExperimentRecord,
)

# Legacy CA core (backward compatibility)
from .world import World
from .rules import (
    Rule,
    OuterTotalisticRule,
    ConwayRule,
    random_outer_totalistic_rule,
)
from .experiment import (
    ExperimentConfig,
    ExperimentResult,
    run_experiment,
    save_result,
)
try:
    from .visualization import plot_metrics, animate_world
except ImportError:
    plot_metrics = None  # type: ignore
    animate_world = None  # type: ignore
from .temporal import (
    TemporalSummary,
    find_extinction_time,
    persistence_ratio,
    lag_autocorrelation,
    find_exact_recurrence_period,
    analyze_temporal_dynamics,
)

# Agent simulation & sandbox
from .sandbox import (
    WorldState,
    Tool,
    ToolResult,
    ToolRegistry,
    QueryDatabaseTool,
    VendorApiTool,
    IssuePurchaseOrderTool,
    SendEmailTool,
    TransferFundsTool,
    AgentAction,
    AgentInterface,
    RuleBasedPurchasingAgent,
    CallableAgentAdapter,
    PolicyViolation,
    GoalSpecification,
    SimulationTrace,
    SandboxRunner,
    LifeForgeMCPServer,
    MCPServerConfig,
    MCPToolCall,
)

# Evolutionary red-teaming engine
from .evolution import (
    EliteScenario,
    MapElitesArchive,
    EvolutionEngine,
    EvolutionaryRunSummary,
    ScenarioMutator,
    PriceVolatilityMutator,
    InventoryScarcityMutator,
    BudgetConstraintMutator,
    VendorDropoutMutator,
    IndirectPromptInjectionMutator,
    SpoofedExecutiveMessageMutator,
    ConflictingSpecificationMutator,
    SemanticMutator,
    SemanticMutatorConfig,
)

# Causal analyzer & reporting
from .reporting import (
    CausalAnalyzer,
    CausalVulnerabilityFinding,
    DiagnosticMetrics,
    ReportGenerator,
)

__all__ = [
    # Substrates
    "Substrate",
    "ElementaryCA",
    "OuterTotalisticCA",
    "MultiStateCA",
    # MODES & Metrics
    "population",
    "density",
    "activity",
    "ActivityMetrics",
    "compute_bedau_packard_activity",
    "ComplexityMetrics",
    "compute_shannon_entropy",
    "compute_compressibility_ratio",
    "compute_complexity_metrics",
    "NoveltyMetrics",
    "compute_novelty_metrics",
    "EcologyMetrics",
    "label_connected_components",
    "compute_ecology_metrics",
    "MODESSummary",
    "analyze_modes",
    "classify_dynamic_regime",
    # Database
    "ExperimentDatabase",
    "ExperimentRecord",
    # Legacy CA
    "World",
    "Rule",
    "OuterTotalisticRule",
    "ConwayRule",
    "random_outer_totalistic_rule",
    "ExperimentConfig",
    "ExperimentResult",
    "run_experiment",
    "save_result",
    "plot_metrics",
    "animate_world",
    "TemporalSummary",
    "find_extinction_time",
    "persistence_ratio",
    "lag_autocorrelation",
    "find_exact_recurrence_period",
    "analyze_temporal_dynamics",
    # Sandbox
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
    # Evolution
    "EliteScenario",
    "MapElitesArchive",
    "EvolutionEngine",
    "EvolutionaryRunSummary",
    "ScenarioMutator",
    "PriceVolatilityMutator",
    "InventoryScarcityMutator",
    "BudgetConstraintMutator",
    "VendorDropoutMutator",
    "IndirectPromptInjectionMutator",
    "SpoofedExecutiveMessageMutator",
    "ConflictingSpecificationMutator",
    "SemanticMutator",
    "SemanticMutatorConfig",
    # Reporting
    "CausalAnalyzer",
    "CausalVulnerabilityFinding",
    "DiagnosticMetrics",
    "ReportGenerator",
]