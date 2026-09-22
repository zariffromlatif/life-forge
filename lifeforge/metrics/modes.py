"""Unified MODES measurement framework aggregating Activity, Complexity, Novelty, and Ecology."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import numpy as np

from .evolutionary_activity import ActivityMetrics, compute_bedau_packard_activity
from .complexity import ComplexityMetrics, compute_complexity_metrics
from .ecology import EcologyMetrics, compute_ecology_metrics
from .novelty import NoveltyMetrics, compute_novelty_metrics


@dataclass(frozen=True)
class MODESSummary:
    """Complete 4-pillar MODES research vector quantifying open-ended evolutionary potential."""

    # 1. Activity (Bedau-Packard)
    cumulative_activity: float
    excess_activity: float
    max_component_activity: int

    # 2. Complexity (Anti-Garbage Gap)
    shannon_entropy: float
    compressibility_ratio: float
    complexity_gap: float
    statistical_complexity: float

    # 3. Novelty (State Innovation)
    unique_patterns_count: int
    pattern_growth_rate: float
    has_cumulative_novelty: bool

    # 4. Ecology (Clusters & Persistence)
    cluster_count: int
    mean_cluster_size: float
    cluster_diversity: float
    persistence_ratio: float
    extinction_step: int | None

    # Classified Dynamic Regime
    wolfram_class: str  # "Class I (Homogeneous)", "Class II (Periodic)", "Class III (Chaotic Noise)", "Class IV (Complex / Open-Ended)"
    is_class_iv_candidate: bool

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to a JSON-serializable dictionary."""
        return asdict(self)


def classify_dynamic_regime(
    activity: ActivityMetrics,
    complexity: ComplexityMetrics,
    novelty: NoveltyMetrics,
    ecology: EcologyMetrics,
) -> tuple[str, bool]:
    """
    Classify the trajectory into Wolfram dynamic classes using quantitative MODES thresholds.
    Eliminates human visual subjectivity:
    - Class I: Rapid extinction or empty state (persistence = 0 or entropy < 0.02).
    - Class II: Low activity, periodic/static, zero pattern growth, highly compressible (C < 0.20, gap < 0.05).
    - Class III: High entropy (H > 0.80), poor compressibility (C > 0.70), complexity gap collapses.
    - Class IV: High complexity gap (gap > 0.15), multi-cluster ecology, persistent evolutionary activity.
    """
    if ecology.persistence_ratio < 0.1 or complexity.is_static_or_trivial:
        return "Class I (Homogeneous / Extinct)", False

    if complexity.is_chaotic_noise:
        return "Class III (Chaotic Noise / Beautiful Garbage)", False

    # Check for Class IV: high complexity gap, non-zero activity, structured entities
    if (
        complexity.complexity_gap > 0.10
        and activity.cumulative_activity > 100
        and ecology.cluster_count >= 1
    ):
        return "Class IV (Complex / Open-Ended)", True

    # Check if static or periodic
    if novelty.pattern_growth_rate == 0.0 and complexity.compressibility_ratio < 0.35:
        return "Class II (Periodic / Simple Stable)", False

    # Default moderate complex or periodic
    if complexity.complexity_gap > 0.05:
        return "Class IV (Complex / Open-Ended)", True

    return "Class II (Periodic / Simple Stable)", False


def analyze_modes(
    trajectory: list[np.ndarray],
    shadow_trajectory: list[np.ndarray] | None = None,
) -> MODESSummary:
    """Analyze a simulation trajectory across all four MODES pillars."""
    if not trajectory:
        raise ValueError("Trajectory cannot be empty.")

    if trajectory[0].ndim == 1:
        eval_state = np.stack(trajectory, axis=0)
    else:
        eval_state = trajectory[-1]

    activity = compute_bedau_packard_activity(trajectory, shadow_trajectory)
    complexity = compute_complexity_metrics(eval_state)
    novelty = compute_novelty_metrics(trajectory)
    ecology = compute_ecology_metrics(trajectory)

    w_class, is_c4 = classify_dynamic_regime(activity, complexity, novelty, ecology)

    return MODESSummary(
        cumulative_activity=activity.cumulative_activity,
        excess_activity=activity.excess_evolutionary_activity,
        max_component_activity=activity.max_component_activity,
        shannon_entropy=complexity.shannon_entropy,
        compressibility_ratio=complexity.compressibility_ratio,
        complexity_gap=complexity.complexity_gap,
        statistical_complexity=complexity.statistical_complexity,
        unique_patterns_count=novelty.unique_patterns_count,
        pattern_growth_rate=novelty.pattern_growth_rate,
        has_cumulative_novelty=novelty.has_cumulative_novelty,
        cluster_count=ecology.cluster_count,
        mean_cluster_size=ecology.mean_cluster_size,
        cluster_diversity=ecology.cluster_diversity,
        persistence_ratio=ecology.persistence_ratio,
        extinction_step=ecology.extinction_step,
        wolfram_class=w_class,
        is_class_iv_candidate=is_c4,
    )
