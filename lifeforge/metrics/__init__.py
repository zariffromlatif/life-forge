"""Metrics package for LIFE FORGE, incorporating both basic CA metrics and the MODES framework."""
from __future__ import annotations

from .basic import population, density, activity
from .evolutionary_activity import ActivityMetrics, compute_bedau_packard_activity
from .complexity import (
    ComplexityMetrics,
    compute_shannon_entropy,
    compute_compressibility_ratio,
    compute_complexity_metrics,
)
from .novelty import NoveltyMetrics, compute_novelty_metrics
from .ecology import EcologyMetrics, label_connected_components, compute_ecology_metrics
from .modes import MODESSummary, analyze_modes, classify_dynamic_regime

__all__ = [
    # Basic
    "population",
    "density",
    "activity",
    # Activity (Bedau-Packard)
    "ActivityMetrics",
    "compute_bedau_packard_activity",
    # Complexity
    "ComplexityMetrics",
    "compute_shannon_entropy",
    "compute_compressibility_ratio",
    "compute_complexity_metrics",
    # Novelty
    "NoveltyMetrics",
    "compute_novelty_metrics",
    # Ecology
    "EcologyMetrics",
    "label_connected_components",
    "compute_ecology_metrics",
    # MODES
    "MODESSummary",
    "analyze_modes",
    "classify_dynamic_regime",
]
