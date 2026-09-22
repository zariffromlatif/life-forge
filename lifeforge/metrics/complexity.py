"""Complexity metrics: Shannon entropy, algorithmic compressibility, and the Anti-Garbage Complexity Gap."""
from __future__ import annotations

import zlib
from dataclasses import dataclass
import numpy as np


@dataclass(frozen=True)
class ComplexityMetrics:
    """Quantitative complexity metrics separating noise from organized dynamics."""

    shannon_entropy: float
    compressibility_ratio: float  # Compressed bytes / raw bytes (lower = more compressible)
    complexity_gap: float  # H * (1 - C): peaks for Class IV, collapses for noise
    statistical_complexity: float  # Normalized 4 * H * (1 - H) * (1 - C)
    is_chaotic_noise: bool
    is_static_or_trivial: bool


def compute_shannon_entropy(state: np.ndarray, num_states: int = 2) -> float:
    """Compute Shannon entropy H in [0, 1] normalized by log2(num_states)."""
    counts = np.bincount(state.ravel(), minlength=num_states)
    probs = counts / np.sum(counts)
    nonzero_probs = probs[probs > 0]
    raw_entropy = -np.sum(nonzero_probs * np.log2(nonzero_probs))
    max_entropy = np.log2(max(2, num_states))
    return max(0.0, float(raw_entropy / max_entropy))


def compute_compressibility_ratio(state: np.ndarray, num_states: int = 2) -> float:
    """
    Compute algorithmic compression ratio C = len(compressed) / len(raw) using zlib.
    For binary states, bits are packed into bytes to properly measure true Kolmogorov/entropy compressibility.
    A value near 1.0 (or > 1.0 due to headers) indicates incompressible noise.
    A low value indicates highly structured patterns or sparse/repetitive structures.
    """
    if state.size == 0:
        return 0.0

    if num_states <= 2:
        raw_bytes = np.packbits(state.astype(bool)).tobytes()
    else:
        raw_bytes = np.ascontiguousarray(state).tobytes()

    if len(raw_bytes) == 0:
        return 0.0

    compressed_bytes = zlib.compress(raw_bytes, level=6)
    # Clip to max 1.0 for normalized metric
    return float(min(1.0, len(compressed_bytes) / len(raw_bytes)))


def compute_complexity_metrics(state: np.ndarray, num_states: int = 2) -> ComplexityMetrics:
    """
    Evaluate structural complexity.
    Mathematically eliminates the 'beautiful garbage' failure mode:
    - Class I/II: Low entropy (H -> 0), Low complexity.
    - Class III: High entropy (H -> 1), but high compressibility ratio (C -> 1). Complexity gap collapses to ~0.
    - Class IV: Intermediate entropy with structured compressibility. Complexity gap is high.
    """
    h = compute_shannon_entropy(state, num_states=num_states)
    c = compute_compressibility_ratio(state, num_states=num_states)

    # Complexity gap: non-random organized structure
    gap = float(h * max(0.0, 1.0 - c))
    stat_comp = float(4.0 * h * (1.0 - h) * max(0.0, 1.0 - c))

    # Diagnostic flags:
    # Chaotic noise has high entropy (H > 0.85) and cannot be packed/compressed (C > 0.80)
    is_noise = (h > 0.85) and (c > 0.80)
    is_trivial = (h < 0.05) or (np.sum(state > 0) == 0)

    return ComplexityMetrics(
        shannon_entropy=h,
        compressibility_ratio=c,
        complexity_gap=gap,
        statistical_complexity=stat_comp,
        is_chaotic_noise=is_noise,
        is_static_or_trivial=is_trivial,
    )
