"""Ecological metrics: spatial organism clustering, entity size diversity, and persistence."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import numpy as np


@dataclass(frozen=True)
class EcologyMetrics:
    """Ecological and structural diversity metrics."""

    cluster_count: int  # Number of distinct spatial entities/organisms
    mean_cluster_size: float
    max_cluster_size: int
    cluster_diversity: float  # Shannon entropy of cluster size distribution
    persistence_ratio: float  # Fraction of steps with active life
    extinction_step: int | None
    spatial_dispersion: float  # Measure of spatial segregation vs clumping


def label_connected_components(grid: np.ndarray) -> tuple[int, list[int]]:
    """
    Find 8-connected components of active cells in a 2D grid.
    Returns (num_clusters, list_of_cluster_sizes).
    Pure numpy implementation (zero external dependency).
    """
    if grid.ndim != 2:
        return 0, []

    h, w = grid.shape
    visited = np.zeros((h, w), dtype=bool)
    active = (grid > 0)
    cluster_sizes: list[int] = []

    for r in range(h):
        for c in range(w):
            if active[r, c] and not visited[r, c]:
                # Run BFS
                size = 0
                queue = deque([(r, c)])
                visited[r, c] = True

                while queue:
                    curr_r, curr_c = queue.popleft()
                    size += 1

                    # 8-neighbors (with periodic boundary)
                    for dr in (-1, 0, 1):
                        for dc in (-1, 0, 1):
                            if dr == 0 and dc == 0:
                                continue
                            nr = (curr_r + dr) % h
                            nc = (curr_c + dc) % w
                            if active[nr, nc] and not visited[nr, nc]:
                                visited[nr, nc] = True
                                queue.append((nr, nc))

                cluster_sizes.append(size)

    return len(cluster_sizes), cluster_sizes


def compute_ecology_metrics(trajectory: list[np.ndarray]) -> EcologyMetrics:
    """Evaluate ecological structure, persistence, and organism clustering."""
    if not trajectory:
        raise ValueError("Trajectory cannot be empty.")

    final_state = trajectory[-1]
    cluster_count, cluster_sizes = label_connected_components(final_state)

    mean_size = float(np.mean(cluster_sizes)) if cluster_sizes else 0.0
    max_size = int(np.max(cluster_sizes)) if cluster_sizes else 0

    # Shannon diversity of cluster sizes
    cluster_div = 0.0
    if cluster_sizes:
        total = sum(cluster_sizes)
        probs = np.array(cluster_sizes) / total
        cluster_div = float(-np.sum(probs * np.log2(probs + 1e-12)))

    # Persistence across trajectory
    populations = [int(np.sum(s > 0)) for s in trajectory]
    active_steps = sum(1 for p in populations if p > 0)
    persistence = float(active_steps / len(populations))

    extinction: int | None = None
    for step, p in enumerate(populations):
        if p == 0:
            extinction = step
            break

    # Spatial dispersion: variance in row/column marginal densities
    row_densities = np.mean(final_state > 0, axis=1) if final_state.ndim == 2 else np.array([0.0])
    dispersion = float(np.std(row_densities))

    return EcologyMetrics(
        cluster_count=cluster_count,
        mean_cluster_size=mean_size,
        max_cluster_size=max_size,
        cluster_diversity=cluster_div,
        persistence_ratio=persistence,
        extinction_step=extinction,
        spatial_dispersion=dispersion,
    )
