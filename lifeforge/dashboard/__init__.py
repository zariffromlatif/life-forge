"""LIFE FORGE Interactive Web Dashboard.

Provides a zero-dependency, local visual flight simulator command center
for exploring MAP-Elites behavior archives, model showdowns, and exploit traces.
"""
from __future__ import annotations

from lifeforge.dashboard.server import start_dashboard, create_server

__all__ = ["start_dashboard", "create_server"]
