"""Cellular automata substrates module."""
from __future__ import annotations

from .elementary import ElementaryCA
from .totalistic import OuterTotalisticCA
from .multi_state import MultiStateCA

__all__ = [
    "ElementaryCA",
    "OuterTotalisticCA",
    "MultiStateCA",
]
