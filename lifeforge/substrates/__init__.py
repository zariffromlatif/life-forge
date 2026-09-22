"""Substrates module for LIFE FORGE universes."""
from __future__ import annotations

from .base import Substrate
from .ca import ElementaryCA, OuterTotalisticCA, MultiStateCA

__all__ = [
    "Substrate",
    "ElementaryCA",
    "OuterTotalisticCA",
    "MultiStateCA",
]
