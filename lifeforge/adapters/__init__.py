"""Adapter layer for integrating third-party agent frameworks with LIFE FORGE.

Each adapter wraps an external executor object and exposes it as a standard
AgentInterface so it can be passed directly to SandboxRunner or EvolutionEngine.

Importing this package does NOT import langchain, langgraph, crewai,
autogen, or smolagents.  Those dependencies are loaded lazily inside each
adapter so that LIFE FORGE works even when only a subset of optional
frameworks is installed.
"""
from __future__ import annotations

from lifeforge.adapters.autogen import AutoGenAdapter
from lifeforge.adapters.crewai import CrewAIAdapter
from lifeforge.adapters.generic import CallableAdapter
from lifeforge.adapters.langchain import LangChainAdapter
from lifeforge.adapters.langgraph import LangGraphAdapter
from lifeforge.adapters.smolagents import SmolAgentsAdapter

__all__ = [
    "AutoGenAdapter",
    "CallableAdapter",
    "CrewAIAdapter",
    "LangChainAdapter",
    "LangGraphAdapter",
    "SmolAgentsAdapter",
]
