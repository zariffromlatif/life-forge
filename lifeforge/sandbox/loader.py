"""Dynamic agent loader for importing user-defined agents and functions."""
from __future__ import annotations

import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Any, Callable

from lifeforge.sandbox.agent import AgentAction, AgentInterface, CallableAgentAdapter


class AgentLoadError(Exception):
    """Raised when an agent target specification cannot be resolved or loaded."""
    pass


def load_agent_from_spec(spec: str, name: str | None = None) -> AgentInterface:
    """
    Load an AgentInterface instance from a specification string.

    Supported formats:
        - "path/to/file.py:agent_instance"
        - "path/to/file.py:AgentClass"
        - "path/to/file.py:agent_function"
        - "my_module.submodule:agent_object"

    Args:
        spec: Target specifier in 'path_or_module:attribute' format.
        name: Optional custom name to assign to the loaded agent.

    Returns:
        An instance implementing AgentInterface.

    Raises:
        AgentLoadError: If file not found, attribute missing, or target cannot be adapted.
    """
    if ":" not in spec:
        raise AgentLoadError(
            f"Invalid agent specification '{spec}'. Format must be 'path/or/module:attribute'."
        )

    module_part, attr_name = spec.rsplit(":", 1)
    module_path = Path(module_part)

    if module_path.is_file() or module_part.endswith(".py"):
        # Load from file system path
        if not module_path.exists():
            raise AgentLoadError(f"Target agent file not found: {module_path.resolve()}")

        module_name = f"_lifeforge_user_agent_{module_path.stem}"
        spec_obj = importlib.util.spec_from_file_location(module_name, str(module_path))
        if spec_obj is None or spec_obj.loader is None:
            raise AgentLoadError(f"Could not load module specification from: {module_path}")

        module = importlib.util.module_from_spec(spec_obj)
        try:
            spec_obj.loader.exec_module(module)
        except Exception as exc:
            raise AgentLoadError(f"Error executing agent module '{module_path}': {exc}") from exc
    else:
        # Load from standard python import path
        try:
            module = importlib.import_module(module_part)
        except Exception as exc:
            raise AgentLoadError(f"Could not import module '{module_part}': {exc}") from exc

    if not hasattr(module, attr_name):
        raise AgentLoadError(
            f"Module '{module_part}' does not define attribute '{attr_name}'."
        )

    target = getattr(module, attr_name)

    # Case 1: Target is an instance of AgentInterface
    if isinstance(target, AgentInterface):
        if name:
            target.name = name
        return target

    # Case 2: Target is an uninstantiated class inheriting from AgentInterface
    if inspect.isclass(target) and issubclass(target, AgentInterface):
        try:
            instance = target()
            if name:
                instance.name = name
            return instance
        except Exception as exc:
            raise AgentLoadError(
                f"Failed to instantiate AgentInterface class '{target.__name__}': {exc}"
            ) from exc

    # Case 3: Target is a callable function: (observation, history) -> AgentAction
    if callable(target):
        agent_name = name or getattr(target, "__name__", "CustomCallableAgent")
        return CallableAgentAdapter(fn=target, name=agent_name)

    raise AgentLoadError(
        f"Attribute '{attr_name}' of type {type(target).__name__} is neither an AgentInterface, "
        "a subclass of AgentInterface, nor a callable."
    )
