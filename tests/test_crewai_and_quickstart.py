"""Tests for the CrewAI adapter and the quickstart auto-detection module.

Every test runs with duck-typed fakes only: crewai is never imported, and no
LLM or network access is required.  Quickstart tests operate exclusively on
files created under ``tmp_path`` and never touch the real repository tree.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from lifeforge.adapters.crewai import ACTION_PROTOCOL, CrewAIAdapter
from lifeforge.cli.quickstart import (
    ADAPTER_CLASS_BY_FRAMEWORK,
    FRAMEWORK_IMPORTS,
    HARNESS_TEMPLATE,
    detect_target,
    find_agent_candidates,
    run_quickstart,
    scan_directory,
    write_harness,
)
from lifeforge.sandbox.agent import AgentAction, AgentInterface

# ----------------------------------------------------------------------
# Duck-typed CrewAI fakes
# ----------------------------------------------------------------------


class FakeCrew:
    """Stand-in for a CrewAI Crew object with a recording kickoff method."""

    def __init__(self, result: Any = "", error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def kickoff(self, inputs: dict[str, Any] | None = None) -> Any:
        self.calls.append({"inputs": inputs})
        if self.error is not None:
            raise self.error
        return self.result


class NoInputsCrew:
    """Crew whose kickoff takes no keyword arguments (TypeError fallback path)."""

    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls = 0

    def kickoff(self) -> Any:
        self.calls += 1
        return self.result


class FakeTask:
    """Minimal task object exposing a mutable description attribute."""

    def __init__(self, description: str = "Handle one purchasing step.") -> None:
        self.description = description


class FakeAgent:
    """Stand-in for a CrewAI Agent object with an execute_task method."""

    def __init__(self, result: Any) -> None:
        self.result = result
        self.tasks: list[Any] = []

    def execute_task(self, task: Any) -> Any:
        self.tasks.append(task)
        return self.result


def _tool_call_json() -> str:
    return (
        '{"action_type": "tool_call", "tool_name": "vendor_api", '
        '"arguments": {"vendor_id": "vendor_alphatech", "item": "server_h100"}, '
        '"thought": "Need a quote before ordering."}'
    )


# ----------------------------------------------------------------------
# CrewAI adapter tests
# ----------------------------------------------------------------------


def test_crewai_adapter_is_an_agent_interface() -> None:
    adapter = CrewAIAdapter(crew=FakeCrew("done"))
    assert isinstance(adapter, AgentInterface)
    assert adapter.name == "CrewAIAdapter"


def test_fenced_json_tool_call_is_parsed() -> None:
    crew = FakeCrew("Here is my next action:\n```json\n" + _tool_call_json() + "\n```\n")
    adapter = CrewAIAdapter(crew=crew)

    action = adapter.act({"inbox": []}, [])

    assert action.action_type == "tool_call"
    assert action.tool_name == "vendor_api"
    assert action.arguments == {"vendor_id": "vendor_alphatech", "item": "server_h100"}
    assert action.thought == "Need a quote before ordering."


def test_bare_json_object_is_parsed() -> None:
    crew = FakeCrew("Thinking... " + _tool_call_json() + " done.")
    adapter = CrewAIAdapter(crew=crew)

    action = adapter.act({"inbox": []}, [])

    assert action.action_type == "tool_call"
    assert action.tool_name == "vendor_api"
    assert action.arguments["vendor_id"] == "vendor_alphatech"


def test_plain_prose_becomes_finish_action() -> None:
    prose = "I cannot complete the purchase because the budget is exhausted."
    adapter = CrewAIAdapter(crew=FakeCrew(prose))

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert action.message == prose


def test_kickoff_exception_becomes_finish_action() -> None:
    crew = FakeCrew(error=RuntimeError("kickoff exploded"))
    adapter = CrewAIAdapter(crew=crew)

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert "kickoff exploded" in (action.message or "")
    assert "kickoff exploded" in (action.thought or "")


def test_kickoff_without_inputs_kwarg_falls_back() -> None:
    crew = NoInputsCrew('{"action_type": "finish", "message": "all done"}')
    adapter = CrewAIAdapter(crew=crew)

    action = adapter.act({}, [])

    assert crew.calls == 1
    assert action.action_type == "finish"
    assert action.message == "all done"


def test_json_finish_action_is_parsed() -> None:
    crew = FakeCrew('{"action_type": "finish", "message": "Procurement complete.", "thought": "done"}')
    adapter = CrewAIAdapter(crew=crew)

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert action.message == "Procurement complete."
    assert action.thought == "done"


def test_malformed_json_degrades_to_finish_without_raising() -> None:
    malformed = '{"action_type": "tool_call", "tool_name":'
    adapter = CrewAIAdapter(crew=FakeCrew(malformed))

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert action.message is not None
    assert malformed in action.message


def test_missing_tool_name_degrades_to_finish() -> None:
    adapter = CrewAIAdapter(crew=FakeCrew('{"action_type": "tool_call", "arguments": {}}'))

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert "tool_name" in (action.thought or "")


def test_non_dict_arguments_degrade_to_finish() -> None:
    payload = '{"action_type": "tool_call", "tool_name": "vendor_api", "arguments": "vendor_id=v1"}'
    adapter = CrewAIAdapter(crew=FakeCrew(payload))

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert "arguments" in (action.thought or "")


def test_unknown_action_type_degrades_to_finish() -> None:
    adapter = CrewAIAdapter(crew=FakeCrew('{"action_type": "dance", "message": "no"}'))

    action = adapter.act({}, [])

    assert action.action_type == "finish"


def test_dict_and_object_results_are_extracted() -> None:
    dict_crew = FakeCrew({"raw": '{"action_type": "finish", "message": "from dict"}'})
    object_crew = FakeCrew(SimpleNamespace(raw='{"action_type": "finish", "message": "from object"}'))

    assert CrewAIAdapter(crew=dict_crew).act({}, []).message == "from dict"
    assert CrewAIAdapter(crew=object_crew).act({}, []).message == "from object"


def test_protocol_and_observation_are_sent_to_the_crew() -> None:
    crew = FakeCrew('{"action_type": "finish", "message": "ok"}')
    adapter = CrewAIAdapter(crew=crew, inputs_key="task_input")
    history = [
        {
            "step": 0,
            "action": {
                "action_type": "tool_call",
                "tool_name": "vendor_api",
                "arguments": {"vendor_id": "vendor_alphatech"},
            },
            "result": {"success": True, "output": {}, "error": None},
        }
    ]
    observation = {
        "inbox": [{"from": "procurement_lead", "subject": "Buy", "body": "Please procure 2 units."}],
        "last_tool_result": {"success": True, "output": {"unit_price": 28000.0}, "error": None},
    }

    adapter.act(observation, history)

    assert len(crew.calls) == 1
    inputs = crew.calls[0]["inputs"]
    assert inputs is not None and "task_input" in inputs
    prompt = inputs["task_input"]
    assert ACTION_PROTOCOL in prompt
    assert "Please procure 2 units." in prompt
    assert "LAST TOOL RESULT" in prompt
    assert "PRIOR STEPS" in prompt
    assert "vendor_api" in prompt


def test_agent_and_task_route_appends_protocol_without_mutating_task() -> None:
    agent = FakeAgent('{"action_type": "finish", "message": "agent route ok"}')
    task = FakeTask("Original description.")
    adapter = CrewAIAdapter(agent=agent, task=task, name="route-agent")

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert action.message == "agent route ok"
    assert len(agent.tasks) == 1
    sent_task = agent.tasks[0]
    assert "Original description." in sent_task.description
    assert ACTION_PROTOCOL in sent_task.description
    # The caller's task object must not be mutated.
    assert task.description == "Original description."


def test_construction_without_crew_or_agent_raises_value_error() -> None:
    with pytest.raises(ValueError):
        CrewAIAdapter()


def test_construction_with_agent_but_no_task_raises_value_error() -> None:
    with pytest.raises(ValueError):
        CrewAIAdapter(agent=FakeAgent(""))


def test_reset_is_callable_and_idempotent() -> None:
    adapter = CrewAIAdapter(crew=FakeCrew('{"action_type": "finish", "message": "ok"}'))

    assert adapter.reset() is None
    assert adapter.reset() is None

    action = adapter.act({}, [])
    assert action.action_type == "finish"

    adapter.reset()
    adapter.reset()
    action_after = adapter.act({}, [])
    assert isinstance(action_after, AgentAction)


def test_max_output_chars_truncates_free_form_text() -> None:
    adapter = CrewAIAdapter(crew=FakeCrew("x" * 500), max_output_chars=50)

    action = adapter.act({}, [])

    assert action.action_type == "finish"
    assert action.message is not None
    assert len(action.message) == 50


# ----------------------------------------------------------------------
# Quickstart: helpers
# ----------------------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _framework_sample(framework: str) -> str:
    """One realistic import line per supported framework label."""
    samples = {
        "langchain": "from langchain_core.tools import tool\n",
        "langgraph": "from langgraph.graph import StateGraph\n",
        "crewai": "from crewai import Crew\n",
        "autogen": "from autogen import AssistantAgent\n",
        "llama_index": "from llama_index.core import VectorStoreIndex\n",
        "smolagents": "from smolagents import CodeAgent\n",
        "openai_agents": "from agents import Agent\n",
    }
    return samples[framework]


# ----------------------------------------------------------------------
# Quickstart: scan_directory
# ----------------------------------------------------------------------


def test_scan_directory_finds_each_framework_once_and_skips_venv(tmp_path: Path) -> None:
    for framework in FRAMEWORK_IMPORTS:
        _write(tmp_path / f"{framework}_app.py", _framework_sample(framework))

    # Duplicate import inside one file: one detection, first hit line.
    _write(
        tmp_path / "duplicate.py",
        "# not an import below\nimport langgraph\nimport langgraph.checkpoint\n",
    )
    # Commented-out import must be ignored.
    _write(tmp_path / "commented.py", "# from crewai import Crew\nVALUE = 1\n")
    # Skipped directories must never be scanned.
    _write(tmp_path / ".venv" / "hidden.py", "from crewai import Crew\n")
    _write(tmp_path / "node_modules" / "hidden.py", "from autogen import AssistantAgent\n")

    detections = scan_directory(tmp_path)

    keys = [(d.framework, d.path, d.line) for d in detections]
    assert keys == sorted(keys)
    assert len({(d.framework, d.path) for d in detections}) == len(detections)
    for framework in FRAMEWORK_IMPORTS:
        assert any(d.framework == framework for d in detections)
    assert not any(".venv" in d.path or "node_modules" in d.path for d in detections)

    langgraph_hits = [d for d in detections if d.path == "duplicate.py"]
    assert len(langgraph_hits) == 1
    assert langgraph_hits[0].framework == "langgraph"
    assert langgraph_hits[0].line == 2

    crewai_hits = [d for d in detections if d.framework == "crewai"]
    assert len(crewai_hits) == 1
    assert crewai_hits[0].path == "crewai_app.py"


def test_scan_directory_requires_import_context_for_bare_prefixes(tmp_path: Path) -> None:
    _write(
        tmp_path / "not_imports.py",
        "sub_agents = []\ncrew = object()\nAGENTS = 'agents'\nfrom langchain.agents import AgentExecutor\n",
    )

    detections = scan_directory(tmp_path)

    frameworks = {(d.framework, d.path) for d in detections}
    assert ("langchain", "not_imports.py") in frameworks
    assert ("openai_agents", "not_imports.py") not in frameworks


def test_scan_directory_missing_directory_returns_empty(tmp_path: Path) -> None:
    assert scan_directory(tmp_path / "does_not_exist") == []


# ----------------------------------------------------------------------
# Quickstart: find_agent_candidates
# ----------------------------------------------------------------------


def test_find_agent_candidates_assignment_and_function(tmp_path: Path) -> None:
    module = tmp_path / "agent_module.py"
    _write(
        module,
        "\n".join(
            [
                "executor = AgentExecutor(agent=None, tools=[])",
                "",
                "def my_agent():",
                "    return None",
                "",
                "def _private_helper():",
                "    return None",
                "",
            ]
        ),
    )

    candidates = find_agent_candidates(module)

    assert any(c.endswith(":executor") for c in candidates)
    assert any(c.endswith(":my_agent") for c in candidates)
    assert not any("_private_helper" in c for c in candidates)

    executor_index = next(i for i, c in enumerate(candidates) if c.endswith(":executor"))
    function_index = next(i for i, c in enumerate(candidates) if c.endswith(":my_agent"))
    assert executor_index < function_index
    assert all(c.startswith(str(module)) for c in candidates)


def test_find_agent_candidates_accepts_name_agent(tmp_path: Path) -> None:
    module = tmp_path / "plain_agent.py"
    _write(module, "agent = build_agent()\n")

    candidates = find_agent_candidates(module)

    assert candidates == [f"{module}:agent"]


def test_find_agent_candidates_syntax_error_returns_empty(tmp_path: Path) -> None:
    broken = tmp_path / "broken.py"
    _write(broken, "def broken(:\n    pass\n")

    assert find_agent_candidates(broken) == []


def test_find_agent_candidates_missing_file_returns_empty(tmp_path: Path) -> None:
    assert find_agent_candidates(tmp_path / "missing.py") == []


# ----------------------------------------------------------------------
# Quickstart: detect_target
# ----------------------------------------------------------------------


def test_detect_target_prefers_highest_priority_framework(tmp_path: Path) -> None:
    _write(
        tmp_path / "crew_file.py",
        "from crewai import Crew\nmy_crew = Crew(agents=[], tasks=[])\n",
    )
    _write(
        tmp_path / "autogen_file.py",
        "from autogen import AssistantAgent\nassistant = Agent('helper')\n",
    )
    _write(
        tmp_path / "graph_file.py",
        "from langgraph.graph import StateGraph\napp = StateGraph(dict)\n",
    )

    best, detections, candidates = detect_target(tmp_path)

    assert best == "graph_file.py:app"
    assert best in candidates
    assert any(d.framework == "langgraph" for d in detections)
    assert any(d.framework == "crewai" for d in detections)


def test_detect_target_falls_back_to_file_without_detection(tmp_path: Path) -> None:
    _write(tmp_path / "custom_agent.py", "def my_agent():\n    return None\n")

    best, detections, candidates = detect_target(tmp_path)

    assert detections == []
    assert best == "custom_agent.py:my_agent"
    assert candidates == ["custom_agent.py:my_agent"]


def test_detect_target_returns_none_for_empty_directory(tmp_path: Path) -> None:
    best, detections, candidates = detect_target(tmp_path)

    assert best is None
    assert detections == []
    assert candidates == []


# ----------------------------------------------------------------------
# Quickstart: harness generation
# ----------------------------------------------------------------------


def test_write_harness_writes_and_respects_force(tmp_path: Path) -> None:
    _write(tmp_path / "agent_def.py", "def my_agent():\n    return None\n")

    harness_path = write_harness(tmp_path, "crewai", "agent_def.py:my_agent")

    assert harness_path == tmp_path / "lifeforge_harness.py"
    assert harness_path.exists()
    source = harness_path.read_text(encoding="utf-8")
    assert "CrewAIAdapter" in source
    assert "lifeforge.adapters.crewai" in source
    assert "agent_def.py" in source
    compile(source, str(harness_path), "exec")

    with pytest.raises(FileExistsError):
        write_harness(tmp_path, "crewai", "agent_def.py:my_agent")

    harness_path_again = write_harness(tmp_path, "crewai", "agent_def.py:my_agent", force=True)
    assert harness_path_again.exists()


def test_write_harness_invalid_spec_raises_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        write_harness(tmp_path, "crewai", "no_colon_here")


@pytest.mark.parametrize("framework", sorted(FRAMEWORK_IMPORTS))
def test_harness_template_compiles_for_every_framework(framework: str) -> None:
    source = HARNESS_TEMPLATE.format(
        framework=framework,
        adapter_class=ADAPTER_CLASS_BY_FRAMEWORK.get(framework, ""),
        module="user_agent.py",
        attribute="agent",
        created="2026-01-01",
    )

    compile(source, "<lifeforge_harness>", "exec")
    assert framework in source


def test_harness_template_degrades_clearly_without_adapter(tmp_path: Path) -> None:
    _write(tmp_path / "agent_def.py", "def my_agent():\n    return None\n")

    harness_path = write_harness(tmp_path, "autogen", "agent_def.py:my_agent")
    source = harness_path.read_text(encoding="utf-8")
    compile(source, str(harness_path), "exec")

    assert "No built-in LIFE FORGE adapter exists for framework" in source
    assert 'ADAPTER_CLASS = ""' in source


# ----------------------------------------------------------------------
# Quickstart: run_quickstart orchestration
# ----------------------------------------------------------------------


def test_run_quickstart_dry_run_empty_directory_returns_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run_quickstart(tmp_path, dry_run=True)

    assert exit_code == 1
    assert not (tmp_path / "lifeforge_harness.py").exists()

    output = capsys.readouterr().out
    assert "[FAIL]" in output
    assert "langgraph" in output
    assert output.isascii()


def test_run_quickstart_dry_run_skips_harness_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "crew_agent.py", "from crewai import Crew\nagent = build_crew()\n")

    exit_code = run_quickstart(tmp_path, dry_run=True)

    assert exit_code == 0
    assert not (tmp_path / "lifeforge_harness.py").exists()

    output = capsys.readouterr().out
    assert "[DETECT]" in output
    assert "[CONFIGURE]" in output
    assert "crewai" in output
    assert output.isascii()


def test_run_quickstart_fails_when_only_unrelated_files_exist(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "no_framework.py", "VALUE = 1\n")

    exit_code = run_quickstart(tmp_path)

    assert exit_code == 1
    assert not (tmp_path / "lifeforge_harness.py").exists()
    output = capsys.readouterr().out
    assert "[FAIL]" in output
    assert output.isascii()
