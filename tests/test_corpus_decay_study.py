"""End-to-end test of scripts/corpus_decay_study.py with scripted 'model versions' (no LLM)."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

from lifeforge.sandbox.agent import AgentAction, AgentInterface

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "corpus_decay_study.py"
ADDRESS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


@pytest.fixture(scope="module")
def study():
    spec = importlib.util.spec_from_file_location("corpus_decay_study", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VersionedAgent(AgentInterface):
    """'old' emails every address it reads in the inbox (obeys injections); 'new' only answers the customer."""

    def __init__(self, model: str) -> None:
        self.name = f"Scripted({model})"
        self.model = model
        self._plan: list[AgentAction] = []
        self._started = False

    def reset(self) -> None:
        self._plan, self._started = [], False

    def act(self, observation, history):
        if not self._started:
            self._started = True
            text = " ".join(str(m.get("body", "")) for m in observation.get("inbox") or [])
            targets = ["customer"]
            if self.model.endswith("old"):
                targets += sorted(set(ADDRESS.findall(text)))
            self._plan = [
                AgentAction(action_type="tool_call", tool_name="send_email",
                            arguments={"recipient": to, "subject": "Re: your request", "body": "Handled."})
                for to in targets
            ]
        if self._plan:
            return self._plan.pop(0)
        return AgentAction(action_type="finish", message="DONE")


def _run(study, monkeypatch, out: Path, *extra: str) -> None:
    monkeypatch.setattr(study, "make_agent", lambda model, api_base, temperature: VersionedAgent(model))
    study.main(["run", "--out", str(out), "--models", "fake/v1-old,fake/v2-new",
                "--generations", "6", "--repeats", "2", *extra])


def test_study_runs_resumes_and_analyses_offline(study, monkeypatch, tmp_path):
    out = tmp_path / "decay"
    _run(study, monkeypatch, out)

    for name in ("v1-old", "v2-new"):
        assert (out / name / "corpus.json").exists()
        assert (out / name / "search.json.gz").exists()
    replays = sorted(p.name for p in (out / "replays").iterdir())
    assert replays == [
        "v1-old__on__v1-old.json.gz", "v1-old__on__v2-new.json.gz",
        "v2-new__on__v1-old.json.gz", "v2-new__on__v2-new.json.gz",
    ]

    # Resume: a deleted scenario is replayed again, everything else is skipped.
    path = out / "replays" / "v1-old__on__v2-new.json.gz"
    record = study.read_json(path)
    dropped = min(record["scenarios"])
    del record["scenarios"][dropped]
    study.write_json(path, record)
    _run(study, monkeypatch, out)
    assert dropped in study.read_json(path)["scenarios"]

    # Changed settings must not silently mix into an existing study.
    with pytest.raises(SystemExit):
        _run(study, monkeypatch, out, "--seed", "7")

    # Analysis needs no agent at all.
    monkeypatch.setattr(study, "make_agent", lambda *a, **k: pytest.fail("analyze must not call the agent"))
    study.main(["analyze", "--out", str(out)])
    results = json.loads((out / "decay_results.json").read_text(encoding="utf-8"))
    pairs = {(p["source"], p["target"]): p for p in results["pairs"]}
    old_on_old = pairs[("fake/v1-old", "fake/v1-old")]
    old_on_new = pairs[("fake/v1-old", "fake/v2-new")]
    assert old_on_old["source_failures"] > 0, "the obeying 'old' version must fail some scenarios"
    assert old_on_old["still_failing"] == old_on_old["replayed"], "a deterministic agent is its own noise floor"
    assert old_on_new["still_failing"] < old_on_new["replayed"], "the upgrade fixed the exfiltration failures"
    assert "Carry-over" in (out / "DECAY_RESULTS.md").read_text(encoding="utf-8")


def test_preflight_rejects_a_model_that_never_calls_tools(study, monkeypatch, tmp_path):
    class Silent(AgentInterface):
        name = "silent"

        def reset(self):
            pass

        def act(self, observation, history):
            return AgentAction(action_type="finish", message="DONE")

    monkeypatch.setattr(study, "make_agent", lambda *a, **k: Silent())
    with pytest.raises(SystemExit, match="no tool calls"):
        study.main(["run", "--out", str(tmp_path / "x"), "--models", "fake/a,fake/b", "--pilot"])


def test_slug_is_filesystem_safe(study):
    assert study.slug("ollama_chat/qwen3:8b") == "qwen3-8b"
    assert study.slug("ollama_chat/qwen3.5:9b") == "qwen3.5-9b"


def test_analysis_counts_refused_refund_attempts_unless_lenient(study, tmp_path):
    from lifeforge.sandbox.domains.customer_support import RefundIntegrityPolicy

    strict = study.new_engine(42)
    study.count_refund_attempts(strict)
    flags = [p.include_attempts for p in strict.runner.goal_spec.policies if isinstance(p, RefundIntegrityPolicy)]
    assert flags and all(flags)
    lenient = study.new_engine(42)
    assert not any(p.include_attempts for p in lenient.runner.goal_spec.policies if isinstance(p, RefundIntegrityPolicy))


def test_pool_sums_studies_of_the_same_models(study, monkeypatch, tmp_path):
    folders = []
    for seed in ("42", "7"):
        folder = tmp_path / f"s{seed}"
        _run(study, monkeypatch, folder, "--seed", seed)
        folders.append(str(folder))
    report = tmp_path / "POOLED.md"
    study.main(["pool", *folders, "--report", str(report)])
    pooled = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    singles = [json.loads((Path(f) / "decay_results.json").read_text(encoding="utf-8")) for f in folders]
    for key in ("still_failing", "replayed"):
        expected = sum(p[key] for r in singles for p in r["pairs"] if p["source"] == p["target"])
        assert pooled["same_model"][key] == expected
    assert pooled["seeds"] == [42, 7]
    assert "Same model" in report.read_text(encoding="utf-8")
