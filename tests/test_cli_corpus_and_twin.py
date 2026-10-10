"""CLI tests: surface record/replay gate and compile-domain --from-mcp."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EXAMPLE_MANIFEST = REPO / "examples" / "mcp_manifest_example.json"


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "lifeforge.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )


def test_record_then_replay_gates_on_regression(tmp_path: Path):
    record = _cli("surface", "--record", "--hardened", "--scenarios", "15", "--out", "base.json", cwd=tmp_path)
    assert record.returncode == 0, record.stderr
    snapshot = json.loads((tmp_path / "base.json").read_text(encoding="utf-8"))
    assert snapshot["corpus"]["entries"]

    same = _cli("surface", "--baseline", "base.json", "--hardened", "--scenarios", "15", "--out", "same.md", "--fail-on-regression", cwd=tmp_path)
    assert same.returncode == 0, same.stdout + same.stderr
    assert "Verdict: UNCHANGED" in (tmp_path / "same.md").read_text(encoding="utf-8")

    worse = _cli("surface", "--baseline", "base.json", "--scenarios", "15", "--out", "worse.md", "--json", "--fail-on-regression", cwd=tmp_path)
    assert worse.returncode == 1
    report = (tmp_path / "worse.md").read_text(encoding="utf-8")
    assert "Verdict: REGRESSED" in report
    assert json.loads((tmp_path / "worse.json").read_text(encoding="utf-8"))["replay"]["regressed"]


def test_baseline_without_corpus_falls_back_with_a_warning(tmp_path: Path):
    _cli("surface", "--record", "--scenarios", "10", "--out", "base.json", cwd=tmp_path)
    data = json.loads((tmp_path / "base.json").read_text(encoding="utf-8"))
    data.pop("corpus")
    (tmp_path / "old.json").write_text(json.dumps(data), encoding="utf-8")
    result = _cli("surface", "--baseline", "old.json", "--scenarios", "10", "--out", "diff.md", cwd=tmp_path)
    assert result.returncode == 0
    assert "no regression corpus" in result.stdout


def test_compile_domain_from_mcp_writes_a_valid_spec(tmp_path: Path):
    generated = _cli(
        "compile-domain", "--from-mcp", str(EXAMPLE_MANIFEST), "--out", "twin.json", "--task", "Look up ORD-1", cwd=tmp_path
    )
    assert generated.returncode == 0, generated.stdout + generated.stderr
    spec = json.loads((tmp_path / "twin.json").read_text(encoding="utf-8"))
    assert spec["world"]["inbox"][0]["body"] == "Look up ORD-1"
    check = _cli("compile-domain", "--spec", "twin.json", "--check", cwd=tmp_path)
    assert check.returncode == 0, check.stdout + check.stderr


def test_compile_domain_requires_spec_or_from_mcp(tmp_path: Path):
    assert _cli("compile-domain", cwd=tmp_path).returncode == 1
    assert _cli("compile-domain", "--from-mcp", str(EXAMPLE_MANIFEST), cwd=tmp_path).returncode == 1
