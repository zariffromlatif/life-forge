"""Unit tests for the generalized LIFE FORGE model benchmark runner.

These tests exercise the pure helper functions and the argument-handling paths
of ``scripts/run_model_benchmark.py``. No GPU, no network access and no LLM
backend are required: dry runs never construct an agent or write files.

The ``scripts/`` directory is not a Python package, so the module is loaded
directly from its file path with :mod:`importlib`.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "run_model_benchmark.py"
MODULE_NAME = "run_model_benchmark"


def _load_benchmark_module() -> ModuleType:
    """Load ``scripts/run_model_benchmark.py`` as a module, once per process.

    Returns:
        The imported benchmark runner module, reused from ``sys.modules`` if a
        previous test already imported it.
    """
    if MODULE_NAME in sys.modules:
        return sys.modules[MODULE_NAME]
    spec = importlib.util.spec_from_file_location(MODULE_NAME, SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


rb = _load_benchmark_module()


def test_slugify_ollama_tag() -> None:
    """A raw Ollama tag becomes a lowercase, filesystem-safe slug."""
    assert rb.slugify("ollama/qwen2.5-coder:14b") == "ollama_qwen2_5-coder_14b"


def test_slugify_human_label() -> None:
    """Spaces and dotted version numbers are normalized to underscores."""
    assert rb.slugify("Mistral Small 3.1") == "mistral_small_3_1"


def test_slugify_collapses_repeated_separators() -> None:
    """Runs of separators collapse and no leading/trailing separators remain."""
    slug = rb.slugify("Weird///Name::v2..gguf")
    assert slug == "weird_name_v2_gguf"
    assert "__" not in slug
    assert not slug.startswith("_")
    assert not slug.endswith("_")


def test_resolve_model_catalog_slug() -> None:
    """A catalog slug resolves to its registered tag, label and results slug."""
    tag, label, results_slug = rb.resolve_model("gemma2")
    assert tag == "ollama/gemma2:9b"
    assert results_slug == "gemma2"
    assert label == "gemma2:9b"


def test_resolve_model_raw_ollama_tag() -> None:
    """A raw Ollama tag passes through verbatim with a derived safe slug."""
    tag, _label, results_slug = rb.resolve_model("ollama/foo:7b")
    assert tag == "ollama/foo:7b"
    assert results_slug == "ollama_foo_7b"
    assert all(ch.isalnum() or ch in "_-" for ch in results_slug)


def test_resolve_model_raw_non_ollama_tag() -> None:
    """A hosted-provider identifier is also passed through verbatim."""
    tag, _label, results_slug = rb.resolve_model("gpt-4o-mini")
    assert tag == "gpt-4o-mini"
    # Hyphens are already filesystem-safe per the slug rules (: / . -> _),
    # so a plain hyphenated provider id survives unchanged.
    assert results_slug == "gpt-4o-mini"


def test_resolve_model_unknown_slug_is_verbatim() -> None:
    """Strings that are neither a catalog slug nor a tag-like identifier pass through."""
    tag, _label, results_slug = rb.resolve_model("not_a_model")
    assert tag == "not_a_model"
    assert results_slug == "not_a_model"


def test_build_output_paths(tmp_path: Path) -> None:
    """Report paths follow the local_<slug>_report.md/.json convention."""
    markdown_path, json_path = rb.build_output_paths(tmp_path, "gemma2")
    assert markdown_path == tmp_path / "local_gemma2_report.md"
    assert json_path == tmp_path / "local_gemma2_report.json"
    assert markdown_path.parent == tmp_path
    assert json_path.parent == tmp_path


def test_format_catalog_lists_every_entry_and_is_ascii() -> None:
    """The catalog table is pure ASCII and lists every slug, tag and column."""
    text = rb.format_catalog()
    assert text.isascii()
    assert "__" not in text
    for header in ("Slug", "Params", "Approx VRAM", "Ollama tag", "Why"):
        assert header in text
    for slug, entry in rb.MODEL_CATALOG.items():
        assert slug in text
        assert str(entry["tag"]) in text
        assert any(line.strip().startswith(f"| {slug}") for line in text.splitlines())


def test_main_catalog_exits_zero(capsys) -> None:
    """``--catalog`` prints the table and returns exit code 0."""
    exit_code = rb.main(["--catalog"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "gemma2" in out
    assert "ollama/gemma2:9b" in out


def test_main_dry_run_writes_no_files(tmp_path: Path, capsys) -> None:
    """A dry run resolves the configuration without creating any artifacts."""
    markdown_path = tmp_path / "local_gemma2_report.md"
    json_path = tmp_path / "local_gemma2_report.json"

    exit_code = rb.main(["--dry-run", "--model", "gemma2", "--results-dir", str(tmp_path)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert list(tmp_path.iterdir()) == []
    assert "ollama/gemma2:9b" in out
    assert str(markdown_path) in out
    assert str(json_path) in out
    assert str(rb.HARDWARE_LINE) in out


def test_main_dry_run_unknown_slug_verbatim(capsys) -> None:
    """An unrecognized slug that is not a raw tag is still used verbatim."""
    exit_code = rb.main(["--dry-run", "--model", "not_a_model"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "not_a_model" in out


def test_main_dry_run_label_override(tmp_path: Path, capsys) -> None:
    """``--label`` overrides the display name and the results slug."""
    exit_code = rb.main(
        [
            "--dry-run",
            "--model",
            "gemma2",
            "--label",
            "Mistral Small 3.1",
            "--results-dir",
            str(tmp_path),
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "mistral_small_3_1" in out
    assert str(tmp_path / "local_mistral_small_3_1_report.md") in out
    assert "ollama/gemma2:9b" in out
    assert list(tmp_path.iterdir()) == []


def test_main_dry_run_no_leaderboard_flag(tmp_path: Path, capsys) -> None:
    """``--no-leaderboard`` is reflected in the dry-run summary."""
    exit_code = rb.main(
        ["--dry-run", "--model", "phi4", "--no-leaderboard", "--results-dir", str(tmp_path)]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "disabled" in out
    assert list(tmp_path.iterdir()) == []
