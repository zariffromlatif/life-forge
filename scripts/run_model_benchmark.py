"""LIFE FORGE general model benchmark runner.

Evaluates any local (Ollama) or hosted model against the LIFE FORGE
co-evolutionary adversarial flight simulator and writes the standard result
artifacts:

    results/local_<results_slug>_report.md
    results/local_<results_slug>_report.json
    results/LEADERBOARD.md              (unless --no-leaderboard)

This script generalizes the per-model runners (for example
``scripts/run_phi4_benchmark.py``) into a single catalog-driven entry point:

    python scripts/run_model_benchmark.py --catalog
    python scripts/run_model_benchmark.py --model gemma2 --dry-run
    python scripts/run_model_benchmark.py --model gemma2 --scenarios 30 --seed 42
    python scripts/run_model_benchmark.py --model ollama/your-model:tag --api-base http://localhost:11434

A ``--model`` value may be a catalog slug (for example ``gemma2``) or a raw
model identifier (for example ``ollama/qwen2.5-coder:14b`` or ``gpt-4o-mini``).
Anything that is not a catalog slug is passed through verbatim.

Hardware target: Intel i9-14900K + NVIDIA RTX 4090 (24GB VRAM)
Inference: Ollama Q4_K_M quantization, 100% VRAM offload (for ollama/* tags)
Seed: 42 (deterministic, reproducible) / Generations: 30
License: MIT
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids importing lifeforge at load time
    from lifeforge.sandbox.world_state import WorldState


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_DIR = REPO_ROOT / "results"
DEFAULT_API_BASE = "http://localhost:11434"
DEFAULT_MODEL_SLUG = "phi4"
HARDWARE_LINE = "Intel i9-14900K + NVIDIA RTX 4090 (24GB VRAM)"

#: Catalog of models registered for the LIFE FORGE benchmark.
#:
#: Keyed by short slug. Each entry provides:
#:   tag          - LiteLLM / Ollama model identifier passed to the agent
#:   params       - approximate parameter count (display only)
#:   vram         - approximate Q4 VRAM footprint on the target 24GB GPU
#:   why          - one-line rationale for including the model in the suite
#:   results_slug - file stem used for results/local_<stem>_report.md/.json
#:
#: Note on llama32: Meta shipped Llama 3.2 in 1B/3B sizes; the plan document's
#: "11B" entry appears to be a typo, so the 3B tag is registered here.
MODEL_CATALOG: dict[str, dict[str, object]] = {
    "phi4": {
        "tag": "ollama/phi4:14b",
        "params": "14B",
        "vram": "~9GB",
        "why": "Microsoft 14B generalist; original LIFE FORGE baseline for tool-use injection tests.",
        "results_slug": "phi4",
    },
    "mistral_small_31": {
        "tag": "ollama/mistral-small:24b",
        "params": "24B",
        "vram": "~14GB",
        "why": "Efficient 24B; largest practical dense model on a 24GB card, tests whether scale resists injection.",
        "results_slug": "mistral_small_31",
    },
    "gemma2": {
        "tag": "ollama/gemma2:9b",
        "params": "9B",
        "vram": "~6GB",
        "why": "Google 9B; strong instruction adherence at a small VRAM footprint.",
        "results_slug": "gemma2",
    },
    "qwen25_coder": {
        "tag": "ollama/qwen2.5-coder:14b",
        "params": "14B",
        "vram": "~9GB",
        "why": "Code-specialist 14B; probes whether code fluency leaks tool-authorization failures.",
        "results_slug": "qwen25_coder",
    },
    "llama32": {
        "tag": "ollama/llama3.2:3b",
        "params": "3B",
        "vram": "~3GB",
        "why": "Meta 3B; smallest registered model, stress-tests robustness at minimal scale.",
        "results_slug": "llama32",
    },
    "command_r": {
        "tag": "ollama/command-r:35b",
        "params": "35B",
        "vram": "~22GB",
        "why": "Cohere 35B tool-use focus; largest model that fits 24GB VRAM at Q4.",
        "results_slug": "command_r",
    },
}


@dataclass(frozen=True)
class BenchmarkJob:
    """Fully resolved configuration for a single benchmark invocation."""

    model_tag: str
    display_label: str
    results_slug: str
    api_base: str
    api_key: str | None
    temperature: float
    generations: int
    seed: int
    delay: float
    domain: str
    results_dir: Path
    markdown_path: Path
    json_path: Path
    regenerate_leaderboard: bool


def slugify(text: str) -> str:
    """Convert arbitrary text into a lowercase, filesystem-safe slug.

    The text is lowercased, every run of characters outside ``[a-z0-9_-]``
    (which covers ``:``, ``/``, ``.`` and whitespace) is replaced by a single
    underscore, leading/trailing underscores are trimmed, and an empty result
    falls back to the literal ``"model"``.

    Examples:
        >>> slugify("ollama/qwen2.5-coder:14b")
        'ollama_qwen2_5-coder_14b'
        >>> slugify("Mistral Small 3.1")
        'mistral_small_3_1'
    """
    cleaned = "".join(
        ch if (ch.isascii() and (ch.isalnum() or ch in "_-")) else "_"
        for ch in text.lower()
    )
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    cleaned = cleaned.strip("_")
    return cleaned or "model"


def resolve_model(
    spec: str,
    catalog: dict[str, dict[str, object]] | None = None,
) -> tuple[str, str, str]:
    """Resolve a model specification into (model_tag, display_label, results_slug).

    Args:
        spec: A catalog slug (for example ``"gemma2"``) or a raw model
            identifier (for example ``"ollama/foo:7b"`` or ``"gpt-4o-mini"``).
        catalog: Optional catalog override; defaults to :data:`MODEL_CATALOG`.

    Returns:
        Tuple of the LiteLLM model tag, the human-readable display label, and
        the filesystem-safe results slug. Catalog hits return the registered
        tag, the tag without its ``ollama/`` prefix as label, and the entry's
        ``results_slug``. Anything else is passed through verbatim: the spec
        itself is both tag and label, and the slug is derived with
        :func:`slugify`.
    """
    active_catalog = MODEL_CATALOG if catalog is None else catalog
    entry = active_catalog.get(spec)
    if entry is not None:
        tag = str(entry["tag"])
        label = tag.removeprefix("ollama/")
        return tag, label, str(entry["results_slug"])
    return spec, spec, slugify(spec)


def build_output_paths(
    results_dir: Path | str,
    results_slug: str,
) -> tuple[Path, Path]:
    """Return the (markdown, json) report paths for a results slug.

    Args:
        results_dir: Directory that receives the report artifacts.
        results_slug: File stem inserted into ``local_<slug>_report.*``.

    Returns:
        Tuple of ``Path`` objects: the Markdown report and the JSON report.
    """
    directory = Path(results_dir)
    return (
        directory / f"local_{results_slug}_report.md",
        directory / f"local_{results_slug}_report.json",
    )


def format_catalog(catalog: dict[str, dict[str, object]] | None = None) -> str:
    """Render the model catalog as a fixed-width, Markdown-free ASCII table.

    Args:
        catalog: Optional catalog override; defaults to :data:`MODEL_CATALOG`.

    Returns:
        A multi-line ASCII table with the columns Slug, Params, Approx VRAM,
        Ollama tag and Why.
    """
    active_catalog = MODEL_CATALOG if catalog is None else catalog
    headers = ("Slug", "Params", "Approx VRAM", "Ollama tag", "Why")
    rows: list[tuple[str, str, str, str, str]] = []
    for slug, entry in active_catalog.items():
        rows.append(
            (
                slug,
                str(entry.get("params", "?")),
                str(entry.get("vram", "?")),
                str(entry.get("tag", "?")),
                str(entry.get("why", "")),
            )
        )

    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"

    def render(cells: tuple[str, ...]) -> str:
        return "| " + " | ".join(cell.ljust(width) for cell, width in zip(cells, widths)) + " |"

    lines = [separator, render(headers), separator]
    lines.extend(render(row) for row in rows)
    lines.append(separator)
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for the benchmark runner.

    Returns:
        Configured :class:`argparse.ArgumentParser`; ``--model`` and
        ``--catalog`` are mutually exclusive.
    """
    parser = argparse.ArgumentParser(
        prog="run_model_benchmark",
        description=(
            "LIFE FORGE general benchmark runner: evaluate a catalog model or a "
            "raw model tag against the co-evolutionary adversarial simulator."
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--model",
        type=str,
        default=None,
        help=(
            "Catalog slug (for example 'gemma2') or raw model tag "
            "(for example 'ollama/qwen2.5-coder:14b' or 'gpt-4o-mini'). "
            f"Defaults to '{DEFAULT_MODEL_SLUG}' when omitted."
        ),
    )
    group.add_argument(
        "--catalog",
        action="store_true",
        help="Print the registered model catalog as a table and exit.",
    )
    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help="Override the display name; also derives the results file slug.",
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default=DEFAULT_API_BASE,
        help=f"Model API base URL (default: {DEFAULT_API_BASE}).",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Optional API key for hosted providers (default: none).",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature passed to the agent (default: 0.0).",
    )
    parser.add_argument(
        "--scenarios",
        type=int,
        default=30,
        help="Number of evolutionary generations to run (default: 30).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed matching prior runs (default: 42).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Optional sleep in seconds between generations (default: 0.0).",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=None,
        help=f"Directory for report artifacts (default: {DEFAULT_RESULTS_DIR}).",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default="procurement",
        help="Scenario domain resolved via lifeforge.sandbox.domains (default: procurement).",
    )
    parser.add_argument(
        "--no-leaderboard",
        action="store_true",
        help="Skip regenerating results/LEADERBOARD.md after the run.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the resolved configuration and exit without contacting any model.",
    )
    return parser


def _ensure_repo_root_on_path() -> None:
    """Insert the repository root into ``sys.path`` so ``import lifeforge`` works.

    Needed because ``scripts/`` is not a package and Python does not place the
    current working directory on ``sys.path`` when executing a script file.
    """
    repo_root = str(REPO_ROOT)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


def _build_seed_state(domain: str) -> WorldState:
    """Resolve the seed world state for the requested scenario domain.

    Attempts ``lifeforge.sandbox.domains.get_domain(domain).build_world()``.
    When the domain package or factory is unavailable (ImportError) or the
    requested domain is not registered (KeyError -- ``"procurement"`` is the
    historical built-in scenario and lives outside the domain registry),
    prints a note and falls back to
    ``WorldState.default_purchasing_world()``.

    Args:
        domain: Domain name, for example ``"procurement"``.

    Returns:
        The seed :class:`~lifeforge.sandbox.world_state.WorldState` for the run.
    """
    _ensure_repo_root_on_path()
    from lifeforge.sandbox.world_state import WorldState

    try:
        from lifeforge.sandbox.domains import get_domain
    except ImportError:
        print(f"  [NOTE] Domain package unavailable; using default purchasing world for '{domain}'.")
        return WorldState.default_purchasing_world()

    try:
        return get_domain(domain).build_world()
    except KeyError:
        print(f"  [NOTE] Domain '{domain}' not registered; using default purchasing world.")
        return WorldState.default_purchasing_world()


def _print_header(job: BenchmarkJob) -> None:
    """Print the run header block, mirroring the per-model scripts' style."""
    print("=" * 66)
    print(f"  LIFE FORGE -- {job.display_label} Security Benchmark")
    print("=" * 66)
    print(f"  Model:       {job.model_tag}")
    print(f"  API Base:    {job.api_base}")
    print(f"  Generations: {job.generations}")
    print(f"  Seed:        {job.seed}")
    print(f"  Domain:      {job.domain}")
    print(f"  Hardware:    {HARDWARE_LINE}")
    print()


def _print_dry_run(job: BenchmarkJob) -> None:
    """Print the fully resolved configuration without touching any model or file."""
    print("=" * 66)
    print("  LIFE FORGE -- Model Benchmark (dry run)")
    print("=" * 66)
    print(f"  Model tag:      {job.model_tag}")
    print(f"  Label:          {job.display_label}")
    print(f"  Results slug:   {job.results_slug}")
    print(f"  Markdown out:   {job.markdown_path}")
    print(f"  JSON out:       {job.json_path}")
    print(f"  Generations:    {job.generations}")
    print(f"  Seed:           {job.seed}")
    print(f"  Delay (s):      {job.delay}")
    print(f"  Temperature:    {job.temperature}")
    print(f"  API base:       {job.api_base}")
    print(f"  API key:        {'(provided)' if job.api_key else '(none)'}")
    print(f"  Domain:         {job.domain}")
    print(f"  Leaderboard:    {'enabled' if job.regenerate_leaderboard else 'disabled'}")
    print(f"  Hardware:       {HARDWARE_LINE}")
    print()
    print("  [OK] Dry run complete. No model was contacted and no files were written.")


def run_benchmark(job: BenchmarkJob) -> int:
    """Execute one benchmark job and write the Markdown, JSON and leaderboard artifacts.

    Args:
        job: Fully resolved :class:`BenchmarkJob` configuration.

    Returns:
        Process exit code: 1 when the run discovered at least one critical
        zero-day vulnerability, 0 otherwise (matching the phi4 script).
    """
    _ensure_repo_root_on_path()
    from lifeforge.evolution.engine import EvolutionEngine
    from lifeforge.reporting.analyzer import CausalAnalyzer
    from lifeforge.reporting.leaderboard import write_leaderboard
    from lifeforge.reporting.report import ReportGenerator
    from lifeforge.sandbox.llm_agent import LLMAgent, LLMAgentConfig

    _print_header(job)

    seed_state = _build_seed_state(job.domain)

    config = LLMAgentConfig(
        model=job.model_tag,
        api_base=job.api_base,
        temperature=job.temperature,
        api_key=job.api_key,
    )
    agent = LLMAgent(config=config)

    engine = EvolutionEngine(seed=job.seed, delay=job.delay)

    print(f"  Running {job.generations} evolutionary generations...")
    print()
    summary = engine.run(agent, seed_state, generations=job.generations)

    print()
    print("  --- Results ---")
    print(f"  Total evaluations:  {summary.total_evaluations}")
    print(f"  Archive coverage:   {summary.archive_coverage * 100:.1f}%")
    print(f"  Elites:             {summary.elites_count}")
    print(f"  Critical failures:  {summary.critical_failures_count}")
    print(f"  Novel failure modes: {summary.novel_failure_modes}")

    # Generate diagnostic report
    analyzer = CausalAnalyzer()
    diagnostics = analyzer.analyze(agent, summary, seed_state)

    job.results_dir.mkdir(parents=True, exist_ok=True)

    # Write Markdown report
    md_report = ReportGenerator.generate_markdown(diagnostics)
    job.markdown_path.write_text(md_report, encoding="utf-8")
    print(f"\n  [OK] Markdown report: {job.markdown_path}")

    # Write JSON report
    job.json_path.write_text(
        json.dumps(asdict(diagnostics), indent=2, default=str),
        encoding="utf-8",
    )
    print(f"  [OK] JSON report:     {job.json_path}")

    # Regenerate leaderboard with new data
    if job.regenerate_leaderboard:
        lb_path = write_leaderboard(job.results_dir)
        print(f"  [OK] Leaderboard:     {lb_path}")

    print()
    if summary.critical_failures_count > 0:
        print(f"  [CRITICAL] {summary.critical_failures_count} critical zero-day vulnerabilities discovered.")
        return 1
    print("  [OK] No critical vulnerabilities found.")
    print(f"  Adversarial failure modes: {summary.novel_failure_modes}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 on success, 1 when critical vulnerabilities were
        found, and argparse's 2 for usage errors.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.catalog:
        print(format_catalog())
        return 0

    spec = args.model if args.model else DEFAULT_MODEL_SLUG
    model_tag, display_label, results_slug = resolve_model(spec)
    if args.label:
        display_label = args.label
        results_slug = slugify(args.label)

    results_dir = Path(args.results_dir) if args.results_dir else DEFAULT_RESULTS_DIR
    markdown_path, json_path = build_output_paths(results_dir, results_slug)

    job = BenchmarkJob(
        model_tag=model_tag,
        display_label=display_label,
        results_slug=results_slug,
        api_base=args.api_base,
        api_key=args.api_key,
        temperature=args.temperature,
        generations=args.scenarios,
        seed=args.seed,
        delay=args.delay,
        domain=args.domain,
        results_dir=results_dir,
        markdown_path=markdown_path,
        json_path=json_path,
        regenerate_leaderboard=not args.no_leaderboard,
    )

    if args.dry_run:
        _print_dry_run(job)
        return 0

    return run_benchmark(job)


if __name__ == "__main__":
    raise SystemExit(main())
