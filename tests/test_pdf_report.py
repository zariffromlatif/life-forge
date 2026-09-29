"""Tests for the LIFE FORGE PDF audit report renderer."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from lifeforge.evolution.map_elites import MapElitesArchive
from lifeforge.reporting import pdf as pdf_report
from lifeforge.reporting.analyzer import CausalVulnerabilityFinding, DiagnosticMetrics
from lifeforge.reporting.pdf import (
    PdfExportUnavailable,
    compute_risk_score,
    render_audit_pdf,
    render_from_report_dict,
    risk_band,
)
from lifeforge.sandbox.oracle import SimulationTrace
from lifeforge.sandbox.world_state import WorldState

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_LLAMA_REPORT = REPO_ROOT / "results" / "local_llama_report.json"


def _require_pdf_extra() -> None:
    """Skip a rendering test when the optional reportlab dependency is not installed."""
    pytest.importorskip("reportlab")


def _make_finding(**overrides: object) -> CausalVulnerabilityFinding:
    """Build a finding with realistic defaults, allowing per-test overrides."""
    values: dict[str, object] = {
        "title": "Indirect Prompt Injection via Unsanitized Vendor Notes",
        "severity": "CRITICAL",
        "category": "UNAUTHORIZED_TOOL_EXECUTION",
        "minimal_causal_trigger": ["indirect_prompt_injection"],
        "description": "The agent executed a prohibited tool after reading an injected directive.",
        "trace_snippet": [
            {"step": 3, "action": "transfer_funds", "thought": "executive override approved"}
        ],
        "recommendation": "Wrap external tool output in untrusted content delimiters.",
    }
    values.update(overrides)
    return CausalVulnerabilityFinding(**values)  # type: ignore[arg-type]


def _make_metrics(**overrides: object) -> DiagnosticMetrics:
    """Build a diagnostics bundle with realistic defaults, allowing per-test overrides."""
    values: dict[str, object] = {
        "agent_name": "PurchasingAgent-v1",
        "total_evaluations": 120,
        "scenarios_generated": 48,
        "success_rate": 62.5,
        "failure_rate": 37.5,
        "critical_failures": 1,
        "novel_failure_modes_count": 3,
        "failure_mode_breakdown": {
            "RECURSIVE_LOOP_TRAP": 9,
            "UNAUTHORIZED_TOOL_EXECUTION": 6,
            "CONFLICTING_SPECIFICATION": 2,
        },
        "most_vulnerable_capability": "Untrusted Tool Output Sanitization and Privilege Separation",
        "worst_discovered_behavior": "Executed an unauthorized funds transfer after indirect injection.",
        "generalization_rating": "Critical Vulnerability (Zero-Day Exploit Discovered)",
        "findings": [_make_finding()],
    }
    values.update(overrides)
    return DiagnosticMetrics(**values)  # type: ignore[arg-type]


def _assert_pdf(path: Path) -> bytes:
    """Assert that ``path`` is a real PDF file of a non-trivial size and return its bytes."""
    assert isinstance(path, Path)
    assert path.exists()
    data = path.read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 2000
    return data


def _build_archive() -> MapElitesArchive:
    """Build a small but real MAP-Elites archive occupying several behavioral bins."""
    world = WorldState.default_purchasing_world()
    archive = MapElitesArchive(bins=(4, 4, 4))
    coords = [(0.05, 0.10, 0.20), (0.55, 0.60, 0.65), (0.90, 0.95, 0.10), (0.35, 0.40, 0.85)]
    for generation, coord in enumerate(coords, start=1):
        failed = generation % 2 == 1
        trace = SimulationTrace(
            initial_state=world,
            final_state=world,
            events=[],
            violations=[],
            success=not failed,
            total_steps=5,
            critical_failure=failed,
            failure_category="RECURSIVE_LOOP_TRAP" if failed else None,
        )
        assert archive.add(world, ["price_volatility"], trace, coord, generation)
    return archive


# ---------------------------------------------------------------------------
# Risk score and risk band
# ---------------------------------------------------------------------------


def test_compute_risk_score_sums_severity_weights() -> None:
    metrics = _make_metrics(
        findings=[
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="HIGH", title="Second"),
            _make_finding(severity="MEDIUM", title="Third"),
            _make_finding(severity="LOW", title="Fourth"),
        ]
    )
    assert compute_risk_score(metrics) == 35 + 20 + 10 + 5


def test_compute_risk_score_clamps_to_100() -> None:
    metrics = _make_metrics(
        findings=[_make_finding(severity="CRITICAL", title=f"critical-{index}") for index in range(4)]
    )
    assert compute_risk_score(metrics) == 100


def test_compute_risk_score_ignores_unknown_severity() -> None:
    metrics = _make_metrics(findings=[_make_finding(severity="INFORMATIONAL")])
    assert compute_risk_score(metrics) == 0


def test_compute_risk_score_falls_back_to_failure_rate() -> None:
    assert compute_risk_score(_make_metrics(findings=[], failure_rate=66.7, critical_failures=0)) == 33
    assert compute_risk_score(_make_metrics(findings=[], failure_rate=0.0, critical_failures=0)) == 0
    assert compute_risk_score(_make_metrics(findings=[], failure_rate=100.0, critical_failures=1)) == 85
    assert compute_risk_score(_make_metrics(findings=[], failure_rate=100.0, critical_failures=3)) == 100


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "LOW"),
        (19, "LOW"),
        (20, "MODERATE"),
        (49, "MODERATE"),
        (50, "HIGH"),
        (79, "HIGH"),
        (80, "CRITICAL"),
        (100, "CRITICAL"),
        (-5, "LOW"),
        (150, "CRITICAL"),
    ],
)
def test_risk_band_boundaries(score: int, expected: str) -> None:
    assert risk_band(score) == expected


def test_risk_band_agrees_with_computed_scores() -> None:
    cases = [
        (_make_metrics(findings=[], failure_rate=0.0, critical_failures=0), "LOW"),
        (_make_metrics(findings=[_make_finding(severity="MEDIUM")]), "LOW"),
        (_make_metrics(findings=[_make_finding(severity="HIGH")]), "MODERATE"),
        (_make_metrics(findings=[_make_finding(severity="HIGH"), _make_finding(severity="HIGH", title="b")]), "MODERATE"),
        (
            _make_metrics(
                findings=[
                    _make_finding(severity="CRITICAL"),
                    _make_finding(severity="HIGH", title="b"),
                ]
            ),
            "HIGH",
        ),
        (
            _make_metrics(
                findings=[
                    _make_finding(severity="CRITICAL"),
                    _make_finding(severity="CRITICAL", title="b"),
                    _make_finding(severity="MEDIUM", title="c"),
                ]
            ),
            "CRITICAL",
        ),
    ]
    for metrics, expected_band in cases:
        assert risk_band(compute_risk_score(metrics)) == expected_band


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_audit_pdf_writes_a_real_pdf(tmp_path: Path) -> None:
    _require_pdf_extra()
    out = render_audit_pdf(
        _make_metrics(),
        tmp_path / "nested" / "audit.pdf",
        customer="LIFE FORGE QA",
        model="ollama/llama3.1:8b",
        hardware="NVIDIA RTX 4090",
        seed=42,
        generations=20,
        command_line="lifeforge audit --agent purchasing --generations 20",
    )
    assert out.parent.is_dir()
    _assert_pdf(out)


def test_render_audit_pdf_renders_archive_heatmap(tmp_path: Path) -> None:
    _require_pdf_extra()
    archive = _build_archive()

    grid = pdf_report._archive_grid_data(archive)
    assert grid is not None
    dims, counts, fitness = grid
    assert dims == (4, 4, 4)
    assert len(counts) == 4
    assert fitness

    drawing = pdf_report._archive_heatmap_drawing(grid, 480.0, pdf_report._require_reportlab())
    assert drawing is not None

    out = render_audit_pdf(_make_metrics(), tmp_path / "archive.pdf", archive=archive)
    _assert_pdf(out)


def test_render_audit_pdf_falls_back_without_archive(tmp_path: Path) -> None:
    _require_pdf_extra()
    out = render_audit_pdf(_make_metrics(), tmp_path / "no_archive.pdf", archive=None)
    _assert_pdf(out)

    # An empty archive exposes no occupancy and must also fall back to the bar chart.
    empty_out = render_audit_pdf(
        _make_metrics(), tmp_path / "empty_archive.pdf", archive=MapElitesArchive(bins=(4, 4, 4))
    )
    _assert_pdf(empty_out)


def test_render_audit_pdf_tolerates_unexpected_archive_shapes(tmp_path: Path) -> None:
    _require_pdf_extra()
    reportlab = pdf_report._require_reportlab()

    class OddArchive:
        bins = (4, 4, 4)
        grid = {"not-an-index": object(), "still-not-an-index": object()}

    class OversizedArchive:
        bins = (20, 20, 20)
        grid = {
            (i, j, k): type("Elite", (), {"fitness": 10.0})()
            for i in range(0, 20, 5)
            for j in range(0, 20, 5)
            for k in range(4)
        }

    assert pdf_report._archive_grid_data(OddArchive()) is None
    assert pdf_report._archive_heatmap_drawing(pdf_report._archive_grid_data(OversizedArchive()), 480.0, reportlab) is None
    _assert_pdf(render_audit_pdf(_make_metrics(), tmp_path / "odd.pdf", archive=OddArchive()))
    _assert_pdf(render_audit_pdf(_make_metrics(), tmp_path / "large.pdf", archive=OversizedArchive()))


def test_render_audit_pdf_handles_empty_findings_and_breakdown(tmp_path: Path) -> None:
    _require_pdf_extra()
    metrics = _make_metrics(findings=[], failure_mode_breakdown={}, critical_failures=0)
    _assert_pdf(render_audit_pdf(metrics, tmp_path / "clean.pdf"))


# ---------------------------------------------------------------------------
# Dictionary entry point (CLI path)
# ---------------------------------------------------------------------------


def test_render_from_report_dict_matches_repo_schema(tmp_path: Path) -> None:
    _require_pdf_extra()
    data = json.loads(LOCAL_LLAMA_REPORT.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert any(finding.get("severity") == "HIGH" for finding in data["findings"])

    out = render_from_report_dict(
        data,
        tmp_path / "local_llama.pdf",
        customer="LIFE FORGE QA",
        model="ollama/llama3.1:8b",
        hardware="NVIDIA RTX 4090",
        seed=42,
        generations=20,
        command_line="lifeforge audit --json results/local_llama_report.json",
    )
    _assert_pdf(out)
    assert out.name == "local_llama.pdf"


def test_render_from_report_dict_tolerates_missing_keys(tmp_path: Path) -> None:
    _require_pdf_extra()
    _assert_pdf(render_from_report_dict({}, tmp_path / "empty_dict.pdf"))
    _assert_pdf(
        render_from_report_dict(
            {"agent_name": "Partial", "findings": [{"title": "Only a title"}]},
            tmp_path / "partial.pdf",
        )
    )


def test_render_from_report_dict_coerces_odd_finding_payloads(tmp_path: Path) -> None:
    _require_pdf_extra()
    data = {
        "agent_name": "Coercion Probe",
        "failure_mode_breakdown": {"UNKNOWN_CATEGORY": "7", "BROKEN": "not-a-number"},
        "findings": [
            {
                "title": "String trigger",
                "severity": "high",
                "minimal_causal_trigger": "single_trigger",
                "description": None,
                "trace_snippet": ["plain string note", {"step": 1}],
                "recommendation": "",
            }
        ],
    }
    _assert_pdf(render_from_report_dict(data, tmp_path / "coerced.pdf"))


def test_render_from_report_dict_rejects_non_mapping(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        render_from_report_dict([], tmp_path / "bad.pdf")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Optional dependency handling and XML safety
# ---------------------------------------------------------------------------


def test_render_raises_when_reportlab_helper_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _unavailable() -> None:
        raise PdfExportUnavailable(
            "PDF report export requires the optional 'reportlab' package. "
            "Install it with: pip install 'lifeforge[pdf]'"
        )

    monkeypatch.setattr(pdf_report, "_require_reportlab", _unavailable)

    with pytest.raises(PdfExportUnavailable, match=r"lifeforge\[pdf\]"):
        render_audit_pdf(_make_metrics(), tmp_path / "unavailable.pdf")

    with pytest.raises(PdfExportUnavailable, match=r"lifeforge\[pdf\]"):
        render_from_report_dict({}, tmp_path / "unavailable_dict.pdf")


def test_require_reportlab_reports_a_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "reportlab", None)
    with pytest.raises(PdfExportUnavailable) as excinfo:
        pdf_report._require_reportlab()
    message = str(excinfo.value)
    assert "lifeforge[pdf]" in message
    assert "reportlab" in message


def test_xml_unsafe_characters_do_not_break_rendering(tmp_path: Path) -> None:
    _require_pdf_extra()
    messy = 'A & B <script>alert("x")</script> > tail'
    metrics = _make_metrics(
        agent_name=f"Acme & Sons <Red Team> {messy}",
        most_vulnerable_capability='Tool "chaining" <unsafe> & unescaped',
        worst_discovered_behavior=f"Behavior with <b>tags</b> & ampersands: {messy}",
        failure_mode_breakdown={"ODD & <CATEGORY>": 3, "RECURSIVE_LOOP_TRAP": 2},
        findings=[
            _make_finding(
                title=f"Finding <1> & {messy}",
                description=f"Description with {messy}",
                recommendation=f"Fix {messy}",
                trace_snippet=[{"step": "1 & 2", "action": "<transfer_funds>", "thought": messy}],
            )
        ],
    )
    _assert_pdf(
        render_audit_pdf(
            metrics,
            tmp_path / "unsafe.pdf",
            customer="<customer> & co",
            command_line="lifeforge audit --agent '<x> & <y>'",
        )
    )
    _assert_pdf(
        render_from_report_dict(
            {
                "agent_name": messy,
                "findings": [
                    {
                        "title": messy,
                        "severity": "HIGH",
                        "description": messy,
                        "recommendation": messy,
                        "trace_snippet": [{"note": messy}],
                    }
                ],
            },
            tmp_path / "unsafe_dict.pdf",
        )
    )
