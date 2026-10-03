"""Tests for the compliance evidence pack (reporting/compliance.py)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lifeforge.gateway import AuditTrail, VERDICT_ALLOW, VERDICT_BLOCK
from lifeforge.reporting.compliance import (
    EU_AI_ACT_CONTROLS,
    build_compliance_pack,
    classify_violation,
    render_compliance_markdown,
    verify_audit_trail,
    write_compliance_pack,
)


@pytest.fixture()
def report() -> dict:
    return json.loads(Path("results/local_qwen_report.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class TestClassification:
    def test_critical_security_violations_map_to_multiple_controls(self):
        controls = classify_violation("UNAUTHORIZED_TOOL_EXECUTION")
        assert "risk_management" in controls
        assert "human_oversight" in controls
        assert "robustness" in controls

    def test_exfiltration_maps_to_data_governance(self):
        assert "data_governance" in classify_violation("UNAUTHORIZED_DATA_EXFILTRATION")

    def test_loop_trap_maps_to_robustness(self):
        assert "robustness" in classify_violation("RECURSIVE_LOOP_TRAP")

    def test_unknown_violation_maps_to_nothing(self):
        assert classify_violation("NOT_A_REAL_VIOLATION") == []

    def test_every_control_has_required_fields(self):
        for control in EU_AI_ACT_CONTROLS:
            assert control["id"] and control["article"] and control["title"]
            assert control["obligation"]
            assert control["remediation"]


# ---------------------------------------------------------------------------
# Trail verification
# ---------------------------------------------------------------------------


class TestTrailVerification:
    def test_missing_trail_is_unverified(self):
        summary = verify_audit_trail(None)
        assert summary["status"] == "UNVERIFIED"

    def test_intact_chain_verifies(self, tmp_path: Path):
        trail = AuditTrail(tmp_path / "audit.jsonl")
        trail.append(tool_name="a", verdict=VERDICT_ALLOW, arguments={"x": 1})
        trail.append(tool_name="b", verdict=VERDICT_BLOCK, violation_type="X")
        summary = verify_audit_trail(tmp_path / "audit.jsonl")
        assert summary["status"] == "VERIFIED"
        assert summary["records"] == 2

    def test_tampered_trail_fails_verification(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        trail = AuditTrail(path)
        trail.append(tool_name="a", verdict=VERDICT_ALLOW)
        trail.append(tool_name="b", verdict=VERDICT_ALLOW)
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["reason"] = "edited after the fact"
        lines[0] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        summary = verify_audit_trail(path)
        assert summary["status"] == "TAMPERED"

    def test_unreadable_file_is_reported(self, tmp_path: Path):
        summary = verify_audit_trail(tmp_path / "does_not_exist.jsonl")
        assert summary["status"] in ("UNREADABLE", "UNVERIFIED")


# ---------------------------------------------------------------------------
# Pack assembly
# ---------------------------------------------------------------------------


class TestPackAssembly:
    def test_pack_assesses_every_control(self, report):
        pack = build_compliance_pack(report)
        assert len(pack.assessments) == len(EU_AI_ACT_CONTROLS)
        assert {a.control_id for a in pack.assessments} == {c["id"] for c in EU_AI_ACT_CONTROLS}

    def test_record_keeping_is_unverified_without_trail(self, report):
        pack = build_compliance_pack(report)
        record_keeping = next(a for a in pack.assessments if a.control_id == "record_keeping")
        assert record_keeping.status == "UNVERIFIED"
        assert "No gateway audit trail" in record_keeping.notes

    def test_record_keeping_passes_with_verified_trail(self, report, tmp_path: Path):
        trail = AuditTrail(tmp_path / "audit.jsonl")
        trail.append(tool_name="query_database", verdict=VERDICT_ALLOW)
        pack = build_compliance_pack(report, trail_path=tmp_path / "audit.jsonl")
        record_keeping = next(a for a in pack.assessments if a.control_id == "record_keeping")
        assert record_keeping.status == "PASS"
        assert "verified" in record_keeping.notes

    def test_record_keeping_gaps_on_tampered_trail(self, report, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        trail = AuditTrail(path)
        trail.append(tool_name="a", verdict=VERDICT_ALLOW)
        trail.append(tool_name="b", verdict=VERDICT_ALLOW)
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["verdict"] = "BLOCKED_FOREVER"
        lines[0] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        pack = build_compliance_pack(report, trail_path=path)
        record_keeping = next(a for a in pack.assessments if a.control_id == "record_keeping")
        assert record_keeping.status == "GAP"

    def test_violations_produce_gaps_with_findings(self, report):
        pack = build_compliance_pack(report)
        # The qwen report contains UNAUTHORIZED_TOOL_EXECUTION.
        unauthorized = next(
            a for a in pack.assessments
            if any(f["violation_type"] == "UNAUTHORIZED_TOOL_EXECUTION" for f in a.findings)
        )
        assert unauthorized.status == "GAP"
        assert unauthorized.finding_count > 0

    def test_gap_register_is_sorted_by_severity(self, report):
        pack = build_compliance_pack(report)
        ranks = [{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(entry["severity"], 4) for entry in pack.gap_register]
        assert ranks == sorted(ranks)

    def test_clean_report_passes_all_assessable_controls(self):
        clean = {
            "agent_name": "clean-agent",
            "failure_mode_breakdown": {},
            "findings": [],
            "critical_failures": 0,
        }
        pack = build_compliance_pack(clean)
        assert all(a.status != "GAP" for a in pack.assessments)

    def test_unknown_framework_raises(self, report):
        with pytest.raises(ValueError):
            build_compliance_pack(report, framework="pci-dss")


# ---------------------------------------------------------------------------
# Rendering and persistence
# ---------------------------------------------------------------------------


class TestRendering:
    def test_markdown_contains_the_required_disclaimer(self, report):
        pack = build_compliance_pack(report)
        markdown = render_compliance_markdown(pack, customer="Acme Corp")
        assert "not legal advice" in markdown
        assert "Acme Corp" in markdown
        assert "Control Assessment Summary" in markdown

    def test_markdown_shows_gap_details(self, report):
        markdown = render_compliance_markdown(build_compliance_pack(report))
        assert "Gap Register" in markdown
        assert "UNAUTHORIZED_TOOL_EXECUTION" in markdown

    def test_write_produces_markdown_and_json(self, report, tmp_path: Path):
        md_path, json_path = write_compliance_pack(report, tmp_path / "pack.md", customer="Test")
        assert md_path.exists() and md_path.stat().st_size > 500
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["framework"] == "eu-ai-act"
        assert len(data["assessments"]) == len(EU_AI_ACT_CONTROLS)
        assert data["disclaimer"]
