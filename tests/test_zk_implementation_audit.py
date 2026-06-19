"""Phase 10: tests for ZK implementation gap audit documentation."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

AUDIT_DOC = ROOT / "docs/phase10_zk_implementation_gap_audit.md"
MATRIX_DOC = ROOT / "docs/zk_path_status_matrix.md"
PILOT_DOC = ROOT / "docs/public_trace_to_zk_pilot_plan.md"

REQUIRED_PROOF_PATHS = (
    "content-only",
    "auth-committed",
    "auth_committed",
    "slot-aligned",
    "auth_slot_aligned",
    "ACL-class",
    "auth_acl_class",
    "access-aware proof planning",
    "public-trace-derived",
)

FORBIDDEN_COMPLETED_CLAIMS = (
    "public benchmark z k proof is complete",
    "public benchmarks are fully z k-proven",
    "public trace z k proof completed",
    "end-to-end public z k pipeline is complete",
)

PILOT_MARKERS = (
    "public-trace-derived",
    "phase 11",
    "pilot_query_manifest",
    "run_public_trace_zk_pilot",
)


@pytest.mark.parametrize(
    "path",
    [AUDIT_DOC, MATRIX_DOC, PILOT_DOC],
)
def test_audit_documents_exist(path: Path):
    assert path.is_file(), f"missing {path}"


def test_status_matrix_contains_all_proof_paths():
    text = MATRIX_DOC.read_text(encoding="utf-8").lower()
    for token in REQUIRED_PROOF_PATHS:
        assert token.lower() in text, f"missing proof path token: {token}"


def test_audit_does_not_claim_public_zk_complete():
    combined = (
        AUDIT_DOC.read_text(encoding="utf-8")
        + MATRIX_DOC.read_text(encoding="utf-8")
    ).lower()
    assert "not implemented" in combined or "no." in combined
    assert "public-trace-derived proof instance" in combined or "public-trace-derived" in combined
    # Must explicitly state gap / not connected
    assert "not connected" in combined or "missing" in combined
    for phrase in FORBIDDEN_COMPLETED_CLAIMS:
        assert phrase not in combined.replace("-", " "), f"forbidden claim: {phrase}"


def test_pilot_plan_present():
    text = PILOT_DOC.read_text(encoding="utf-8").lower()
    for marker in PILOT_MARKERS:
        assert marker.lower() in text, f"missing pilot marker: {marker}"
    assert "calibration_queries.csv" in text
    assert "auth_committed" in text


def test_audit_distinguishes_plaintext_layers():
    text = AUDIT_DOC.read_text(encoding="utf-8").lower()
    assert "phase 8c" in text
    assert "phase 9a" in text
    assert "phase 9b" in text
    assert "plaintext" in text or "not z k" in text.replace("-", " ")
    assert "controlled parameterized proof workloads" in text


def test_no_json_artifacts_in_pilot_plan():
    text = PILOT_DOC.read_text(encoding="utf-8").lower()
    assert "no json" in text
    assert ".json" not in text.split("no json")[0]  # no json paths before explicit no-json note
