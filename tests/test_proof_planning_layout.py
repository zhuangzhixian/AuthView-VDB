"""Phase 6B-2.10: tests for repaired access-signature layout evaluation."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

import pytest

from auth_reference.attacks import DEFAULT_CHECKPOINT
from auth_reference.layout_planning_reference import (
    AccessSignatureConfig,
    build_access_signature_workload,
    evaluate_layout,
)
from scripts.bench_proof_planning_layout import CSV_FIELDS
from scripts.summarize_proof_planning_layout import SUMMARY_FIELDS

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH = REPO_ROOT / "scripts" / "bench_proof_planning_layout.py"
SUMMARY = REPO_ROOT / "scripts" / "summarize_proof_planning_layout.py"
AUDIT = REPO_ROOT / "scripts" / "audit_proof_planning_layout_model.py"

METRICS = REPO_ROOT / "artifacts" / "proof_planning_layout_metrics_repaired.csv"
SUMMARY_CSV = REPO_ROOT / "artifacts" / "proof_planning_layout_summary_repaired.csv"
SANITY_CSV = REPO_ROOT / "artifacts" / "proof_planning_layout_sanity.csv"


def _run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _load(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _workload(seed: int = 0, num_objects: int = 256) -> tuple:
    config = AccessSignatureConfig(
        num_objects=num_objects,
        num_roles=8,
        num_signatures=16,
        seed=seed,
    )
    return build_access_signature_workload(config), config


def _run_small_bench(tmp_path: Path) -> Path:
    out = tmp_path / "metrics.csv"
    cmd = [
        sys.executable,
        str(BENCH),
        "--num-objects",
        "128",
        "--num-roles",
        "8",
        "--num-signatures",
        "16",
        "--layouts",
        "global,acl_signature,oracle_authorized_view",
        "--merged-k-list",
        "1,4,16",
        "--query-roles",
        "0,4",
        "--seeds",
        "0,1",
        "--output",
        str(out),
    ]
    result = _run(cmd)
    assert result.returncode == 0, result.stderr
    return out


def test_access_signature_workload_builds():
    workload, config = _workload()
    assert len(workload.candidates) >= config.num_objects
    assert len(workload.object_signatures) == config.num_objects
    assert workload.total_memberships > config.num_objects


def test_layout_bench_small_config_runs(tmp_path):
    out = _run_small_bench(tmp_path)
    rows = _load(out)
    assert rows
    assert set(rows[0].keys()) == set(CSV_FIELDS)
    assert rows[0]["workload_model"] == "access_signature_layout"


def test_oracle_sa_higher_than_acl_and_global():
    workload, _ = _workload(num_objects=512)
    query_role = 2
    oracle = evaluate_layout(
        "oracle_authorized_view", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    acl = evaluate_layout(
        "acl_signature", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    global_r = evaluate_layout(
        "global", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    assert oracle.SA_commit > acl.SA_commit > global_r.SA_commit


def test_oracle_pa_lowest():
    workload, _ = _workload(num_objects=512)
    query_role = 2
    oracle = evaluate_layout(
        "oracle_authorized_view", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    acl = evaluate_layout(
        "acl_signature", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    global_r = evaluate_layout(
        "global", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    assert oracle.PA_plan <= acl.PA_plan + 0.05
    assert oracle.PA_plan <= global_r.PA_plan


def test_global_impure_higher_than_acl_signature():
    workload, _ = _workload(num_objects=512)
    query_role = 3
    acl = evaluate_layout(
        "acl_signature", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    global_r = evaluate_layout(
        "global", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    assert acl.impure_valid_ratio < global_r.impure_valid_ratio


def test_merged_k_varies_with_k():
    workload, _ = _workload(num_objects=512)
    query_role = 1
    low_k = evaluate_layout(
        "merged_k", workload, query_role, DEFAULT_CHECKPOINT, merged_k=1, top_k=5
    )
    high_k = evaluate_layout(
        "merged_k", workload, query_role, DEFAULT_CHECKPOINT, merged_k=16, top_k=5
    )
    assert high_k.PA_plan >= low_k.PA_plan - 0.02
    assert high_k.SA_commit <= low_k.SA_commit + 0.02
    assert high_k.impure_valid_ratio >= low_k.impure_valid_ratio - 0.05


def test_acl_signature_not_identical_to_oracle():
    workload, _ = _workload(num_objects=512)
    query_role = 4
    oracle = evaluate_layout(
        "oracle_authorized_view", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    acl = evaluate_layout(
        "acl_signature", workload, query_role, DEFAULT_CHECKPOINT, top_k=5
    )
    assert abs(oracle.SA_commit - acl.SA_commit) > 0.05
    assert abs(oracle.PA_plan - acl.PA_plan) > 0.02 or oracle.impure_valid_ratio == acl.impure_valid_ratio


def test_all_layouts_equivalent_and_valid():
    workload, _ = _workload(num_objects=128)
    for layout in ("global", "acl_signature", "oracle_authorized_view"):
        result = evaluate_layout(
            layout, workload, query_role=0, checkpoint=DEFAULT_CHECKPOINT, top_k=3
        )
        assert result.planned_equals_masked, layout
        assert result.validation_passed, layout


def test_repaired_metrics_artifact():
    if not METRICS.is_file():
        pytest.skip("repaired metrics not generated")
    rows = _load(METRICS)
    assert len(rows) >= 100
    assert all(r["planned_equals_masked"] == "true" for r in rows)
    assert all(r["validation_passed"] == "true" for r in rows)


def test_sanity_audit_runs(tmp_path):
    metrics = _run_small_bench(tmp_path)
    summary_path = tmp_path / "summary.csv"
    assert _run(
        [
            sys.executable,
            str(SUMMARY),
            "--input",
            str(metrics),
            "--output",
            str(summary_path),
        ]
    ).returncode == 0
    sanity_path = tmp_path / "sanity.csv"
    result = _run(
        [
            sys.executable,
            str(AUDIT),
            "--input",
            str(summary_path),
            "--output",
            str(sanity_path),
        ]
    )
    checks = _load(sanity_path)
    assert len(checks) >= 10
    assert any(c["check_id"] == "all_validation_passed" and c["passed"] == "true" for c in checks)
    assert any(c["check_id"] == "all_planned_equals_masked" and c["passed"] == "true" for c in checks)


def test_full_sanity_artifact_if_present():
    if not SANITY_CSV.is_file():
        pytest.skip("sanity csv not generated")
    checks = _load(SANITY_CSV)
    failed = [c for c in checks if c["passed"] != "true"]
    assert not failed, failed
