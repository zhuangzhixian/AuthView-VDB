"""Phase 2D: smoke tests for scripts/bench_auth_paths.py."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "bench_auth_paths.py"

PATH_NAMES = {"baseline", "auth_all_visible", "auth_policy", "auth_committed"}
METRIC_FIELDS = ("build_time", "prove_time", "verify_time", "proof_size", "memory", "gates")


def _run_bench(tmp_path: Path) -> Path:
    out = tmp_path / "auth_zk_path_metrics.csv"
    cmd = [
        sys.executable,
        str(SCRIPT),
        "--repeat",
        "1",
        "--output",
        str(out),
        "--num-vectors",
        "400",
        "--dim",
        "32",
        "--n-list",
        "4",
        "--n-probe",
        "2",
        "--top-k",
        "3",
        "--n-iter",
        "4",
        "--seed",
        "7",
    ]
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, (
        f"bench script failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return out


def test_bench_script_runs_and_writes_csv(tmp_path):
    out = _run_bench(tmp_path)
    assert out.is_file()

    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 4
    paths = {row["path"] for row in rows}
    assert paths == PATH_NAMES

    for row in rows:
        for field in METRIC_FIELDS:
            val = float(row[field]) if field != "proof_size" and field != "gates" else int(row[field])
            assert val > 0, f"{row['path']}.{field} should be positive, got {val}"


def test_bench_gate_ordering(tmp_path):
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        rows = {row["path"]: row for row in csv.DictReader(f)}

    baseline_gates = int(rows["baseline"]["gates"])
    policy_gates = int(rows["auth_policy"]["gates"])
    committed_gates = int(rows["auth_committed"]["gates"])
    all_visible_gates = int(rows["auth_all_visible"]["gates"])

    assert policy_gates >= baseline_gates, (
        f"expected policy gates ({policy_gates}) >= baseline ({baseline_gates})"
    )
    assert committed_gates >= policy_gates, (
        f"expected committed gates ({committed_gates}) >= policy ({policy_gates})"
    )
    assert all_visible_gates >= baseline_gates, (
        f"expected all_visible gates ({all_visible_gates}) >= baseline ({baseline_gates})"
    )
