"""Phase 3D: smoke tests for scripts/summarize_auth_metrics.py."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from scripts.bench_auth_paths import CSV_FIELDS
from scripts.summarize_auth_metrics import SUMMARY_FIELDS

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_SCRIPT = REPO_ROOT / "scripts" / "bench_auth_paths.py"
SUMMARY_SCRIPT = REPO_ROOT / "scripts" / "summarize_auth_metrics.py"

PATH_NAMES = {
    "baseline",
    "auth_all_visible",
    "auth_policy",
    "auth_committed",
    "auth_slot_aligned",
}


def _run_mini_bench(tmp_path: Path) -> Path:
    """Small grid for summary smoke (1 repeat, 1 workload)."""
    out = tmp_path / "metrics.csv"
    cmd = [
        sys.executable,
        str(BENCH_SCRIPT),
        "--repeat",
        "1",
        "--output",
        str(out),
        "--num-vectors",
        "400",
        "--dim",
        "32",
        "--n-list",
        "8",
        "--n-probe-list",
        "4",
        "--slot-per-list-list",
        "32",
        "--top-k-list",
        "5",
        "--n-iter",
        "4",
        "--seed",
        "17",
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
        f"bench failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return out


def _run_summary(metrics: Path, summary: Path) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(SUMMARY_SCRIPT),
        "--input",
        str(metrics),
        "--output",
        str(summary),
    ]
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_summary_script_runs(tmp_path):
    metrics = _run_mini_bench(tmp_path)
    summary = tmp_path / "summary.csv"
    result = _run_summary(metrics, summary)
    assert result.returncode == 0, result.stderr
    assert summary.is_file()


def test_summary_csv_paths_and_medians(tmp_path):
    metrics = _run_mini_bench(tmp_path)
    summary = tmp_path / "summary.csv"
    _run_summary(metrics, summary)

    with summary.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert rows
    assert set(rows[0].keys()) == set(SUMMARY_FIELDS)
    paths = {r["path"] for r in rows}
    assert PATH_NAMES.issubset(paths)

    for row in rows:
        assert int(row["median_gates"]) > 0
        assert float(row["median_prove_time"]) > 0
        assert int(row["median_proof_size"]) > 0


def test_summary_slot_vs_committed_ratio(tmp_path):
    metrics = _run_mini_bench(tmp_path)
    summary = tmp_path / "summary.csv"
    _run_summary(metrics, summary)

    with summary.open(newline="") as f:
        rows = list(csv.DictReader(f))

    slot_rows = [r for r in rows if r["path"] == "auth_slot_aligned"]
    assert slot_rows
    for row in slot_rows:
        ratio = float(row["slot_vs_committed_gates"])
        assert ratio > 0
        assert ratio <= 1.0, (
            f"expected slot_vs_committed_gates <= 1 at n_probe=4 slot=32, got {ratio}"
        )


def test_benchmark_csv_schema_unchanged(tmp_path):
    metrics = _run_mini_bench(tmp_path)
    with metrics.open(newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == CSV_FIELDS


def test_summary_one_row_per_workload_path(tmp_path):
    metrics = _run_mini_bench(tmp_path)
    summary = tmp_path / "summary.csv"
    _run_summary(metrics, summary)

    with summary.open(newline="") as f:
        rows = list(csv.DictReader(f))

    by_workload: dict[tuple[int, int, int], set[str]] = defaultdict(set)
    for row in rows:
        key = (int(row["n_probe"]), int(row["slot_per_list"]), int(row["top_k"]))
        by_workload[key].add(row["path"])

    for key, paths in by_workload.items():
        assert len(paths) >= 5, f"workload {key} has only {paths}"
