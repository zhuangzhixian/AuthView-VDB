"""Phase 5C: smoke tests for ACL-class compression benchmark scripts."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

from scripts.bench_acl_class_paths import CSV_FIELDS, PATH_NAMES, filter_n_acl_list
from scripts.summarize_acl_class_metrics import SUMMARY_FIELDS

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_SCRIPT = REPO_ROOT / "scripts" / "bench_acl_class_paths.py"
SUMMARY_SCRIPT = REPO_ROOT / "scripts" / "summarize_acl_class_metrics.py"

METRIC_FIELDS = ("build_time", "prove_time", "verify_time", "proof_size", "memory", "gates")


def _run_bench(tmp_path: Path, extra_args: list[str] | None = None) -> Path:
    out = tmp_path / "acl_metrics.csv"
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
        "4",
        "--n-probe-list",
        "2",
        "--slot-per-list-list",
        "16",
        "--top-k-list",
        "3",
        "--n-acl-list",
        "1,2,4",
        "--n-iter",
        "4",
        "--seed",
        "23",
    ]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=1800,
    )
    assert result.returncode == 0, (
        f"bench_acl_class_paths failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
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


def test_bench_script_runs_and_writes_csv(tmp_path):
    out = _run_bench(tmp_path)
    assert out.is_file()

    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert rows
    paths = {row["path"] for row in rows}
    assert paths == set(PATH_NAMES)

    for row in rows:
        for field in METRIC_FIELDS:
            val = (
                float(row[field])
                if field not in ("proof_size", "gates", "memory")
                else int(row[field])
            )
            assert val > 0, f"{row['path']}.{field} should be positive, got {val}"


def test_raw_csv_has_both_paths_per_n_acl(tmp_path):
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    by_n_acl: dict[int, set[str]] = defaultdict(set)
    for row in rows:
        by_n_acl[int(row["N_acl"])].add(row["path"])

    for n_acl, paths in by_n_acl.items():
        assert paths == set(PATH_NAMES), f"N_acl={n_acl} missing paths: {paths}"


def test_n_acl_leq_n_sel_and_acl_ratio(tmp_path):
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        n_sel = int(row["N_sel"])
        n_acl = int(row["N_acl"])
        assert n_acl <= n_sel
        ratio = float(row["acl_ratio"])
        assert abs(ratio - n_acl / n_sel) < 1e-5


def test_csv_schema(tmp_path):
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == CSV_FIELDS


def test_summary_script_runs(tmp_path):
    metrics = _run_bench(tmp_path)
    summary = tmp_path / "summary.csv"
    result = _run_summary(metrics, summary)
    assert result.returncode == 0, result.stderr
    assert summary.is_file()


def test_summary_csv_positive_medians(tmp_path):
    metrics = _run_bench(tmp_path)
    summary = tmp_path / "summary.csv"
    _run_summary(metrics, summary)

    with summary.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert rows
    assert set(rows[0].keys()) == set(SUMMARY_FIELDS)
    for row in rows:
        assert int(row["median_gates"]) > 0
        assert float(row["median_prove_time"]) > 0
        assert int(row["median_proof_size"]) > 0


def test_small_n_acl_beats_committed_gates(tmp_path):
    """When N_acl=1, auth_acl_class gates should be below auth_committed."""
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    by_n_acl: dict[int, dict[str, int]] = defaultdict(dict)
    for row in rows:
        by_n_acl[int(row["N_acl"])][row["path"]] = int(row["gates"])

    assert 1 in by_n_acl
    committed = by_n_acl[1]["auth_committed"]
    acl = by_n_acl[1]["auth_acl_class"]
    assert acl < committed, (
        f"expected auth_acl_class gates < auth_committed at N_acl=1; "
        f"got acl={acl} committed={committed}"
    )


def test_degenerate_n_acl_near_n_sel_not_required_to_win(tmp_path):
    """N_acl close to N_sel may not beat committed; only check data exists."""
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    max_n_acl = max(int(r["N_acl"]) for r in rows)
    degenerate = [r for r in rows if int(r["N_acl"]) == max_n_acl]
    assert len(degenerate) == 2
    paths = {r["path"] for r in degenerate}
    assert paths == set(PATH_NAMES)


def test_filter_n_acl_list():
    assert filter_n_acl_list([1, 2, 4, 8, 64], n_sel=32, n_valid=30) == [1, 2, 4, 8]
    assert filter_n_acl_list([1, 100], n_sel=256, n_valid=200) == [1, 100]


def test_summary_acl_vs_committed_ratios(tmp_path):
    metrics = _run_bench(tmp_path)
    summary = tmp_path / "summary.csv"
    _run_summary(metrics, summary)

    with summary.open(newline="") as f:
        rows = list(csv.DictReader(f))

    acl_rows = [r for r in rows if r["path"] == "auth_acl_class"]
    assert acl_rows
    for row in acl_rows:
        assert row["acl_vs_committed_gates"]
        assert float(row["acl_vs_committed_gates"]) > 0
