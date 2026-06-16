"""Phase 2D/2E/3C: smoke tests for scripts/bench_auth_paths.py."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

from auth_reference.auth_commitment import next_pow2
from scripts.bench_auth_paths import (
    CSV_FIELDS,
    auth_tree_depth,
    slot_aligned_auth_tree_depth,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "bench_auth_paths.py"

PATH_NAMES = {
    "baseline",
    "auth_all_visible",
    "auth_policy",
    "auth_committed",
    "auth_slot_aligned",
}
METRIC_FIELDS = ("build_time", "prove_time", "verify_time", "proof_size", "memory", "gates")


def _run_bench(tmp_path: Path, extra_args: list[str] | None = None) -> Path:
    out = tmp_path / "metrics.csv"
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
        "--n-probe-list",
        "2",
        "--slot-per-list-list",
        "32",
        "--top-k-list",
        "3",
        "--n-iter",
        "4",
        "--seed",
        "7",
    ]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, (
        f"bench script failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return out


def _run_scaling_bench(tmp_path: Path) -> Path:
    out = tmp_path / "scaling_metrics.csv"
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
        "--n-probe-list",
        "2,4",
        "--slot-per-list-list",
        "32",
        "--top-k-list",
        "3,5",
        "--n-iter",
        "4",
        "--seed",
        "11",
    ]
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, (
        f"scaling bench failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return out


def test_bench_script_runs_and_writes_csv(tmp_path):
    out = _run_bench(tmp_path)
    assert out.is_file()

    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 5
    paths = {row["path"] for row in rows}
    assert paths == PATH_NAMES
    assert "auth_slot_aligned" in paths

    for row in rows:
        for field in METRIC_FIELDS:
            val = (
                float(row[field])
                if field not in ("proof_size", "gates")
                else int(row[field])
            )
            assert val > 0, f"{row['path']}.{field} should be positive, got {val}"


def test_bench_gate_ordering(tmp_path):
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        rows = {row["path"]: row for row in csv.DictReader(f)}

    baseline_gates = int(rows["baseline"]["gates"])
    policy_gates = int(rows["auth_policy"]["gates"])
    committed_gates = int(rows["auth_committed"]["gates"])
    slot_aligned_gates = int(rows["auth_slot_aligned"]["gates"])
    all_visible_gates = int(rows["auth_all_visible"]["gates"])

    assert policy_gates >= baseline_gates
    assert committed_gates >= policy_gates
    assert all_visible_gates >= baseline_gates
    assert slot_aligned_gates > 0
    assert committed_gates > 0


def test_scaling_bench_multiple_workloads(tmp_path):
    out = _run_scaling_bench(tmp_path)
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    # (n_probe=2, slot=32, top_k=3), (2,32,5), (4,32,3), (4,32,5) => 4 workloads × 5 paths
    assert len(rows) == 20
    workloads = {(int(r["n_probe"]), int(r["slot_per_list"]), int(r["top_k"])) for r in rows}
    assert len(workloads) == 4

    by_workload: dict[tuple[int, int, int], set[str]] = defaultdict(set)
    for row in rows:
        key = (int(row["n_probe"]), int(row["slot_per_list"]), int(row["top_k"]))
        by_workload[key].add(row["path"])

    for key, paths in by_workload.items():
        assert paths == PATH_NAMES, f"workload {key} missing paths: {paths}"


def test_scaling_n_sel_and_auth_tree_depth(tmp_path):
    out = _run_scaling_bench(tmp_path)
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    n_list = 4
    for row in rows:
        n_probe = int(row["n_probe"])
        slot = int(row["slot_per_list"])
        n_sel = int(row["N_sel"])
        depth = int(row["auth_tree_depth"])
        assert n_sel == n_probe * slot
        if row["path"] == "auth_slot_aligned":
            assert depth == slot_aligned_auth_tree_depth(n_list, slot)
        else:
            assert depth == auth_tree_depth(n_probe, slot)
            padded = next_pow2(n_sel)
            d = 0
            n = padded
            while n > 1:
                n //= 2
                d += 1
            assert depth == d


def test_scaling_gate_ordering_per_workload(tmp_path):
    out = _run_scaling_bench(tmp_path)
    with out.open(newline="") as f:
        rows = list(csv.DictReader(f))

    by_workload: dict[tuple[int, int, int], dict[str, int]] = defaultdict(dict)
    for row in rows:
        key = (int(row["n_probe"]), int(row["slot_per_list"]), int(row["top_k"]))
        by_workload[key][row["path"]] = int(row["gates"])

    for key, gates in by_workload.items():
        assert gates["auth_committed"] >= gates["auth_policy"] >= gates["baseline"], (
            f"gate ordering failed for workload {key}: {gates}"
        )
        assert gates["auth_slot_aligned"] > 0
        assert gates["auth_committed"] > 0


def test_slot_aligned_vs_committed_on_typical_workload(tmp_path):
    """At n_probe=4, slot=32 global committed should exceed slot-aligned gates."""
    out = tmp_path / "slot_cmp.csv"
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
        "13",
    ]
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, result.stderr

    with out.open(newline="") as f:
        rows = {row["path"]: row for row in csv.DictReader(f)}

    committed = int(rows["auth_committed"]["gates"])
    slot_aligned = int(rows["auth_slot_aligned"]["gates"])
    assert slot_aligned <= committed, (
        f"expected slot_aligned gates <= committed at n_probe=4 slot=32; "
        f"got slot={slot_aligned} committed={committed}"
    )


def test_csv_schema_unchanged(tmp_path):
    out = _run_bench(tmp_path)
    with out.open(newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == CSV_FIELDS
