"""Phase 9B: tests for full authorized-reference calibration."""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from scripts.auth_calibration_lib import (
    CALIBRATION_QUERY_FIELDS,
    CHECKPOINT_FIELDS,
    REFERENCE_SCOPE_CALIBRATION,
    aggregate_checkpoint_rows,
    append_csv,
    cap_queries_per_dataset,
    compute_query_features,
    estimate_calibration_cost,
    full_authorized_topk_chunked,
    full_authorized_topk_naive,
    load_completed_keys,
    load_csv,
    overlap_at_k,
    per_query_gap_bucket,
    per_query_underfill_bucket,
    select_calibration_queries,
    write_csv,
)
from scripts.auth_overlay_lib import generate_overlay, seed_for

ROOT = Path(__file__).resolve().parents[1]


def _write_fvecs(path: Path, vectors: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        for vec in vectors:
            dim = np.array([vec.size], dtype=np.int32)
            f.write(dim.tobytes())
            f.write(vec.astype(np.float32).tobytes())


def _write_ivecs(path: Path, vectors: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        for vec in vectors:
            dim = np.array([vec.size], dtype=np.int32)
            f.write(dim.tobytes())
            f.write(vec.astype(np.int32).tobytes())


def test_calibration_query_selection_reproducible():
    rng = np.random.default_rng(0)
    pred = rng.integers(0, 200, size=(50, 20), dtype=np.int64)
    gt = rng.integers(0, 200, size=(50, 1), dtype=np.int64)
    visible, _, _ = generate_overlay(
        dataset="mock",
        policy_mode="uniform_random",
        selectivity=0.25,
        num_base=200,
        seed=seed_for("mock", "uniform_random", 0.25, 42),
    )
    r1 = select_calibration_queries(
        trace_pred=pred,
        trace_gt=gt,
        dataset="mockds",
        config="high-acc",
        policy_mode="uniform_random",
        selectivity=0.25,
        visible=visible,
        candidate_depth=20,
        queries_per_bucket=2,
        rng=np.random.default_rng(123),
    )
    r2 = select_calibration_queries(
        trace_pred=pred,
        trace_gt=gt,
        dataset="mockds",
        config="high-acc",
        policy_mode="uniform_random",
        selectivity=0.25,
        visible=visible,
        candidate_depth=20,
        queries_per_bucket=2,
        rng=np.random.default_rng(123),
    )
    assert r1 == r2
    assert all("query_id" in r for r in r1)


def test_gap_and_underfill_buckets():
    assert per_query_gap_bucket(True, True, False) == "low"
    assert per_query_gap_bucket(False, True, True) == "high"
    assert per_query_gap_bucket(True, True, True) == "medium"
    assert per_query_underfill_bucket(True) == "underfill"
    assert per_query_underfill_bucket(False) == "filled"


def test_full_authorized_excludes_invisible():
    base = np.array(
        [
            [0.0, 0.0],
            [1.0, 0.0],
            [10.0, 0.0],
            [0.1, 0.0],
        ],
        dtype=np.float32,
    )
    visible = np.array([True, False, True, True], dtype=bool)
    query = np.array([0.0, 0.0], dtype=np.float32)
    full = full_authorized_topk_naive(query, base, visible, k=2)
    assert all(visible[i] for i in full)
    assert 1 not in full


def test_chunked_matches_naive(tmp_path: Path):
    rng = np.random.default_rng(7)
    dim = 8
    n = 64
    base = rng.random((n, dim), dtype=np.float32)
    visible = rng.random(n) < 0.4
    query = rng.random(dim, dtype=np.float32)
    tmp = tmp_path / "base.fvecs"
    _write_fvecs(tmp, base)
    k = 5
    naive = full_authorized_topk_naive(query, base, visible, k)
    chunked = full_authorized_topk_chunked(
        query, tmp, visible, dim=dim, k=k, chunk_size=16
    )
    assert naive == chunked


def test_metrics_overlap_and_recall():
    post = [0, 2]
    cand = [0, 3, 4]
    full = [0, 5, 6]
    assert overlap_at_k(post, full, 2) == 0.5
    assert overlap_at_k(cand, full, 3) == pytest.approx(1 / 3)


def test_resume_checkpoint_logic(tmp_path: Path):
    ckpt = tmp_path / "checkpoint.csv"
    rows = [
        {
            "dataset": "mock",
            "config": "high-acc",
            "policy_mode": "uniform_random",
            "selectivity": 0.5,
            "query_id": 1,
            "k": 10,
            "post_filter_recall": 1.0,
            "candidate_reference_recall": 1.0,
            "full_authorized_recall": 1.0,
            "post_filter_underfill": 0.0,
            "candidate_vs_full_overlap": 0.8,
            "post_filter_vs_full_overlap": 0.7,
            "reference_scope": REFERENCE_SCOPE_CALIBRATION,
            "full_base": True,
            "visible_count": 50,
            "visible_ratio": 0.5,
            "dim": 8,
            "num_base": 100,
        }
    ]
    append_csv(ckpt, rows, CHECKPOINT_FIELDS)
    keys = load_completed_keys(ckpt)
    assert ("mock", "high-acc", "uniform_random", "0.5", "1", "10") in keys
    summary = aggregate_checkpoint_rows(load_csv(ckpt))
    assert summary[0]["reference_scope"] == REFERENCE_SCOPE_CALIBRATION
    assert summary[0]["full_base"] is True


def test_estimate_cost():
    rows = [
        {"dataset": "sift1m", "selectivity": 0.1},
        {"dataset": "gist1m", "selectivity": 0.25},
    ]
    cost = estimate_calibration_cost(rows, chunk_size=10_000)
    assert cost["total_calibration_queries"] == 2
    assert cost["estimated_distance_ops"] > 0


def test_cap_queries_per_dataset():
    rows = [{"dataset": "sift1m", "query_id": i} for i in range(10)]
    capped = cap_queries_per_dataset(rows, max_per_dataset=3, seed=0)
    assert len(capped) == 3


def test_plot_table_on_mock_summary(tmp_path: Path):
    summary = tmp_path / "summary.csv"
    row = {
        "dataset": "sift1m",
        "config": "high-acc",
        "policy_mode": "uniform_random",
        "selectivity": 0.1,
        "k": 10,
        "num_queries": 5,
        "num_base": 1000000,
        "dim": 128,
        "full_base": True,
        "visible_count": 100000,
        "visible_ratio": 0.1,
        "post_filter_recall": 0.2,
        "candidate_reference_recall": 0.25,
        "full_authorized_recall": 0.3,
        "post_filter_underfill_rate": 0.8,
        "candidate_vs_full_overlap": 0.4,
        "post_filter_vs_full_overlap": 0.2,
        "candidate_full_recall_gap": -0.05,
        "post_full_recall_gap": -0.1,
        "reference_scope": REFERENCE_SCOPE_CALIBRATION,
    }
    write_csv(summary, [row], tuple(row.keys()))
    py = sys.executable
    env = {"PYTHONPATH": str(ROOT)}
    fig_dir = tmp_path / "fig"
    tex = tmp_path / "table.tex"
    subprocess.run(
        [
            py,
            str(ROOT / "scripts/plot_authorized_calibration_figures.py"),
            "--input",
            str(summary),
            "--output-dir",
            str(fig_dir),
        ],
        check=True,
        cwd=ROOT,
        env={**dict(__import__("os").environ), **env},
    )
    subprocess.run(
        [
            py,
            str(ROOT / "scripts/make_authorized_calibration_table.py"),
            "--input",
            str(summary),
            "--output",
            str(tex),
        ],
        check=True,
        cwd=ROOT,
        env={**dict(__import__("os").environ), **env},
    )
    assert (fig_dir / "main_authorized_reference_calibration.pdf").is_file()
    assert "full_base_calibration" in tex.read_text(encoding="utf-8")
    assert not list(tmp_path.glob("*.json"))


def test_compute_query_features():
    visible = np.array([True, False, True, True], dtype=bool)
    pred = np.array([1, 0, 2, 3], dtype=np.int64)
    gt = np.array([2], dtype=np.int64)
    feat = compute_query_features(pred, gt, visible, k=2, candidate_depth=4)
    assert feat.candidate_hit is True
    assert feat.post_hit is False
    assert feat.utility_gap == 1.0
