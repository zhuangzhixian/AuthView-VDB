"""Phase 9A: tests for authorization overlay on public benchmark traces."""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from scripts.auth_overlay_lib import (
    REFERENCE_SCOPE,
    evaluate_trace_with_visibility,
    generate_overlay,
    post_filter_results,
    seed_for,
)

ROOT = Path(__file__).resolve().parents[1]


def _mock_trace(num_queries: int = 8, depth: int = 20, num_base: int = 200) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(0)
    pred = rng.integers(0, num_base, size=(num_queries, depth), dtype=np.int64)
    gt = rng.integers(0, num_base, size=(num_queries, 1), dtype=np.int64)
    return pred, gt


def test_visibility_mask_reproducible():
    seed = seed_for("sift1m", "uniform_random", 0.25, 42)
    v1, _, _ = generate_overlay(
        dataset="sift1m",
        policy_mode="uniform_random",
        selectivity=0.25,
        num_base=10_000,
        seed=seed,
    )
    v2, _, _ = generate_overlay(
        dataset="sift1m",
        policy_mode="uniform_random",
        selectivity=0.25,
        num_base=10_000,
        seed=seed,
    )
    assert np.array_equal(v1, v2)


@pytest.mark.parametrize("selectivity", [0.1, 0.25, 0.5, 0.75])
@pytest.mark.parametrize("policy_mode", ["uniform_random", "clustered_acl", "skewed_acl"])
def test_selectivity_approximate_target(selectivity: float, policy_mode: str):
    num_base = 50_000
    seed = seed_for("mock", policy_mode, selectivity, 7)
    visible, _, observed = generate_overlay(
        dataset="mock",
        policy_mode=policy_mode,
        selectivity=selectivity,
        num_base=num_base,
        seed=seed,
    )
    assert visible.dtype == bool
    assert visible.size == num_base
    tol = 0.08 if policy_mode == "skewed_acl" else 0.05
    assert abs(observed - selectivity) <= tol


def test_post_filter_removes_invisible():
    visible = np.array([True, False, True, False, True], dtype=bool)
    pred = np.array([1, 0, 3, 2, 4], dtype=np.int64)
    result = post_filter_results(pred, visible, k=5)
    assert result == [0, 2, 4]
    assert all(visible[cid] for cid in result)


def test_underfill_rate():
    pred, gt = _mock_trace(num_queries=4, depth=10, num_base=50)
    visible = np.zeros(50, dtype=bool)
    visible[[pred[0, 0]]] = True
    aggs = evaluate_trace_with_visibility(
        pred=pred,
        gt=gt,
        visible=visible,
        dataset="mock",
        config="high-acc",
        policy_mode="uniform_random",
        selectivity=0.01,
        ks=[10],
        candidate_depth=10,
    )
    agg = aggs[0]
    assert agg.k == 10
    assert 0.0 <= agg.underfill_rate <= 1.0
    assert agg.underfill_rate == 1.0


def test_violation_rate_zero_for_correct_post_filter():
    pred, gt = _mock_trace(num_queries=16, depth=15, num_base=100)
    visible, _, _ = generate_overlay(
        dataset="mock",
        policy_mode="uniform_random",
        selectivity=0.5,
        num_base=100,
        seed=123,
    )
    aggs = evaluate_trace_with_visibility(
        pred=pred,
        gt=gt,
        visible=visible,
        dataset="mock",
        config="zk-opt",
        policy_mode="uniform_random",
        selectivity=0.5,
        ks=[10],
        candidate_depth=15,
    )
    assert aggs[0].violation_count == 0
    assert aggs[0].violation_rate == 0.0


def test_recall_in_unit_interval():
    pred, gt = _mock_trace(num_queries=32, depth=25, num_base=300)
    visible, _, _ = generate_overlay(
        dataset="mock",
        policy_mode="clustered_acl",
        selectivity=0.25,
        num_base=300,
        seed=99,
    )
    aggs = evaluate_trace_with_visibility(
        pred=pred,
        gt=gt,
        visible=visible,
        dataset="mock",
        config="high-acc",
        policy_mode="clustered_acl",
        selectivity=0.25,
        ks=[1, 10, 100],
        candidate_depth=25,
    )
    for agg in aggs:
        for name in ("unrestricted_recall", "post_filter_recall", "authorized_recall"):
            val = getattr(agg, name)
            assert 0.0 <= val <= 1.0


def test_candidate_level_reference_scope_in_summary(tmp_path: Path):
    pred, gt = _mock_trace()
    visible = np.ones(200, dtype=bool)
    aggs = evaluate_trace_with_visibility(
        pred=pred,
        gt=gt,
        visible=visible,
        dataset="mock",
        config="high-acc",
        policy_mode="uniform_random",
        selectivity=1.0,
        ks=[10],
        candidate_depth=pred.shape[1],
    )
    row = aggs[0].to_row()
    assert row["reference_scope"] == REFERENCE_SCOPE == "candidate_level"


def test_utility_gap_when_authorized_beats_post_filter():
    visible = np.zeros(10, dtype=bool)
    visible[2] = True
    visible[3] = True
    pred = np.array([[0, 1, 2, 3, 4]], dtype=np.int64)
    gt = np.array([[2]], dtype=np.int64)
    aggs = evaluate_trace_with_visibility(
        pred=pred,
        gt=gt,
        visible=visible,
        dataset="mock",
        config="high-acc",
        policy_mode="uniform_random",
        selectivity=0.2,
        ks=[2],
        candidate_depth=5,
    )
    agg = aggs[0]
    assert agg.post_filter_recall == 0.0
    assert agg.authorized_recall == 1.0
    assert agg.utility_gap == 1.0
    assert agg.affected_query_rate == 1.0


def test_plot_and_table_scripts_on_mock_csv(tmp_path: Path):
    summary = tmp_path / "public_trace_auth_summary.csv"
    rows = [
        {
            "dataset": "sift1m",
            "config": "high-acc",
            "policy_mode": "uniform_random",
            "selectivity": 0.1,
            "k": 10,
            "num_queries": 100,
            "visible_ratio": 0.1,
            "unrestricted_recall": 0.7,
            "post_filter_recall": 0.5,
            "authorized_recall": 0.55,
            "underfill_rate": 0.8,
            "avg_visible_results": 2.0,
            "violation_count": 0,
            "violation_rate": 0.0,
            "utility_gap": 0.05,
            "affected_query_rate": 0.2,
            "reference_scope": "candidate_level",
        },
        {
            "dataset": "sift1m",
            "config": "high-acc",
            "policy_mode": "uniform_random",
            "selectivity": 0.25,
            "k": 10,
            "num_queries": 100,
            "visible_ratio": 0.25,
            "unrestricted_recall": 0.72,
            "post_filter_recall": 0.6,
            "authorized_recall": 0.65,
            "underfill_rate": 0.5,
            "avg_visible_results": 5.0,
            "violation_count": 0,
            "violation_rate": 0.0,
            "utility_gap": 0.05,
            "affected_query_rate": 0.15,
            "reference_scope": "candidate_level",
        },
    ]
    with summary.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    fig_dir = tmp_path / "figures"
    table_out = tmp_path / "table.tex"
    py = sys.executable
    env = {"PYTHONPATH": str(ROOT)}
    subprocess.run(
        [py, str(ROOT / "scripts/plot_authorization_overlay_figures.py"), "--input", str(summary), "--output-dir", str(fig_dir)],
        check=True,
        cwd=ROOT,
        env={**dict(__import__("os").environ), **env},
    )
    subprocess.run(
        [py, str(ROOT / "scripts/make_authorization_overlay_table.py"), "--input", str(summary), "--output", str(table_out)],
        check=True,
        cwd=ROOT,
        env={**dict(__import__("os").environ), **env},
    )
    assert (fig_dir / "main_auth_overlay_utility_gap.pdf").is_file()
    assert (fig_dir / "main_auth_overlay_underfill.pdf").is_file()
    assert table_out.is_file()
    assert "candidate_level" in table_out.read_text(encoding="utf-8")
    assert not list(tmp_path.glob("*.json"))


def test_no_json_from_generate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "auth_overlay"
    monkeypatch.chdir(ROOT)
    py = sys.executable
    env = {"PYTHONPATH": str(ROOT)}
    subprocess.run(
        [
            py,
            "scripts/generate_authorization_overlay.py",
            "--datasets",
            "sift1m",
            "--num-base-from-summary",
            str(ROOT / "artifacts/public_utility/sift_gist_utility_summary.csv"),
            "--policy-modes",
            "uniform_random",
            "--selectivities",
            "0.5",
            "--output-dir",
            str(out),
            "--seed",
            "42",
            "--sample-size",
            "100",
        ],
        check=True,
        cwd=ROOT,
        env={**dict(__import__("os").environ), **env},
    )
    assert (out / "sift1m_uniform_random_overlay_summary.csv").is_file()
    assert not list(out.glob("*.json"))
