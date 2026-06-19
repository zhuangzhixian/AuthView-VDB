"""Phase 8C: tests for public utility baseline (mock data only)."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from bench.acc_bench import _query_metrics
from scripts.make_public_utility_table import render_table
from scripts.plot_public_utility_figures import plot_recall
from scripts.run_public_utility_baseline import (
    METRICS_FIELDS,
    SUMMARY_FIELDS,
    V3DB_PUBLIC_CONFIGS,
    aggregate_results,
    build_summary_rows,
    compute_full_base,
    per_config_summary_path,
    recall_from_trace,
    recover_config_from_trace,
    resolve_configs,
    should_skip_config,
    trace_path_for,
    write_csv,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def write_fvecs(path: Path, vectors: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        for v in vectors:
            d = int(v.shape[0])
            f.write(np.array([d], dtype="<i4").tobytes())
            f.write(v.astype("<f4").tobytes())


def write_ivecs(path: Path, vectors: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        for v in vectors:
            d = int(v.shape[0])
            f.write(np.array([d], dtype="<i4").tobytes())
            f.write(v.astype("<i4").tobytes())


def _four_row_summary() -> list[dict]:
    return [
        {
            "dataset": "sift1m",
            "config": "high-acc",
            "data_name": "sift",
            "scheme": "standard",
            "M": 8,
            "K": 256,
            "top_k": 100,
            "n_list": 8192,
            "n_probe": 64,
            "cluster_bound": 256,
            "scale_n": 65536,
            "layout": "none",
            "num_base": 1_000_000,
            "num_queries": 10_000,
            "dim": 128,
            "full_base": "true",
            "recall_at_1": 0.3217,
            "recall_at_10": 0.7487,
            "recall_at_100": 0.9581,
            "build_time_s": 98.9,
            "query_time_s": 37.2,
            "qps": 268.8,
            "index_size_bytes": 76390912,
            "trace_path": "traces/sift1m_high-acc_results.npz",
        },
        {
            "dataset": "sift1m",
            "config": "zk-opt",
            "data_name": "sift",
            "scheme": "standard",
            "M": 8,
            "K": 256,
            "top_k": 100,
            "n_list": 1024,
            "n_probe": 8,
            "cluster_bound": 2048,
            "scale_n": 65536,
            "layout": "none",
            "num_base": 1_000_000,
            "num_queries": 10_000,
            "dim": 128,
            "full_base": "true",
            "recall_at_1": 0.2816,
            "recall_at_10": 0.6702,
            "recall_at_100": 0.8713,
            "build_time_s": 7.0,
            "query_time_s": 25.3,
            "qps": 395.4,
            "index_size_bytes": 72663552,
            "trace_path": "traces/sift1m_zk-opt_results.npz",
        },
        {
            "dataset": "gist1m",
            "config": "high-acc",
            "data_name": "gist",
            "scheme": "standard",
            "M": 8,
            "K": 256,
            "top_k": 100,
            "n_list": 8192,
            "n_probe": 64,
            "cluster_bound": 256,
            "scale_n": 65536,
            "layout": "none",
            "num_base": 1_000_000,
            "num_queries": 1_000,
            "dim": 960,
            "full_base": "true",
            "recall_at_1": 0.084,
            "recall_at_10": 0.241,
            "recall_at_100": 0.552,
            "build_time_s": 247.9,
            "query_time_s": 13.9,
            "qps": 72.0,
            "index_size_bytes": 104505856,
            "trace_path": "traces/gist1m_high-acc_results.npz",
        },
        {
            "dataset": "gist1m",
            "config": "zk-opt",
            "data_name": "gist",
            "scheme": "standard",
            "M": 8,
            "K": 256,
            "top_k": 100,
            "n_list": 512,
            "n_probe": 4,
            "cluster_bound": 4096,
            "scale_n": 65536,
            "layout": "none",
            "num_base": 1_000_000,
            "num_queries": 1_000,
            "dim": 960,
            "full_base": "true",
            "recall_at_1": 0.08,
            "recall_at_10": 0.211,
            "recall_at_100": 0.438,
            "build_time_s": 18.9,
            "query_time_s": 9.0,
            "qps": 110.9,
            "index_size_bytes": 74953216,
            "trace_path": "traces/gist1m_zk-opt_results.npz",
        },
    ]


def test_recall_at_k_hit_semantics():
    gt = np.array([42, 7, 3, 1], dtype=np.int64)
    pred_hit = np.array([99, 42, 1], dtype=np.int64)
    pred_miss = np.array([99, 98, 97], dtype=np.int64)

    hit = _query_metrics(scheme="standard", pred=pred_hit, gt_topk=gt, report_ks=(1, 10, 100))
    miss = _query_metrics(scheme="standard", pred=pred_miss, gt_topk=gt, report_ks=(1, 10, 100))

    assert hit["standard_recall_at_1"] == 0.0
    assert hit["standard_recall_at_10"] == 1.0
    assert hit["standard_recall_at_100"] == 1.0
    assert miss["standard_recall_at_10"] == 0.0


def test_summary_schema_includes_full_base(tmp_path):
    rows = _four_row_summary()
    summary_path = tmp_path / "summary.csv"
    write_csv(summary_path, rows, SUMMARY_FIELDS)
    with summary_path.open(newline="", encoding="utf-8") as f:
        summary = list(csv.DictReader(f))
    assert "full_base" in summary[0]
    assert summary[0]["full_base"] == "true"
    assert list(summary[0].keys()) == list(SUMMARY_FIELDS)


def test_recall_values_in_unit_interval():
    for row in _four_row_summary():
        for key in ("recall_at_1", "recall_at_10", "recall_at_100"):
            val = float(row[key])
            assert 0.0 <= val <= 1.0


def test_compute_full_base():
    assert compute_full_base("sift1m", 1_000_000, 10_000, 128) is True
    assert compute_full_base("gist1m", 1_000_000, 1_000, 960) is True
    assert compute_full_base("sift1m", 1000, 10, 128) is False


def test_resolve_configs_subset():
    cfgs = resolve_configs(["sift1m"], ["high-acc"])
    assert len(cfgs) == 1
    assert cfgs[0].config == "high-acc"


def test_skip_existing_when_summary_present(tmp_path):
    cfg = V3DB_PUBLIC_CONFIGS[0]
    out = tmp_path / "public_utility"
    write_csv(per_config_summary_path(out, cfg), _four_row_summary()[:1], SUMMARY_FIELDS)
    skip, _ = should_skip_config(cfg, out, skip_existing=True, only_missing=False)
    assert skip is True


def test_recall_from_trace_mock(tmp_path):
    cfg = V3DB_PUBLIC_CONFIGS[0]
    gt = np.array([[42, 7], [99, 1]], dtype=np.int64)
    pred = np.array([[0, 1], [99, 0]], dtype=np.int64)
    trace = trace_path_for(tmp_path, cfg)
    trace.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        trace,
        pred=pred,
        gt=gt,
        num_base=1_000_000,
        num_queries=2,
        dim=128,
        index_size_bytes=123,
    )
    recalls = recall_from_trace(trace)
    assert recalls["recall_at_1"] == 0.5
    assert recalls["recall_at_10"] == 0.5


def test_recover_from_trace_writes_per_config(tmp_path):
    cfg = V3DB_PUBLIC_CONFIGS[0]
    gt = np.array([[42, 7], [99, 1]], dtype=np.int64)
    pred = np.array([[42, 7], [99, 1]], dtype=np.int64)
    trace = trace_path_for(tmp_path, cfg)
    trace.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        trace,
        pred=pred,
        gt=gt,
        num_base=1_000_000,
        num_queries=10_000,
        dim=128,
        index_size_bytes=456,
    )
    rows = recover_config_from_trace(cfg, tmp_path, trace)
    assert rows[0]["full_base"] == "true"
    assert float(rows[0]["recall_at_1"]) == 1.0
    assert per_config_summary_path(tmp_path, cfg).is_file()


def test_aggregate_merges_per_config(tmp_path):
    out = tmp_path / "public_utility"
    for row in _four_row_summary():
        cfg = next(
            c for c in V3DB_PUBLIC_CONFIGS
            if c.dataset == row["dataset"] and c.config == row["config"]
        )
        write_csv(per_config_summary_path(out, cfg), [row], SUMMARY_FIELDS)
    _, summary_rows = aggregate_results(out)
    assert len(summary_rows) == 4
    assert all(r["full_base"] == "true" for r in summary_rows)


def test_plot_and_table_four_rows(tmp_path):
    rows = _four_row_summary()
    fig = tmp_path / "main_public_utility_recall.pdf"
    plot_recall(rows, fig)
    assert fig.is_file() and fig.stat().st_size > 0
    tex = render_table(rows)
    assert "SIFT1M" in tex and "GIST1M" in tex
    assert not list(tmp_path.glob("*.json"))


def test_build_summary_rows_filters_zk():
    rows = [
        {**_four_row_summary()[0], "scheme": "standard"},
        {**_four_row_summary()[0], "scheme": "zk", "recall_at_1": 0.1},
    ]
    summary = build_summary_rows(rows)
    assert len(summary) == 1
    assert summary[0]["scheme"] == "standard"


def test_plot_script_cli(tmp_path):
    summary = tmp_path / "summary.csv"
    write_csv(summary, _four_row_summary(), SUMMARY_FIELDS)
    out_dir = tmp_path / "figures"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/plot_public_utility_figures.py"),
            "--input",
            str(summary),
            "--output-dir",
            str(out_dir),
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert (out_dir / "main_public_utility_recall.pdf").is_file()
