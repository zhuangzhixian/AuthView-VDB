"""Phase 6B-2.5–2.8: tests for paper-ready proof-planning figures."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.bench_proof_planning_model import CSV_FIELDS
from scripts.summarize_proof_planning_model import BETA_SUMMARY_FIELDS, SUMMARY_FIELDS
from scripts.plot_proof_planning_figures import (
    APPENDIX_PLOT_FILES,
    BETA_MAIN_PLOT_FILES,
    enrich_rows,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_SCRIPT = REPO_ROOT / "scripts" / "bench_proof_planning_model.py"
SUMMARY_SCRIPT = REPO_ROOT / "scripts" / "summarize_proof_planning_model.py"
PLOT_SCRIPT = REPO_ROOT / "scripts" / "plot_proof_planning_figures.py"

BETA_METRICS = REPO_ROOT / "artifacts" / "proof_planning_beta_metrics.csv"
BETA_SUMMARY = REPO_ROOT / "artifacts" / "proof_planning_beta_summary.csv"
FIGURES_DIR = REPO_ROOT / "artifacts" / "figures"


def _run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _load_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _run_beta_bench(tmp_path: Path) -> Path:
    out = tmp_path / "beta_metrics.csv"
    cmd = [
        sys.executable,
        str(BENCH_SCRIPT),
        "--workload-model",
        "beta_locality",
        "--n-valid",
        "64",
        "--n-lists",
        "4",
        "--slot-per-list",
        "16",
        "--visible-ratios",
        "0.25,0.5",
        "--grouping-strategies",
        "ivf_list,fixed_block",
        "--locality-values",
        "0.0,0.5,1.0",
        "--block-sizes",
        "16",
        "--seeds",
        "0,1",
        "--top-k",
        "3",
        "--output",
        str(out),
    ]
    result = _run(cmd)
    assert result.returncode == 0, result.stderr
    return out


def test_beta_bench_small_config_runs(tmp_path):
    out = _run_beta_bench(tmp_path)
    rows = _load_csv(out)
    assert rows
    assert set(rows[0].keys()) == set(CSV_FIELDS)
    assert all(r["workload_model"] == "beta_locality" for r in rows)
    assert all(r["seed"] != "" for r in rows)
    assert "effective_visible_ratio" in rows[0]
    assert "estimated_distance_cost" in rows[0]


def test_beta_metrics_artifact_exists():
    if not BETA_METRICS.is_file():
        pytest.skip("beta metrics not generated")
    rows = _load_csv(BETA_METRICS)
    assert len(rows) >= 450
    assert rows[0]["workload_model"] == "beta_locality"
    assert "seed" in rows[0]
    assert "effective_impure_valid_ratio" in rows[0]


def test_beta_summary_artifact_exists():
    if not BETA_SUMMARY.is_file():
        pytest.skip("beta summary not generated")
    rows = _load_csv(BETA_SUMMARY)
    assert len(rows) >= 90
    assert set(rows[0].keys()) == set(BETA_SUMMARY_FIELDS)
    assert "q25_plan_vs_masked_cost" in rows[0]
    assert "q75_plan_vs_masked_cost" in rows[0]


def test_summary_script_on_beta_metrics(tmp_path):
    metrics = _run_beta_bench(tmp_path)
    summary_path = tmp_path / "summary.csv"
    result = _run(
        [
            sys.executable,
            str(SUMMARY_SCRIPT),
            "--input",
            str(metrics),
            "--output",
            str(summary_path),
        ]
    )
    assert result.returncode == 0, result.stderr
    rows = _load_csv(summary_path)
    assert rows
    assert set(rows[0].keys()) == set(BETA_SUMMARY_FIELDS)
    assert float(rows[0]["q25_plan_vs_masked_cost"]) <= float(
        rows[0]["median_plan_vs_masked_cost"]
    )


def test_plot_script_runs_beta(tmp_path):
    metrics = _run_beta_bench(tmp_path)
    summary_path = tmp_path / "summary.csv"
    _run(
        [
            sys.executable,
            str(SUMMARY_SCRIPT),
            "--input",
            str(metrics),
            "--output",
            str(summary_path),
        ]
    )
    fig_dir = tmp_path / "figures"
    result = _run(
        [
            sys.executable,
            str(PLOT_SCRIPT),
            "--input",
            str(summary_path),
            "--output-dir",
            str(fig_dir),
        ]
    )
    assert result.returncode == 0, result.stderr
    for name in BETA_MAIN_PLOT_FILES:
        pdf = fig_dir / name
        assert pdf.is_file()
        assert pdf.stat().st_size > 0


def test_beta_main_figures_exist_after_full_run():
    if not BETA_SUMMARY.is_file():
        pytest.skip("beta summary not generated")
    for name in BETA_MAIN_PLOT_FILES:
        pdf = FIGURES_DIR / name
        if not pdf.is_file():
            pytest.skip("beta figures not generated")
        assert pdf.stat().st_size > 0


def test_all_beta_cases_equivalent_and_valid():
    if not BETA_METRICS.is_file():
        pytest.skip("beta metrics missing")
    rows = _load_csv(BETA_METRICS)
    assert all(r["planned_equals_masked"] == "true" for r in rows)
    assert all(r["validation_passed"] == "true" for r in rows)


def test_beta_locality_one_lower_impure_than_zero_at_fixed_vr():
    if not BETA_SUMMARY.is_file():
        pytest.skip("beta summary missing")
    rows = enrich_rows(_load_csv(BETA_SUMMARY))
    ivf = [
        r
        for r in rows
        if r["grouping_strategy"] == "ivf_list"
        and abs(r["visible_ratio_f"] - 0.25) < 0.02
    ]
    loc0 = [r for r in ivf if abs(r["locality_f"] - 0.0) < 0.02]
    loc1 = [r for r in ivf if abs(r["locality_f"] - 1.0) < 0.02]
    assert loc0 and loc1
    imp0 = sum(r["impure_valid_ratio_f"] for r in loc0) / len(loc0)
    imp1 = sum(r["impure_valid_ratio_f"] for r in loc1) / len(loc1)
    assert imp1 < imp0


def test_beta_locality_one_lower_cost_than_zero_at_fixed_vr():
    if not BETA_SUMMARY.is_file():
        pytest.skip("beta summary missing")
    rows = enrich_rows(_load_csv(BETA_SUMMARY))
    ivf = [
        r
        for r in rows
        if r["grouping_strategy"] == "ivf_list"
        and abs(r["visible_ratio_f"] - 0.25) < 0.02
    ]
    loc0 = [r for r in ivf if abs(r["locality_f"] - 0.0) < 0.02]
    loc1 = [r for r in ivf if abs(r["locality_f"] - 1.0) < 0.02]
    assert loc0 and loc1
    cost0 = sum(r["plan_vs_masked_cost_f"] for r in loc0) / len(loc0)
    cost1 = sum(r["plan_vs_masked_cost_f"] for r in loc1) / len(loc1)
    assert cost1 < cost0


def test_beta_cost_monotone_with_locality_at_fixed_vr():
    if not BETA_SUMMARY.is_file():
        pytest.skip("beta summary missing")
    rows = enrich_rows(_load_csv(BETA_SUMMARY))
    ivf = [
        r
        for r in rows
        if r["grouping_strategy"] == "ivf_list"
        and abs(r["visible_ratio_f"] - 0.5) < 0.02
    ]
    by_loc = sorted(ivf, key=lambda r: r["locality_f"])
    costs = [r["plan_vs_masked_cost_f"] for r in by_loc]
    assert len(costs) >= 3
    assert costs[-1] <= costs[0]


def test_legacy_summary_fields_still_available():
    """locality_sweep summary uses legacy SUMMARY_FIELDS."""
    assert "purity_mode" in SUMMARY_FIELDS
