"""Phase 6B-2: tests for proof-planning cost-model sweep scripts."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

from scripts.bench_proof_planning_model import CSV_FIELDS, evaluate_case, run_benchmark
from scripts.summarize_proof_planning_model import SUMMARY_FIELDS, summarize

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_SCRIPT = REPO_ROOT / "scripts" / "bench_proof_planning_model.py"
SUMMARY_SCRIPT = REPO_ROOT / "scripts" / "summarize_proof_planning_model.py"


def _run_bench(tmp_path: Path, extra_args: list[str] | None = None) -> Path:
    out = tmp_path / "metrics.csv"
    cmd = [
        sys.executable,
        str(BENCH_SCRIPT),
        "--n-valid",
        "32",
        "--n-lists",
        "2",
        "--slot-per-list",
        "16",
        "--visible-ratios",
        "0.0,0.5,1.0",
        "--grouping-strategies",
        "acl_class,ivf_list,fixed_block",
        "--purity-modes",
        "clustered,mixed,adversarial_mixed",
        "--block-sizes",
        "8,16",
        "--top-k",
        "3",
        "--output",
        str(out),
    ]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"bench_proof_planning_model failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
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


def _load_rows(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def test_bench_script_small_config_runs(tmp_path):
    out = _run_bench(tmp_path)
    assert out.is_file()
    rows = _load_rows(out)
    assert rows
    assert set(rows[0].keys()) == set(CSV_FIELDS)


def test_summary_script_runs(tmp_path):
    metrics = _run_bench(tmp_path)
    summary_path = tmp_path / "summary.csv"
    result = _run_summary(metrics, summary_path)
    assert result.returncode == 0, result.stderr
    assert summary_path.is_file()
    rows = _load_rows(summary_path)
    assert rows
    assert set(rows[0].keys()) == set(SUMMARY_FIELDS)


def test_all_cases_planned_equals_masked(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    assert all(r["planned_equals_masked"] == "true" for r in rows)


def test_all_cases_validation_passed(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    assert all(r["validation_passed"] == "true" for r in rows)


def test_all_invisible_clustered_low_dist_plan(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    invisible = [
        r
        for r in rows
        if float(r["visible_ratio"]) == 0.0 and r["purity_mode"] == "clustered"
    ]
    assert invisible
    for row in invisible:
        assert int(row["N_dist_plan"]) < int(row["N_dist_masked"])
        assert int(row["N_dist_plan"]) == 0


def test_all_visible_dist_plan_not_below_valid(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    visible = [r for r in rows if float(r["visible_ratio"]) == 1.0]
    assert visible
    for row in visible:
        assert int(row["N_dist_plan"]) >= int(row["N_valid"])


def test_clustered_higher_pure_region_ratio_than_adversarial(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    grouped: dict[tuple[str, str, str], dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        if float(row["visible_ratio"]) in (0.0, 1.0):
            continue
        key = (row["grouping_strategy"], row["visible_ratio"], row["block_size"])
        grouped[key][row["purity_mode"]].append(float(row["pure_region_ratio"]))

    compared = 0
    for key, modes in grouped.items():
        if "clustered" in modes and "adversarial_mixed" in modes:
            clustered_med = sum(modes["clustered"]) / len(modes["clustered"])
            adv_med = sum(modes["adversarial_mixed"]) / len(modes["adversarial_mixed"])
            assert clustered_med >= adv_med
            compared += 1
    assert compared >= 1


def test_adversarial_mixed_high_impure_ratio(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    mid = [
        r
        for r in rows
        if r["purity_mode"] == "adversarial_mixed" and float(r["visible_ratio"]) == 0.5
    ]
    assert mid
    for row in mid:
        assert float(row["impure_region_ratio"]) >= 0.5


def test_ideal_vs_masked_increases_with_visible_ratio(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    by_vr: dict[float, list[float]] = defaultdict(list)
    for row in rows:
        by_vr[float(row["visible_ratio"])].append(float(row["ideal_vs_masked_cost"]))
    medians = {vr: sum(v) / len(v) for vr, v in sorted(by_vr.items())}
    vrs = sorted(medians)
    for i in range(len(vrs) - 1):
        assert medians[vrs[i]] <= medians[vrs[i + 1]] + 1e-6


def test_plan_cost_decreases_with_invisible_clustered(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    clustered = [r for r in rows if r["purity_mode"] == "clustered"]
    by_vr = sorted({float(r["visible_ratio"]) for r in clustered})
    costs = []
    for vr in by_vr:
        subset = [r for r in clustered if float(r["visible_ratio"]) == vr]
        costs.append(
            sum(float(r["plan_vs_masked_cost"]) for r in subset) / len(subset)
        )
    assert costs[0] <= costs[-1]


def test_fixed_block_size_changes_region_count():
    import argparse

    args = argparse.Namespace(
        n_valid=32,
        n_lists=2,
        slot_per_list=16,
        visible_ratios=[0.5],
        grouping_strategies=["fixed_block"],
        purity_modes=["clustered"],
        block_sizes=[8, 32],
        top_k=3,
        workload_model="purity_sweep",
    )
    rows = run_benchmark(args)
    counts = {int(r["block_size"]): int(r["region_count"]) for r in rows}
    assert counts[8] != counts[32]


def test_pa_values_positive(tmp_path):
    rows = _load_rows(_run_bench(tmp_path))
    for row in rows:
        assert float(row["PA_plan"]) > 0
        assert float(row["PA_ideal"]) > 0


def test_degenerate_all_impure_near_masked_baseline():
    row = evaluate_case(
        case_id="degenerate_impure",
        workload_model="purity_sweep",
        grouping_strategy="ivf_list",
        purity_mode="adversarial_mixed",
        locality="",
        block_size=16,
        n_valid=8,
        n_lists=2,
        slot_per_list=4,
        target_visible_ratio=0.5,
        top_k=2,
        cost_params={
            "C_dist": 10,
            "C_vis": 3,
            "C_mask": 1,
            "C_region_pure": 5,
            "C_region_impure": 2,
            "C_topk_per_candidate": 1,
            "C_compact": 5,
        },
    )
    assert row["planned_equals_masked"] == "true"
    assert int(row["impure_regions"]) >= 1
    assert float(row["plan_vs_masked_cost"]) >= 1.0


def test_artifact_csv_exists_after_full_run():
    metrics = REPO_ROOT / "artifacts" / "proof_planning_model_metrics.csv"
    if not metrics.is_file():
        pytest.skip("full benchmark artifact not generated in this environment")
    rows = _load_rows(metrics)
    assert len(rows) >= 54
    assert all(r["planned_equals_masked"] == "true" for r in rows)


def test_summarize_in_memory():
    rows = [
        {
            "workload_model": "purity_sweep",
            "grouping_strategy": "ivf_list",
            "purity_mode": "clustered",
            "locality": "",
            "visible_ratio": "0.500000",
            "block_size": "16",
            "N_valid": "256",
            "impure_valid_count": "64",
            "region_count": "4",
            "pure_region_ratio": "0.750000",
            "impure_region_ratio": "0.250000",
            "dist_reduction_plan": "0.100000",
            "dist_reduction_ideal": "0.500000",
            "plan_vs_masked_cost": "0.900000",
            "ideal_vs_masked_cost": "0.600000",
            "PA_plan": "2.000000",
            "PA_ideal": "1.500000",
            "planned_equals_masked": "true",
            "validation_passed": "true",
        }
    ]
    summary = summarize(rows)
    assert len(summary) == 1
    assert summary[0]["cases"] == 1
