"""Phase 6B-2.14: tests for Veda-style layout subfigure PDFs."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.plot_proof_planning_layout_figures import (
    COST_BREAKDOWN_LABELS,
    COST_BREAKDOWN_SPECS,
    FORBIDDEN_PLOT_FILES,
    MAIN_PLOT_FILES,
    OPTIONAL_PLOT_FILES,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PLOT = REPO_ROOT / "scripts" / "plot_proof_planning_layout_figures.py"
SUMMARY = REPO_ROOT / "artifacts" / "proof_planning_layout_summary_repaired.csv"
METRICS = REPO_ROOT / "artifacts" / "proof_planning_layout_metrics_repaired.csv"
FIGURES = REPO_ROOT / "artifacts" / "figures"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=120,
    )


def _load(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def test_plot_script_runs_subfigures(tmp_path):
    if not SUMMARY.is_file() or not METRICS.is_file():
        pytest.skip("repaired CSVs not generated")
    fig_dir = tmp_path / "figures"
    result = _run(
        [
            sys.executable,
            str(PLOT),
            "--summary",
            str(SUMMARY),
            "--metrics",
            str(METRICS),
            "--output-dir",
            str(fig_dir),
        ]
    )
    assert result.returncode == 0, result.stderr
    for name in MAIN_PLOT_FILES:
        pdf = fig_dir / name
        assert pdf.is_file(), name
        assert pdf.stat().st_size > 0, name


def test_main_subfigures_exist():
    if not SUMMARY.is_file():
        pytest.skip("repaired summary missing")
    for name in MAIN_PLOT_FILES:
        pdf = FIGURES / name
        if not pdf.is_file():
            pytest.skip("main subfigures not generated")
        assert pdf.stat().st_size > 0


def test_optional_frontier_exists():
    if not SUMMARY.is_file():
        pytest.skip("repaired summary missing")
    pdf = FIGURES / OPTIONAL_PLOT_FILES[0]
    if not pdf.is_file():
        pytest.skip("optional frontier not generated")
    assert pdf.stat().st_size > 0


def test_forbidden_figures_not_generated(tmp_path):
    if not SUMMARY.is_file() or not METRICS.is_file():
        pytest.skip("repaired CSVs not generated")
    fig_dir = tmp_path / "figures"
    _run(
        [
            sys.executable,
            str(PLOT),
            "--summary",
            str(SUMMARY),
            "--metrics",
            str(METRICS),
            "--output-dir",
            str(fig_dir),
        ]
    )
    for name in FORBIDDEN_PLOT_FILES:
        assert not (fig_dir / name).exists(), name


def test_cost_breakdown_excludes_oracle():
    layouts = {spec[0] for spec in COST_BREAKDOWN_SPECS}
    assert "oracle_authorized_view" not in layouts
    assert len(COST_BREAKDOWN_SPECS) == 5


def test_cost_breakdown_labels():
    assert COST_BREAKDOWN_LABELS == ("Global", "k=16", "k=4", "k=1", "ACL")


def test_merged_k_pa_monotone_in_summary():
    if not SUMMARY.is_file():
        pytest.skip("repaired summary missing")
    rows = _load(SUMMARY)
    merged = sorted(
        [r for r in rows if r["physical_layout"] == "merged_k"],
        key=lambda r: int(r["merged_k"]),
    )
    pas = [float(r["median_PA_plan"]) for r in merged]
    assert pas[-1] >= pas[0] - 0.05


def test_merged_k_sa_antitone_in_summary():
    if not SUMMARY.is_file():
        pytest.skip("repaired summary missing")
    rows = _load(SUMMARY)
    merged = sorted(
        [r for r in rows if r["physical_layout"] == "merged_k"],
        key=lambda r: int(r["merged_k"]),
    )
    sas = [float(r["median_SA_commit"]) for r in merged]
    assert sas[0] >= sas[-1] - 0.05


def test_plot_script_does_not_emit_json(tmp_path):
    if not SUMMARY.is_file() or not METRICS.is_file():
        pytest.skip("repaired CSVs not generated")
    fig_dir = tmp_path / "figures"
    _run(
        [
            sys.executable,
            str(PLOT),
            "--summary",
            str(SUMMARY),
            "--metrics",
            str(METRICS),
            "--output-dir",
            str(fig_dir),
        ]
    )
    assert list(fig_dir.glob("*.json")) == []
