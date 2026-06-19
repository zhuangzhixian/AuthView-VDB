"""Phase 7C: tests for RQ6 proof scaling figure/table export."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.plot_proof_scaling_figures import (
    MAIN_PLOT_FILES,
    PATH_LABELS,
    distinct_n_sel_values,
    load_csv,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY = REPO_ROOT / "artifacts" / "auth_zk_paper_ready_summary.csv"
PLOT = REPO_ROOT / "scripts" / "plot_proof_scaling_figures.py"
TABLE = REPO_ROOT / "scripts" / "make_proof_scaling_table.py"
FIGURES = REPO_ROOT / "artifacts" / "figures"
TABLE_OUT = REPO_ROOT / "artifacts" / "tables" / "table_proof_scaling_summary.tex"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_plot_script_runs(tmp_path):
    if not SUMMARY.is_file():
        pytest.skip("paper-ready summary missing")
    fig_dir = tmp_path / "figures"
    result = _run(
        [
            sys.executable,
            str(PLOT),
            "--input",
            str(SUMMARY),
            "--output-dir",
            str(fig_dir),
        ]
    )
    assert result.returncode == 0, result.stderr
    for name in MAIN_PLOT_FILES:
        pdf = fig_dir / name
        assert pdf.is_file() and pdf.stat().st_size > 0, name


def test_table_script_runs(tmp_path):
    if not SUMMARY.is_file():
        pytest.skip("paper-ready summary missing")
    out = tmp_path / "table_proof_scaling_summary.tex"
    result = _run(
        [
            sys.executable,
            str(TABLE),
            "--input",
            str(SUMMARY),
            "--output",
            str(out),
        ]
    )
    assert result.returncode == 0, result.stderr
    assert out.is_file() and out.stat().st_size > 0


def test_scaling_figures_exist():
    if not SUMMARY.is_file():
        pytest.skip("summary missing")
    for name in MAIN_PLOT_FILES:
        pdf = FIGURES / name
        if not pdf.is_file():
            pytest.skip("scaling figures not generated")
        assert pdf.stat().st_size > 0


def test_table_exists_with_paper_labels():
    if not TABLE_OUT.is_file():
        pytest.skip("scaling table not generated")
    text = TABLE_OUT.read_text(encoding="utf-8")
    assert "Content-only" in text
    assert "Committed-auth" in text
    assert "Slot-aligned" in text


def test_multiple_n_sel_values():
    if not SUMMARY.is_file():
        pytest.skip("summary missing")
    n_sel = distinct_n_sel_values(load_csv(SUMMARY))
    assert len(n_sel) >= 3


def test_no_json_generated(tmp_path):
    if not SUMMARY.is_file():
        pytest.skip("summary missing")
    fig_dir = tmp_path / "figures"
    tab_dir = tmp_path / "tables"
    tab_dir.mkdir()
    _run(
        [
            sys.executable,
            str(PLOT),
            "--input",
            str(SUMMARY),
            "--output-dir",
            str(fig_dir),
        ]
    )
    _run(
        [
            sys.executable,
            str(TABLE),
            "--input",
            str(SUMMARY),
            "--output",
            str(tab_dir / "table_proof_scaling_summary.tex"),
        ]
    )
    assert list(fig_dir.glob("*.json")) == []
    assert list(tab_dir.glob("*.json")) == []


def test_path_labels_defined():
    assert "baseline" in PATH_LABELS
    assert PATH_LABELS["baseline"] == "Content-only"
    assert PATH_LABELS["auth_committed"] == "Committed-auth"
