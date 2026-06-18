"""Phase 7B: tests for ACL-class repeat=3 outputs and RQ3 figure/table export."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.plot_acl_class_figures import MAIN_PLOT_FILES, N_ACL_ORDER
from scripts.make_acl_class_table import interpret_sharing

REPO_ROOT = Path(__file__).resolve().parents[1]
METRICS = REPO_ROOT / "artifacts" / "auth_zk_acl_class_metrics_repeat3.csv"
SUMMARY = REPO_ROOT / "artifacts" / "auth_zk_acl_class_summary_repeat3.csv"
PLOT = REPO_ROOT / "scripts" / "plot_acl_class_figures.py"
TABLE = REPO_ROOT / "scripts" / "make_acl_class_table.py"
FIGURES = REPO_ROOT / "artifacts" / "figures"
TABLE_OUT = REPO_ROOT / "artifacts" / "tables" / "table_acl_class_summary.tex"

EXPECTED_N_ACL = {1, 2, 4, 8, 16, 32, 64}


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _load(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def test_repeat3_metrics_exists():
    if not METRICS.is_file():
        pytest.skip("repeat3 metrics not generated")
    assert METRICS.stat().st_size > 0


def test_repeat3_summary_exists():
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary not generated")
    assert SUMMARY.stat().st_size > 0


def test_n_acl_sweep_in_summary():
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
    acl_rows = [r for r in _load(SUMMARY) if r["path"] == "auth_acl_class"]
    n_acl_set = {int(float(r["N_acl"])) for r in acl_rows}
    assert EXPECTED_N_ACL.issubset(n_acl_set)


def test_repeat3_has_three_repeats():
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
    acl_rows = [r for r in _load(SUMMARY) if r["path"] == "auth_acl_class"]
    assert all(int(float(r["n_repeats"])) >= 3 for r in acl_rows)


def test_small_n_acl_gates_ratio_below_one():
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
    row = next(
        r
        for r in _load(SUMMARY)
        if r["path"] == "auth_acl_class" and int(float(r["N_acl"])) == 1
    )
    ratio = float(row["acl_vs_committed_gates"])
    assert ratio < 1.0


def test_gates_ratio_increases_with_n_acl_mostly():
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
    acl_rows = sorted(
        [r for r in _load(SUMMARY) if r["path"] == "auth_acl_class"],
        key=lambda r: int(float(r["N_acl"])),
    )
    ratios = [float(r["acl_vs_committed_gates"]) for r in acl_rows]
    assert ratios[0] < ratios[-1]


def test_plot_script_runs(tmp_path):
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
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
    pdf = fig_dir / MAIN_PLOT_FILES[0]
    assert pdf.is_file() and pdf.stat().st_size > 0


def test_table_script_runs(tmp_path):
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
    out = tmp_path / "table_acl_class_summary.tex"
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


def test_main_acl_class_figure_exists():
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
    pdf = FIGURES / MAIN_PLOT_FILES[0]
    if not pdf.is_file():
        pytest.skip("figure not generated")
    assert pdf.stat().st_size > 0


def test_table_exists_with_interpretation():
    if not TABLE_OUT.is_file():
        pytest.skip("table not generated")
    text = TABLE_OUT.read_text(encoding="utf-8")
    assert "strong sharing" in text or "moderate sharing" in text
    assert "Gates ratio" in text


def test_no_json_generated(tmp_path):
    if not SUMMARY.is_file():
        pytest.skip("repeat3 summary missing")
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
            str(tab_dir / "table_acl_class_summary.tex"),
        ]
    )
    assert list(fig_dir.glob("*.json")) == []
    assert list(tab_dir.glob("*.json")) == []


def test_interpretation_labels():
    assert interpret_sharing(0.90) == "strong sharing"
    assert interpret_sharing(1.00) == "moderate sharing"
    assert interpret_sharing(1.50) == "degenerate / near object-level"
