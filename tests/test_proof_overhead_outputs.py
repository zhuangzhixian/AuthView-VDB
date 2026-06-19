"""Phase 7A: tests for proof overhead figure/table export."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.plot_proof_overhead_figures import (
    MAIN_PLOT_FILES,
    OPTIONAL_PLOT_FILES,
    PATH_SHORT_LABELS,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY = REPO_ROOT / "artifacts" / "auth_zk_paper_ready_summary.csv"
PLOT = REPO_ROOT / "scripts" / "plot_proof_overhead_figures.py"
TABLE = REPO_ROOT / "scripts" / "make_proof_overhead_table.py"
FIGURES = REPO_ROOT / "artifacts" / "figures"
TABLE_OUT = REPO_ROOT / "artifacts" / "tables" / "table_proof_overhead.tex"


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
        assert pdf.is_file(), name
        assert pdf.stat().st_size > 0, name


def test_table_script_runs(tmp_path):
    if not SUMMARY.is_file():
        pytest.skip("paper-ready summary missing")
    out = tmp_path / "table_proof_overhead.tex"
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
    assert out.is_file()
    assert out.stat().st_size > 0


def test_main_overhead_figures_exist():
    if not SUMMARY.is_file():
        pytest.skip("summary missing")
    for name in MAIN_PLOT_FILES:
        pdf = FIGURES / name
        if not pdf.is_file():
            pytest.skip("figures not generated in artifacts/figures")
        assert pdf.stat().st_size > 0


def test_table_exists_with_paper_labels():
    if not SUMMARY.is_file():
        pytest.skip("summary missing")
    if not TABLE_OUT.is_file():
        pytest.skip("table not generated")
    text = TABLE_OUT.read_text(encoding="utf-8")
    assert "Content-only" in text
    assert "Committed-auth" in text
    assert "Slot-aligned" in text


def test_baseline_normalized_gates_in_table():
    if not TABLE_OUT.is_file():
        pytest.skip("table not generated")
    text = TABLE_OUT.read_text(encoding="utf-8")
    assert re.search(r"Content-only\s+&\s+\d+\s+&", text)
    assert re.search(r"Content-only.*&\s*1\.00\s+&\s*1\.00", text)


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
            str(tab_dir / "table_proof_overhead.tex"),
        ]
    )
    assert list(fig_dir.glob("*.json")) == []
    assert list(tab_dir.glob("*.json")) == []


def test_path_labels_defined_for_summary_paths():
    expected = {"baseline", "auth_committed", "auth_slot_aligned"}
    for p in expected:
        assert p in PATH_SHORT_LABELS
