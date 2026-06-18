"""Phase 8B: tests for fvecs/ivecs dataset checker."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from scripts.check_fvecs_dataset import (
    check_dataset,
    peek_vec_dim,
    read_fvecs_sample,
    read_ivecs_sample,
    render_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_fvecs_dataset.py"


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


def test_peek_and_sample_fvecs(tmp_path):
    vecs = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
    path = tmp_path / "x.fvecs"
    write_fvecs(path, vecs)
    assert peek_vec_dim(path) == 2
    sample = read_fvecs_sample(path, sample=2)
    assert sample.shape == (2, 2)
    np.testing.assert_allclose(sample[0], vecs[0])


def test_read_ivecs_sample(tmp_path):
    gt = np.array([[0, 1, 2], [3, 4, 5]], dtype=np.int32)
    path = tmp_path / "gt.ivecs"
    write_ivecs(path, gt)
    sample = read_ivecs_sample(path, sample=1)
    assert sample.shape == (1, 3)


def test_check_sift1m_ok(tmp_path):
    d = tmp_path / "sift1m"
    write_fvecs(d / "sift_base.fvecs", np.random.rand(20, 128).astype(np.float32))
    write_fvecs(d / "sift_query.fvecs", np.random.rand(5, 128).astype(np.float32))
    write_ivecs(
        d / "sift_groundtruth.ivecs",
        np.arange(100, dtype=np.int32).reshape(1, -1).repeat(5, axis=0),
    )
    result = check_dataset("sift1m", data_root=tmp_path, sample=3)
    assert result.status == "ok"
    assert result.dim_matches_expected
    assert result.dim_consistent


def test_check_gist1m_dim_mismatch(tmp_path):
    d = tmp_path / "gist1m"
    write_fvecs(d / "gist_base.fvecs", np.random.rand(5, 128).astype(np.float32))
    write_fvecs(d / "gist_query.fvecs", np.random.rand(2, 128).astype(np.float32))
    write_ivecs(
        d / "gist_groundtruth.ivecs",
        np.arange(10, dtype=np.int32).reshape(1, -1).repeat(2, axis=0),
    )
    result = check_dataset("gist1m", data_root=tmp_path, sample=2)
    assert result.status == "error"
    assert not result.dim_matches_expected


def test_check_missing_partial(tmp_path):
    d = tmp_path / "sift1m"
    d.mkdir()
    write_fvecs(d / "sift_base.fvecs", np.random.rand(2, 128).astype(np.float32))
    result = check_dataset("sift1m", data_root=tmp_path, sample=1)
    assert result.status == "partial"


def test_render_report_no_json(tmp_path):
    result = check_dataset("sift1m", data_root=tmp_path, sample=1)
    md = render_report([result], sample=1)
    assert "# FVECS Dataset Check Report" in md
    assert not list(tmp_path.glob("*.json"))


def test_cli_runs(tmp_path):
    out = tmp_path / "check.md"
    result = subprocess.run(
        [
            sys.executable,
            str(CHECK_SCRIPT),
            "--dataset",
            "sift1m",
            "--data-root",
            str(tmp_path),
            "--output",
            str(out),
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert out.is_file()
