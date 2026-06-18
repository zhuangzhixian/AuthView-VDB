"""Phase 8B: tests for TEXMEX dataset preparation script."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from scripts.prepare_texmex_datasets import (
    DATASET_SPECS,
    check_dataset_files,
    dataset_status_from_checks,
    ensure_dataset_dirs,
    link_v3db_compat,
    normalize_dataset_files,
    prepare_one,
    render_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PREPARE_SCRIPT = REPO_ROOT / "scripts" / "prepare_texmex_datasets.py"


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


def _populate_sift1m(directory: Path) -> None:
    write_fvecs(directory / "sift_base.fvecs", np.random.rand(10, 128).astype(np.float32))
    write_fvecs(directory / "sift_query.fvecs", np.random.rand(3, 128).astype(np.float32))
    write_ivecs(directory / "sift_groundtruth.ivecs", np.arange(100, dtype=np.int32).reshape(1, -1).repeat(3, axis=0))


def test_ensure_dataset_dirs(tmp_path):
    created = ensure_dataset_dirs(tmp_path, ["sift1m", "gist1m"])
    assert len(created) == 2
    assert (tmp_path / "sift1m").is_dir()
    assert (tmp_path / "gist1m").is_dir()


def test_check_only_ready_status(tmp_path):
    sift_dir = tmp_path / "sift1m"
    _populate_sift1m(sift_dir)
    result = prepare_one(
        "sift1m",
        data_root=tmp_path,
        download=False,
        link_v3db=False,
        check_only=True,
    )
    assert result.status == "ready"
    assert all(c.exists for c in result.checks if c.role in ("base", "query", "groundtruth"))


def test_check_only_missing_status(tmp_path):
    ensure_dataset_dirs(tmp_path, ["sift1m"])
    result = prepare_one(
        "sift1m",
        data_root=tmp_path,
        download=False,
        link_v3db=False,
        check_only=True,
    )
    assert result.status == "missing"


def test_normalize_symlink_from_alt_name(tmp_path):
    spec = DATASET_SPECS["sift1m"]
    directory = tmp_path / "sift1m"
    directory.mkdir()
    alt = directory / "other_base.fvecs"
    write_fvecs(alt, np.ones((2, 128), dtype=np.float32))
    notes = normalize_dataset_files(directory, spec)
    assert (directory / "sift_base.fvecs").exists()
    assert any("symlink" in n for n in notes)


def test_link_v3db_creates_symlink(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data" / "public" / "sift1m").mkdir(parents=True)
    _populate_sift1m(tmp_path / "data" / "public" / "sift1m")

    import scripts.prepare_texmex_datasets as mod

    monkeypatch.setattr(mod, "repo_root", lambda: tmp_path)
    link_path, ok, msg = link_v3db_compat(tmp_path / "data" / "public", DATASET_SPECS["sift1m"])
    assert ok, msg
    assert link_path.is_symlink()
    assert link_path.resolve() == (tmp_path / "data" / "public" / "sift1m").resolve()


def test_render_report_no_json(tmp_path):
    ensure_dataset_dirs(tmp_path, ["sift1m"])
    result = prepare_one(
        "sift1m",
        data_root=tmp_path,
        download=False,
        link_v3db=False,
        check_only=True,
    )
    md = render_report([result], data_root=tmp_path)
    assert "# TEXMEX Dataset Preparation Report" in md
    assert "SIFT1M" in md
    assert not list(tmp_path.glob("*.json"))


def test_dataset_status_partial():
    spec = DATASET_SPECS["gist1m"]
    checks = check_dataset_files(Path("/nonexistent"), spec)
    for c in checks:
        c.exists = c.role == "base"
    assert dataset_status_from_checks(spec, checks) == "partial"


def test_cli_check_only(tmp_path):
    out = tmp_path / "report.md"
    result = subprocess.run(
        [
            sys.executable,
            str(PREPARE_SCRIPT),
            "--dataset",
            "all",
            "--data-root",
            str(tmp_path),
            "--check-only",
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
    assert "missing" in out.read_text(encoding="utf-8").lower()
