"""Phase 8A: tests for public benchmark inventory scanner."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.inspect_public_benchmark_data import (
    REQUIRED_ROLES,
    dataset_status,
    render_markdown,
    scan_roots,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "inspect_public_benchmark_data.py"


def _touch(path: Path, content: bytes = b"x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_mock_sift_ready_in_temp_dir(tmp_path):
    sift_dir = tmp_path / "sift"
    _touch(sift_dir / "sift_base.fvecs", b"0" * 100)
    _touch(sift_dir / "sift_query.fvecs", b"0" * 50)
    _touch(sift_dir / "sift_groundtruth.ivecs", b"0" * 50)
    result = scan_roots([tmp_path], max_depth=3)
    status = dataset_status(result.files)
    assert status["sift1m"] == "ready"
    assert len(result.files) == 3


def test_mock_gist_partial(tmp_path):
    gist_dir = tmp_path / "gist"
    _touch(gist_dir / "gist_base.fvecs")
    _touch(gist_dir / "gist_query.fvecs")
    result = scan_roots([tmp_path], max_depth=3)
    assert dataset_status(result.files)["gist1m"] == "partial"


def test_mock_msmarco_ready(tmp_path):
    marco = tmp_path / "msmacro"
    _touch(marco / "collection.duckdb")
    _touch(marco / "queries.dev.duckdb")
    _touch(marco / "qrels.dev.tsv")
    result = scan_roots([tmp_path], max_depth=3)
    assert dataset_status(result.files)["msmarco"] == "ready"


def test_missing_when_empty(tmp_path):
    result = scan_roots([tmp_path], max_depth=2)
    status = dataset_status(result.files)
    assert status["sift1m"] == "missing"
    assert status["gist1m"] == "missing"
    assert status["msmarco"] == "missing"


def test_outputs_markdown_not_json(tmp_path):
    _touch(tmp_path / "sift" / "sift_base.fvecs")
    result = scan_roots([tmp_path], max_depth=2)
    md = render_markdown(result)
    assert "# Public Benchmark Dataset Inventory" in md
    assert "SIFT1M" in md
    out = tmp_path / "inventory.md"
    out.write_text(md, encoding="utf-8")
    assert not list(tmp_path.glob("*.json"))


def test_script_cli_runs(tmp_path):
    _touch(tmp_path / "data" / "sift" / "sift_base.fvecs")
    out = tmp_path / "out.md"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--roots",
            str(tmp_path),
            "--max-depth",
            "4",
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
    assert out.is_file() and out.stat().st_size > 0


def test_required_roles_defined():
    assert REQUIRED_ROLES["sift1m"] == frozenset({"base", "query", "groundtruth"})
    assert REQUIRED_ROLES["msmarco"] == frozenset({"collection", "queries_dev", "qrels"})
