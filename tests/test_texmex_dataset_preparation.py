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
    find_canonical_in_tree,
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


def _populate_sift1m_flat(directory: Path) -> None:
    write_fvecs(directory / "sift_base.fvecs", np.random.rand(10, 128).astype(np.float32))
    write_fvecs(directory / "sift_query.fvecs", np.random.rand(3, 128).astype(np.float32))
    write_ivecs(
        directory / "sift_groundtruth.ivecs",
        np.arange(100, dtype=np.int32).reshape(1, -1).repeat(3, axis=0),
    )


def _populate_sift1m_nested(directory: Path, *, with_learn: bool = True) -> None:
    nested = directory / "sift"
    write_fvecs(nested / "sift_base.fvecs", np.random.rand(10, 128).astype(np.float32))
    write_fvecs(nested / "sift_query.fvecs", np.random.rand(3, 128).astype(np.float32))
    write_ivecs(
        nested / "sift_groundtruth.ivecs",
        np.arange(100, dtype=np.int32).reshape(1, -1).repeat(3, axis=0),
    )
    if with_learn:
        write_fvecs(nested / "sift_learn.fvecs", np.random.rand(5, 128).astype(np.float32))


def test_primary_url_is_ftp():
    assert DATASET_SPECS["sift1m"]["tarball_url_primary"].startswith("ftp://")
    assert DATASET_SPECS["gist1m"]["tarball_url_primary"].startswith("ftp://")
    assert "ftp.irisa.fr/local/texmex/corpus/sift.tar.gz" in DATASET_SPECS["sift1m"]["tarball_url_primary"]
    assert "ftp.irisa.fr/local/texmex/corpus/gist.tar.gz" in DATASET_SPECS["gist1m"]["tarball_url_primary"]


def test_http_fallback_urls_preserved():
    assert DATASET_SPECS["sift1m"]["tarball_url_fallback"].startswith("http://")
    assert DATASET_SPECS["gist1m"]["tarball_url_fallback"].startswith("http://")
    assert "corpus-texmex.irisa.fr" in DATASET_SPECS["sift1m"]["tarball_url_fallback"]
    assert "file_urls_fallback" in DATASET_SPECS["sift1m"]
    assert "sift_base.fvecs" in DATASET_SPECS["sift1m"]["file_urls_fallback"]["base"]


def test_ensure_dataset_dirs(tmp_path):
    created = ensure_dataset_dirs(tmp_path, ["sift1m", "gist1m"])
    assert len(created) == 2
    assert (tmp_path / "sift1m").is_dir()
    assert (tmp_path / "gist1m").is_dir()


def test_nested_layout_creates_root_symlinks(tmp_path):
    directory = tmp_path / "sift1m"
    _populate_sift1m_nested(directory)
    notes = normalize_dataset_files(directory, DATASET_SPECS["sift1m"])
    assert (directory / "sift_base.fvecs").is_symlink()
    assert (directory / "sift_query.fvecs").is_symlink()
    assert (directory / "sift_groundtruth.ivecs").is_symlink()
    assert (directory / "sift_base.fvecs").resolve() == (directory / "sift" / "sift_base.fvecs").resolve()
    assert any("created symlink" in n or "updated symlink" in n for n in notes)


def test_find_canonical_in_tree_max_depth(tmp_path):
    directory = tmp_path / "sift1m"
    deep = directory / "a" / "b" / "c" / "d" / "e"
    write_fvecs(deep / "sift_base.fvecs", np.ones((1, 128), dtype=np.float32))
    assert find_canonical_in_tree(directory, "sift_base.fvecs", max_depth=4) is None
    assert find_canonical_in_tree(directory, "sift_base.fvecs", max_depth=5) is not None


def test_required_missing_status(tmp_path):
    ensure_dataset_dirs(tmp_path, ["sift1m"])
    result = prepare_one(
        "sift1m",
        data_root=tmp_path,
        download=False,
        link_v3db=False,
        check_only=True,
    )
    assert result.status == "missing"


def test_optional_learn_missing_still_ready(tmp_path):
    directory = tmp_path / "sift1m"
    _populate_sift1m_nested(directory, with_learn=False)
    result = prepare_one(
        "sift1m",
        data_root=tmp_path,
        download=False,
        link_v3db=False,
        check_only=True,
    )
    assert result.status == "ready"
    learn = next(c for c in result.checks if c.role == "learn")
    assert not learn.exists


def test_check_only_ready_flat_layout(tmp_path):
    sift_dir = tmp_path / "sift1m"
    _populate_sift1m_flat(sift_dir)
    result = prepare_one(
        "sift1m",
        data_root=tmp_path,
        download=False,
        link_v3db=False,
        check_only=True,
    )
    assert result.status == "ready"


def test_regular_file_at_root_not_overwritten(tmp_path):
    directory = tmp_path / "sift1m"
    _populate_sift1m_nested(directory)
    root_base = directory / "sift_base.fvecs"
    root_base.write_bytes(b"KEEP")
    notes = normalize_dataset_files(directory, DATASET_SPECS["sift1m"])
    assert root_base.read_bytes() == b"KEEP"
    assert any("regular file" in n for n in notes)


def test_link_v3db_creates_relative_symlink(tmp_path, monkeypatch):
    (tmp_path / "data" / "public" / "sift1m").mkdir(parents=True)
    _populate_sift1m_flat(tmp_path / "data" / "public" / "sift1m")

    import scripts.prepare_texmex_datasets as mod

    monkeypatch.setattr(mod, "repo_root", lambda: tmp_path)
    link_path, ok, msg, warning = link_v3db_compat(
        tmp_path / "data" / "public", DATASET_SPECS["sift1m"]
    )
    assert ok, msg
    assert not warning
    assert link_path.is_symlink()
    assert link_path.readlink() == Path("public/sift1m")
    assert link_path.resolve() == (tmp_path / "data" / "public" / "sift1m").resolve()


def test_link_v3db_updates_wrong_symlink(tmp_path, monkeypatch):
    (tmp_path / "data" / "public" / "sift1m").mkdir(parents=True)
    link_path = tmp_path / "data" / "sift"
    link_path.symlink_to("wrong")

    import scripts.prepare_texmex_datasets as mod

    monkeypatch.setattr(mod, "repo_root", lambda: tmp_path)
    _, ok, msg, warning = link_v3db_compat(tmp_path / "data" / "public", DATASET_SPECS["sift1m"])
    assert ok, msg
    assert not warning
    assert link_path.readlink() == Path("public/sift1m")


def test_link_v3db_warns_on_existing_directory(tmp_path, monkeypatch):
    link_path = tmp_path / "data" / "sift"
    link_path.mkdir(parents=True)

    import scripts.prepare_texmex_datasets as mod

    monkeypatch.setattr(mod, "repo_root", lambda: tmp_path)
    _, ok, msg, warning = link_v3db_compat(tmp_path / "data" / "public", DATASET_SPECS["sift1m"])
    assert not ok
    assert warning
    assert "directory" in msg.lower()
    assert link_path.is_dir()


def test_prepare_with_link_v3db_both_datasets(tmp_path, monkeypatch):
    import scripts.prepare_texmex_datasets as mod

    monkeypatch.setattr(mod, "repo_root", lambda: tmp_path)
    _populate_sift1m_nested(tmp_path / "sift1m")
    gist = tmp_path / "gist1m" / "gist"
    write_fvecs(gist / "gist_base.fvecs", np.random.rand(5, 960).astype(np.float32))
    write_fvecs(gist / "gist_query.fvecs", np.random.rand(2, 960).astype(np.float32))
    write_ivecs(
        gist / "gist_groundtruth.ivecs",
        np.arange(10, dtype=np.int32).reshape(1, -1).repeat(2, axis=0),
    )

    for name in ("sift1m", "gist1m"):
        result = prepare_one(
            name,
            data_root=tmp_path,
            download=False,
            link_v3db=True,
            check_only=True,
        )
        assert result.status == "ready"
        assert result.v3db_link_ok

    assert (tmp_path / "data" / "sift").is_symlink()
    assert (tmp_path / "data" / "gist").is_symlink()


def test_render_report_includes_urls_and_no_json(tmp_path):
    ensure_dataset_dirs(tmp_path, ["sift1m"])
    result = prepare_one(
        "sift1m",
        data_root=tmp_path,
        download=False,
        link_v3db=False,
        check_only=True,
    )
    md = render_report([result], data_root=tmp_path)
    assert "ftp://ftp.irisa.fr" in md
    assert "corpus-texmex.irisa.fr" in md
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
    assert "ftp://ftp.irisa.fr" in result.stdout
    assert "fallback (HTTP)" in result.stdout
    text = out.read_text(encoding="utf-8")
    assert "ftp://ftp.irisa.fr" in text
    assert "corpus-texmex.irisa.fr" in text
