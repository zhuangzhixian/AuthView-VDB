#!/usr/bin/env python3
"""
Phase 8B: Read-only sanity check for TEXMEX fvecs/ivecs datasets (SIFT1M, GIST1M).

Samples a few vectors without loading full files into memory.
Outputs markdown only (no JSON).
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

DATASET_SPECS: dict[str, dict] = {
    "sift1m": {
        "label": "SIFT1M",
        "prefix": "sift",
        "subdir": "sift1m",
        "expected_dim": 128,
        "files": {
            "base": "sift_base.fvecs",
            "query": "sift_query.fvecs",
            "groundtruth": "sift_groundtruth.ivecs",
        },
    },
    "gist1m": {
        "label": "GIST1M",
        "prefix": "gist",
        "subdir": "gist1m",
        "expected_dim": 960,
        "files": {
            "base": "gist_base.fvecs",
            "query": "gist_query.fvecs",
            "groundtruth": "gist_groundtruth.ivecs",
        },
    },
}


@dataclass
class VecFileInfo:
    role: str
    path: Path
    exists: bool
    dim: int | None = None
    num_vectors: int | None = None
    sample_shape: tuple[int, int] | None = None
    error: str | None = None


@dataclass
class DatasetCheckResult:
    dataset: str
    label: str
    dataset_dir: Path
    files: list[VecFileInfo] = field(default_factory=list)
    status: str = "missing"
    dim_consistent: bool = False
    dim_matches_expected: bool = False
    messages: list[str] = field(default_factory=list)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def peek_vec_dim(path: Path) -> int:
    with path.open("rb") as f:
        header = f.read(4)
    if len(header) < 4:
        raise ValueError("file too short for dimension header")
    dim = int(np.frombuffer(header, dtype="<i4")[0])
    if dim <= 0:
        raise ValueError(f"invalid dimension {dim}")
    return dim


def count_fvecs_vectors(path: Path, dim: int) -> int:
    record_bytes = (dim + 1) * 4
    size = path.stat().st_size
    if size % record_bytes != 0:
        raise ValueError(
            f"file size {size} is not a multiple of record size {record_bytes}"
        )
    return size // record_bytes


def count_ivecs_vectors(path: Path, dim: int) -> int:
    return count_fvecs_vectors(path, dim)


def read_fvecs_sample(path: Path, *, sample: int) -> np.ndarray:
    dim = peek_vec_dim(path)
    record_bytes = (dim + 1) * 4
    vectors: list[np.ndarray] = []
    with path.open("rb") as f:
        for _ in range(sample):
            chunk = f.read(record_bytes)
            if len(chunk) < record_bytes:
                break
            arr = np.frombuffer(chunk, dtype="<i4")
            if int(arr[0]) != dim:
                raise ValueError("inconsistent dimension header in sample")
            vectors.append(arr[1:].view("<f4").copy())
    if not vectors:
        return np.empty((0, dim), dtype=np.float32)
    return np.stack(vectors, axis=0)


def read_ivecs_sample(path: Path, *, sample: int) -> np.ndarray:
    dim = peek_vec_dim(path)
    record_bytes = (dim + 1) * 4
    vectors: list[np.ndarray] = []
    with path.open("rb") as f:
        for _ in range(sample):
            chunk = f.read(record_bytes)
            if len(chunk) < record_bytes:
                break
            arr = np.frombuffer(chunk, dtype="<i4")
            if int(arr[0]) != dim:
                raise ValueError("inconsistent dimension header in ivecs sample")
            vectors.append(arr[1:].copy())
    if not vectors:
        return np.empty((0, dim), dtype=np.int32)
    return np.stack(vectors, axis=0)


def inspect_file(role: Path | str, path: Path, *, sample: int, is_ivecs: bool = False) -> VecFileInfo:
    role_str = str(role)
    info = VecFileInfo(role=role_str, path=path, exists=path.is_file())
    if not info.exists:
        info.error = "file not found"
        return info
    try:
        info.dim = peek_vec_dim(path)
        if is_ivecs:
            info.num_vectors = count_ivecs_vectors(path, info.dim)
            sample_arr = read_ivecs_sample(path, sample=sample)
        else:
            info.num_vectors = count_fvecs_vectors(path, info.dim)
            sample_arr = read_fvecs_sample(path, sample=sample)
        info.sample_shape = sample_arr.shape
    except (OSError, ValueError) as exc:
        info.error = str(exc)
    return info


def check_dataset(
    name: str,
    *,
    data_root: Path,
    sample: int,
) -> DatasetCheckResult:
    spec = DATASET_SPECS[name]
    directory = data_root / spec["subdir"]
    result = DatasetCheckResult(dataset=name, label=spec["label"], dataset_dir=directory)

    for role, fname in spec["files"].items():
        path = directory / fname
        is_ivecs = role == "groundtruth"
        result.files.append(inspect_file(role, path, sample=sample, is_ivecs=is_ivecs))

    required = [f for f in result.files if f.role != "learn"]
    if not all(f.exists for f in required):
        result.status = "missing" if not any(f.exists for f in required) else "partial"
        return result

    if any(f.error for f in required):
        result.status = "error"
        result.messages.append("one or more files failed to read")
        return result

    base_dim = next(f.dim for f in result.files if f.role == "base")
    query_dim = next(f.dim for f in result.files if f.role == "query")
    result.dim_consistent = base_dim == query_dim
    result.dim_matches_expected = base_dim == spec["expected_dim"]
    result.status = "ok" if result.dim_consistent and result.dim_matches_expected else "error"

    if not result.dim_consistent:
        result.messages.append(f"base dim {base_dim} != query dim {query_dim}")
    if not result.dim_matches_expected:
        result.messages.append(
            f"expected dim {spec['expected_dim']}, got base dim {base_dim}"
        )

    gt = next(f for f in result.files if f.role == "groundtruth")
    if gt.sample_shape and gt.sample_shape[1] > 0:
        result.messages.append(f"groundtruth neighbors per query (sample): {gt.sample_shape[1]}")

    return result


def render_report(results: list[DatasetCheckResult], *, sample: int) -> str:
    now = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# FVECS Dataset Check Report",
        "",
        f"Generated: {now}",
        f"Sample vectors per file: {sample}",
        "",
        "## Summary",
        "",
        "| Dataset | Status | Dim OK | Base/Query consistent |",
        "|---------|--------|--------|------------------------|",
    ]
    for r in results:
        dim_ok = "yes" if r.dim_matches_expected else "no"
        consistent = "yes" if r.dim_consistent else "no"
        lines.append(f"| {r.label} | **{r.status}** | {dim_ok} | {consistent} |")

    for r in results:
        lines.extend(["", f"## {r.label}", "", f"Directory: `{r.dataset_dir}`", ""])
        lines.append("| Role | File | Exists | Dim | #Vectors | Sample shape | Notes |")
        lines.append("|------|------|--------|-----|----------|--------------|-------|")
        for f in r.files:
            exists = "yes" if f.exists else "no"
            dim = str(f.dim) if f.dim is not None else "—"
            nvec = str(f.num_vectors) if f.num_vectors is not None else "—"
            shape = str(f.sample_shape) if f.sample_shape else "—"
            note = f.error or ""
            lines.append(
                f"| {f.role} | `{f.path.name}` | {exists} | {dim} | {nvec} | {shape} | {note} |"
            )
        if r.messages:
            lines.extend(["", "**Notes:**", ""])
            for msg in r.messages:
                lines.append(f"- {msg}")

    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check TEXMEX fvecs/ivecs datasets.")
    parser.add_argument("--dataset", choices=["sift1m", "gist1m", "all"], default="all")
    parser.add_argument("--data-root", type=Path, default=Path("data/public"))
    parser.add_argument("--sample", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/fvecs_dataset_check.md"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    data_root = args.data_root
    if not data_root.is_absolute():
        data_root = repo_root() / data_root

    datasets = ["sift1m", "gist1m"] if args.dataset == "all" else [args.dataset]
    results = [check_dataset(name, data_root=data_root, sample=args.sample) for name in datasets]

    report = render_report(results, sample=args.sample)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"Wrote {args.output}")
    for r in results:
        print(f"  {r.label}: {r.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
