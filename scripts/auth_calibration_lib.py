"""Phase 9B: full authorized-reference calibration utilities."""

from __future__ import annotations

import csv
import heapq
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import numpy as np

from scripts.auth_overlay_lib import (
    authorized_candidate_results,
    load_visibility_npz,
    post_filter_results,
    recall_from_result,
)

REFERENCE_SCOPE_CALIBRATION = "full_base_calibration"

DATASET_SPECS: dict[str, dict[str, str | int]] = {
    "sift1m": {
        "prefix": "sift",
        "subdir": "sift1m",
        "dim": 128,
        "num_base": 1_000_000,
        "num_queries": 10_000,
    },
    "gist1m": {
        "prefix": "gist",
        "subdir": "gist1m",
        "dim": 960,
        "num_base": 1_000_000,
        "num_queries": 1_000,
    },
}

CALIBRATION_QUERY_FIELDS = (
    "dataset",
    "config",
    "policy_mode",
    "selectivity",
    "query_id",
    "gap_bucket",
    "underfill_bucket",
    "reason",
)

CHECKPOINT_FIELDS = (
    "dataset",
    "config",
    "policy_mode",
    "selectivity",
    "query_id",
    "k",
    "post_filter_recall",
    "candidate_reference_recall",
    "full_authorized_recall",
    "post_filter_underfill",
    "candidate_vs_full_overlap",
    "post_filter_vs_full_overlap",
    "reference_scope",
    "full_base",
    "visible_count",
    "visible_ratio",
    "dim",
    "num_base",
)

SUMMARY_FIELDS = (
    "dataset",
    "config",
    "policy_mode",
    "selectivity",
    "k",
    "num_queries",
    "num_base",
    "dim",
    "full_base",
    "visible_count",
    "visible_ratio",
    "post_filter_recall",
    "candidate_reference_recall",
    "full_authorized_recall",
    "post_filter_underfill_rate",
    "candidate_vs_full_overlap",
    "post_filter_vs_full_overlap",
    "candidate_full_recall_gap",
    "post_full_recall_gap",
    "reference_scope",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_data_dir(data_root: Path, dataset: str) -> Path:
    spec = DATASET_SPECS[dataset]
    return data_root / str(spec["subdir"])


def dataset_paths(data_root: Path, dataset: str) -> dict[str, Path]:
    spec = DATASET_SPECS[dataset]
    prefix = str(spec["prefix"])
    root = resolve_data_dir(data_root, dataset)
    return {
        "base": root / f"{prefix}_base.fvecs",
        "query": root / f"{prefix}_query.fvecs",
        "groundtruth": root / f"{prefix}_groundtruth.ivecs",
    }


def mask_path_for(overlay_dir: Path, dataset: str, policy_mode: str, selectivity: float) -> Path:
    sel_tag = str(selectivity).replace(".", "p")
    return overlay_dir / f"{dataset}_{policy_mode}_sel{sel_tag}_visibility.npz"


def peek_vec_dim(path: Path) -> int:
    with path.open("rb") as f:
        header = f.read(4)
    if len(header) < 4:
        raise ValueError(f"empty file: {path}")
    return int(np.frombuffer(header, dtype="<i4")[0])


def read_fvecs_indices(path: Path, dim: int, indices: np.ndarray) -> np.ndarray:
    if indices.size == 0:
        return np.empty((0, dim), dtype=np.float32)
    record_bytes = (dim + 1) * 4
    out = np.empty((indices.size, dim), dtype=np.float32)
    with path.open("rb") as f:
        for j, idx in enumerate(indices):
            f.seek(int(idx) * record_bytes)
            chunk = f.read(record_bytes)
            if len(chunk) < record_bytes:
                raise ValueError(f"short read at index {idx} in {path}")
            arr = np.frombuffer(chunk, dtype="<i4")
            if int(arr[0]) != dim:
                raise ValueError(f"bad dim header at index {idx}")
            out[j] = arr[1:].view("<f4")
    return out


def read_fvecs_all(path: Path, dim: int) -> np.ndarray:
    record_bytes = (dim + 1) * 4
    size = path.stat().st_size
    n = size // record_bytes
    out = np.empty((n, dim), dtype=np.float32)
    with path.open("rb") as f:
        for i in range(n):
            chunk = f.read(record_bytes)
            arr = np.frombuffer(chunk, dtype="<i4")
            out[i] = arr[1:].view("<f4")
    return out


def read_query_vector(path: Path, dim: int, query_id: int) -> np.ndarray:
    return read_fvecs_indices(path, dim, np.array([query_id], dtype=np.int64))[0]


def read_ivecs_row(path: Path, dim: int, query_id: int) -> np.ndarray:
    record_bytes = (dim + 1) * 4
    with path.open("rb") as f:
        f.seek(int(query_id) * record_bytes)
        chunk = f.read(record_bytes)
    arr = np.frombuffer(chunk, dtype="<i4")
    return arr[1:].copy()


def overlap_at_k(a: list[int], b: list[int], k: int) -> float:
    sa = set(a[:k])
    sb = set(b[:k])
    if k <= 0:
        return 1.0
    return len(sa & sb) / k


def per_query_gap_bucket(post_hit: bool, candidate_hit: bool, affected: bool) -> str:
    if candidate_hit and not post_hit:
        return "high"
    if affected and candidate_hit == post_hit:
        return "medium"
    return "low"


def per_query_underfill_bucket(underfill: bool) -> str:
    return "underfill" if underfill else "filled"


@dataclass
class QueryCalibrationFeatures:
    query_id: int
    post_hit: bool
    candidate_hit: bool
    underfill: bool
    affected: bool
    utility_gap: float


def compute_query_features(
    pred_row: np.ndarray,
    gt_row: np.ndarray,
    visible: np.ndarray,
    *,
    k: int,
    candidate_depth: int,
) -> QueryCalibrationFeatures:
    post = post_filter_results(pred_row, visible, k)
    candidate = authorized_candidate_results(
        pred_row, visible, k, candidate_depth=candidate_depth
    )
    post_hit = recall_from_result(post, gt_row) > 0
    candidate_hit = recall_from_result(candidate, gt_row) > 0
    underfill = len(post) < k
    affected = post != candidate
    return QueryCalibrationFeatures(
        query_id=-1,
        post_hit=post_hit,
        candidate_hit=candidate_hit,
        underfill=underfill,
        affected=affected,
        utility_gap=float(candidate_hit) - float(post_hit),
    )


class TopKTracker:
    def __init__(self, k: int) -> None:
        self.k = k
        self._heap: list[tuple[float, int]] = []

    def update(self, distances: np.ndarray, ids: np.ndarray) -> None:
        for dist, idx in zip(distances, ids, strict=True):
            d = float(dist)
            i = int(idx)
            if len(self._heap) < self.k:
                heapq.heappush(self._heap, (-d, i))
            elif d < -self._heap[0][0]:
                heapq.heapreplace(self._heap, (-d, i))

    def results(self) -> list[int]:
        ordered = sorted(self._heap, key=lambda x: -x[0])
        return [idx for _, idx in ordered]


def full_authorized_topk_chunked(
    query: np.ndarray,
    base_path: Path,
    visible: np.ndarray,
    *,
    dim: int,
    k: int,
    chunk_size: int,
) -> list[int]:
    visible_ids = np.flatnonzero(visible).astype(np.int64)
    tracker = TopKTracker(k)
    q = query.astype(np.float32, copy=False)
    for start in range(0, visible_ids.size, chunk_size):
        chunk_ids = visible_ids[start : start + chunk_size]
        vecs = read_fvecs_indices(base_path, dim, chunk_ids)
        dists = np.sum((vecs - q) ** 2, axis=1)
        tracker.update(dists, chunk_ids)
    return tracker.results()


def full_authorized_topk_naive(
    query: np.ndarray,
    base: np.ndarray,
    visible: np.ndarray,
    k: int,
) -> list[int]:
    visible_ids = np.flatnonzero(visible)
    vecs = base[visible_ids]
    q = query.astype(np.float32, copy=False)
    dists = np.sum((vecs - q) ** 2, axis=1)
    order = np.argsort(dists)[:k]
    return visible_ids[order].tolist()


def try_faiss_topk(
    query: np.ndarray,
    base_path: Path,
    visible: np.ndarray,
    *,
    dim: int,
    k: int,
    chunk_size: int,
) -> list[int] | None:
    try:
        import faiss  # type: ignore[import-untyped]
    except ImportError:
        return None
    visible_ids = np.flatnonzero(visible).astype(np.int64)
    if visible_ids.size == 0:
        return []
    parts: list[np.ndarray] = []
    for start in range(0, visible_ids.size, chunk_size):
        chunk_ids = visible_ids[start : start + chunk_size]
        parts.append(read_fvecs_indices(base_path, dim, chunk_ids))
    vecs = np.vstack(parts).astype(np.float32)
    index = faiss.IndexFlatL2(dim)
    index.add(vecs)
    q = query.astype(np.float32, copy=True).reshape(1, -1)
    _, idx = index.search(q, min(k, vecs.shape[0]))
    local = idx[0]
    return [int(visible_ids[i]) for i in local if i >= 0]


def evaluate_calibration_query(
    *,
    query: np.ndarray,
    pred_row: np.ndarray,
    gt_row: np.ndarray,
    visible: np.ndarray,
    base_path: Path,
    dim: int,
    ks: Iterable[int],
    candidate_depth: int,
    chunk_size: int,
    use_faiss: bool = True,
) -> list[dict]:
    visible_count = int(visible.sum())
    visible_ratio = visible_count / max(visible.size, 1)
    ks_list = sorted({int(k) for k in ks})
    max_k = max(ks_list) if ks_list else 1

    full_max: list[int] | None = None
    if use_faiss:
        full_max = try_faiss_topk(
            query, base_path, visible, dim=dim, k=max_k, chunk_size=chunk_size
        )
    if full_max is None:
        full_max = full_authorized_topk_chunked(
            query, base_path, visible, dim=dim, k=max_k, chunk_size=chunk_size
        )

    rows: list[dict] = []
    for k in ks_list:
        post = post_filter_results(pred_row, visible, k)
        candidate = authorized_candidate_results(
            pred_row, visible, k, candidate_depth=candidate_depth
        )
        full = full_max[:k]
        rows.append(
            {
                "k": k,
                "post_filter_recall": recall_from_result(post, gt_row),
                "candidate_reference_recall": recall_from_result(candidate, gt_row),
                "full_authorized_recall": recall_from_result(full, gt_row),
                "post_filter_underfill": 1.0 if len(post) < k else 0.0,
                "candidate_vs_full_overlap": overlap_at_k(candidate, full, k),
                "post_filter_vs_full_overlap": overlap_at_k(post, full, k),
                "reference_scope": REFERENCE_SCOPE_CALIBRATION,
                "full_base": True,
                "visible_count": visible_count,
                "visible_ratio": visible_ratio,
                "dim": dim,
                "num_base": int(visible.size),
            }
        )
    return rows


def load_csv(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fieldnames: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def append_csv(path: Path, rows: list[dict], fieldnames: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.is_file() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)


def checkpoint_key(row: dict) -> tuple:
    return (
        row["dataset"],
        row["config"],
        row["policy_mode"],
        str(row["selectivity"]),
        str(row["query_id"]),
        str(row["k"]),
    )


def load_completed_keys(checkpoint_path: Path) -> set[tuple]:
    return {checkpoint_key(r) for r in load_csv(checkpoint_path)}


def aggregate_checkpoint_rows(rows: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (
            row["dataset"],
            row["config"],
            row["policy_mode"],
            float(row["selectivity"]),
            int(float(row["k"])),
        )
        groups.setdefault(key, []).append(row)

    summary: list[dict] = []
    for key, items in sorted(groups.items()):
        dataset, config, policy_mode, selectivity, k = key
        n = len(items)
        def mean(field: str) -> float:
            return float(np.mean([float(r[field]) for r in items]))

        summary.append(
            {
                "dataset": dataset,
                "config": config,
                "policy_mode": policy_mode,
                "selectivity": selectivity,
                "k": k,
                "num_queries": n,
                "num_base": int(float(items[0]["num_base"])),
                "dim": int(float(items[0]["dim"])),
                "full_base": True,
                "visible_count": int(float(items[0]["visible_count"])),
                "visible_ratio": mean("visible_ratio"),
                "post_filter_recall": mean("post_filter_recall"),
                "candidate_reference_recall": mean("candidate_reference_recall"),
                "full_authorized_recall": mean("full_authorized_recall"),
                "post_filter_underfill_rate": mean("post_filter_underfill"),
                "candidate_vs_full_overlap": mean("candidate_vs_full_overlap"),
                "post_filter_vs_full_overlap": mean("post_filter_vs_full_overlap"),
                "candidate_full_recall_gap": mean("candidate_reference_recall")
                - mean("full_authorized_recall"),
                "post_full_recall_gap": mean("post_filter_recall")
                - mean("full_authorized_recall"),
                "reference_scope": REFERENCE_SCOPE_CALIBRATION,
            }
        )
    return summary


def estimate_calibration_cost(
    calibration_rows: list[dict],
    *,
    chunk_size: int,
) -> dict[str, float | int]:
    total_queries = len(calibration_rows)
    by_dataset: dict[str, int] = {}
    dist_ops = 0.0
    for row in calibration_rows:
        ds = row["dataset"]
        by_dataset[ds] = by_dataset.get(ds, 0) + 1
        spec = DATASET_SPECS[ds]
        dim = int(spec["dim"])
        sel = float(row["selectivity"])
        visible = int(round(int(spec["num_base"]) * sel))
        dist_ops += visible * dim * 3  # mul-add approx

    return {
        "total_calibration_queries": total_queries,
        "queries_by_dataset": by_dataset,
        "estimated_distance_ops": dist_ops,
        "chunk_size": chunk_size,
        "estimated_chunks_per_query_mean": dist_ops / max(chunk_size * 128, 1),
    }


def select_calibration_queries(
    *,
    trace_pred: np.ndarray,
    trace_gt: np.ndarray,
    dataset: str,
    config: str,
    policy_mode: str,
    selectivity: float,
    visible: np.ndarray,
    candidate_depth: int,
    queries_per_bucket: int,
    rng: np.random.Generator,
    k_select: int = 10,
) -> list[dict]:
    buckets: dict[tuple[str, str], list[int]] = {}
    num_queries = trace_pred.shape[0]
    for qid in range(num_queries):
        feat = compute_query_features(
            trace_pred[qid],
            trace_gt[qid],
            visible,
            k=k_select,
            candidate_depth=candidate_depth,
        )
        gap_bucket = per_query_gap_bucket(
            feat.post_hit, feat.candidate_hit, feat.affected
        )
        underfill_bucket = per_query_underfill_bucket(feat.underfill)
        buckets.setdefault((gap_bucket, underfill_bucket), []).append(qid)

    selected: list[dict] = []
    for (gap_bucket, underfill_bucket), qids in sorted(buckets.items()):
        if not qids:
            continue
        n = min(queries_per_bucket, len(qids))
        picks = rng.choice(qids, size=n, replace=False)
        for qid in sorted(int(x) for x in picks):
            selected.append(
                {
                    "dataset": dataset,
                    "config": config,
                    "policy_mode": policy_mode,
                    "selectivity": selectivity,
                    "query_id": qid,
                    "gap_bucket": gap_bucket,
                    "underfill_bucket": underfill_bucket,
                    "reason": f"bucket={gap_bucket}/{underfill_bucket}",
                }
            )
    return selected


def cap_queries_per_dataset(rows: list[dict], max_per_dataset: int, seed: int) -> list[dict]:
    if max_per_dataset <= 0:
        return rows
    rng = np.random.default_rng(seed + 99)
    out: list[dict] = []
    for dataset in sorted({r["dataset"] for r in rows}):
        ds_rows = [r for r in rows if r["dataset"] == dataset]
        if len(ds_rows) <= max_per_dataset:
            out.extend(ds_rows)
            continue
        idx = rng.choice(len(ds_rows), size=max_per_dataset, replace=False)
        out.extend(ds_rows[i] for i in sorted(idx))
    return out
