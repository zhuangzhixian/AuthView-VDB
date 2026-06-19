#!/usr/bin/env python3
"""
Phase 8C: Public utility baseline for SIFT1M/GIST1M (V3DB-aligned).

Reuses bench.acc_bench / tests.acc_bench IVF-PQ pipeline on full public datasets.
Outputs CSV + optional NPZ traces (no JSON artifacts in output dir).
Supports resumable per-config runs with --resume / --skip-existing / --only-missing.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from tqdm import tqdm

from bench.acc_bench import (
    _query_metrics,
    run_accuracy_bench,
)
from ivf_pq.standard import ivf_pq_learn, ivf_pq_query
from vec_data_load.sift import SIFT

REPORT_KS = (1, 10, 100)

EXPECTED_NUM_BASE = {"sift1m": 1_000_000, "gist1m": 1_000_000}
EXPECTED_NUM_QUERIES = {"sift1m": 10_000, "gist1m": 1_000}
EXPECTED_DIM = {"sift1m": 128, "gist1m": 960}

SUMMARY_FIELDS = (
    "dataset",
    "config",
    "data_name",
    "scheme",
    "M",
    "K",
    "top_k",
    "n_list",
    "n_probe",
    "cluster_bound",
    "scale_n",
    "layout",
    "num_base",
    "num_queries",
    "dim",
    "full_base",
    "recall_at_1",
    "recall_at_10",
    "recall_at_100",
    "build_time_s",
    "query_time_s",
    "qps",
    "index_size_bytes",
    "trace_path",
)

METRICS_FIELDS = SUMMARY_FIELDS + ("run_index",)


@dataclass(frozen=True)
class PublicUtilityConfig:
    dataset: str
    data_name: str
    config: str
    n_list: int
    n_probe: int
    cluster_bound: int
    M: int = 8
    K: int = 256
    top_k: int = 100
    scale_n: int = 65536
    layout: str | None = None
    bench_name: str = ""

    def __post_init__(self) -> None:
        if not self.bench_name:
            object.__setattr__(
                self,
                "bench_name",
                f"phase8_{self.dataset}_{self.config}",
            )

    @property
    def key(self) -> str:
        return f"{self.dataset}_{self.config}"


V3DB_PUBLIC_CONFIGS: tuple[PublicUtilityConfig, ...] = (
    PublicUtilityConfig(
        dataset="sift1m",
        data_name="sift",
        config="high-acc",
        n_list=8192,
        n_probe=64,
        cluster_bound=256,
    ),
    PublicUtilityConfig(
        dataset="sift1m",
        data_name="sift",
        config="zk-opt",
        n_list=1024,
        n_probe=8,
        cluster_bound=2048,
    ),
    PublicUtilityConfig(
        dataset="gist1m",
        data_name="gist",
        config="high-acc",
        n_list=8192,
        n_probe=64,
        cluster_bound=256,
    ),
    PublicUtilityConfig(
        dataset="gist1m",
        data_name="gist",
        config="zk-opt",
        n_list=512,
        n_probe=4,
        cluster_bound=4096,
    ),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_configs(
    datasets: Iterable[str],
    config_names: Iterable[str] | None = None,
) -> list[PublicUtilityConfig]:
    wanted_ds = {d.strip().lower() for d in datasets}
    wanted_cfg = None
    if config_names is not None:
        wanted_cfg = {c.strip().lower() for c in config_names}
    out: list[PublicUtilityConfig] = []
    for cfg in V3DB_PUBLIC_CONFIGS:
        if cfg.dataset not in wanted_ds:
            continue
        if wanted_cfg is not None and cfg.config not in wanted_cfg:
            continue
        out.append(cfg)
    return out


def compute_full_base(dataset: str, num_base: int, num_queries: int, dim: int) -> bool:
    return (
        num_base == EXPECTED_NUM_BASE.get(dataset, -1)
        and num_queries == EXPECTED_NUM_QUERIES.get(dataset, -1)
        and dim == EXPECTED_DIM.get(dataset, -1)
    )


def per_config_metrics_path(output_dir: Path, cfg: PublicUtilityConfig) -> Path:
    return output_dir / "per_config" / f"{cfg.key}_metrics.csv"


def per_config_summary_path(output_dir: Path, cfg: PublicUtilityConfig) -> Path:
    return output_dir / "per_config" / f"{cfg.key}_summary.csv"


def trace_path_for(output_dir: Path, cfg: PublicUtilityConfig) -> Path:
    return output_dir / "traces" / f"{cfg.key}_results.npz"


def load_csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def load_dataset(data_root: Path, data_name: str) -> SIFT:
    data_dir = data_root / data_name
    if not data_dir.exists():
        raise FileNotFoundError(
            f"Dataset dir not found: {data_dir} "
            f"(expected V3DB symlink, e.g. data/{data_name} -> public/{data_name}1m)"
        )
    return SIFT(str(data_dir))


def _estimate_index_size_bytes(
    labels: np.ndarray,
    center: np.ndarray,
    code_books: np.ndarray,
    quant_vecs: np.ndarray,
    id_groups: list[np.ndarray],
) -> int:
    total = int(labels.nbytes + center.nbytes + code_books.nbytes + quant_vecs.nbytes)
    for group in id_groups:
        total += int(np.asarray(group).nbytes)
    return total


def export_standard_traces(
    cfg: PublicUtilityConfig,
    *,
    base: np.ndarray,
    queries: np.ndarray,
    gt: np.ndarray,
    trace_path: Path,
    random_state: int = 42,
) -> int:
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    max_k = max(REPORT_KS + (cfg.top_k,))

    labels, center, code_books, quant_vecs, id_groups = ivf_pq_learn(
        base,
        n_list=cfg.n_list,
        M=cfg.M,
        K=cfg.K,
        random_state=random_state,
        layout=cfg.layout,
    )
    index_size = _estimate_index_size_bytes(
        labels, center, code_books, quant_vecs, id_groups
    )

    q = int(queries.shape[0])
    preds = np.empty((q, max_k), dtype=np.int64)
    for i in tqdm(range(q), desc=f"trace {cfg.dataset}/{cfg.config}"):
        pred = ivf_pq_query(
            queries[i],
            max_k,
            labels,
            center,
            code_books,
            quant_vecs,
            id_groups,
            n_probe=cfg.n_probe,
            layout=cfg.layout,
        )
        preds[i, : pred.size] = np.asarray(pred, dtype=np.int64)[:max_k]

    np.savez_compressed(
        trace_path,
        pred=preds,
        gt=gt,
        dataset=cfg.dataset,
        config=cfg.config,
        data_name=cfg.data_name,
        n_list=cfg.n_list,
        n_probe=cfg.n_probe,
        cluster_bound=cfg.cluster_bound,
        M=cfg.M,
        K=cfg.K,
        top_k=cfg.top_k,
        scale_n=cfg.scale_n,
        layout=cfg.layout or "none",
        num_base=int(base.shape[0]),
        num_queries=q,
        dim=int(base.shape[1]),
        index_size_bytes=index_size,
    )
    return index_size


def recall_from_trace(trace_path: Path) -> dict[str, float]:
    with np.load(trace_path) as data:
        if "pred" not in data or "gt" not in data:
            raise ValueError(f"trace missing pred/gt arrays: {trace_path}")
        pred = np.asarray(data["pred"])
        gt = np.asarray(data["gt"])
    if pred.ndim != 2 or gt.ndim != 2:
        raise ValueError(f"trace pred/gt must be 2D: {trace_path}")
    if pred.shape[0] != gt.shape[0]:
        raise ValueError(f"trace query count mismatch: {trace_path}")

    sums = {k: 0.0 for k in REPORT_KS}
    q = int(pred.shape[0])
    for i in range(q):
        metrics = _query_metrics(
            scheme="standard",
            pred=pred[i],
            gt_topk=gt[i],
            report_ks=REPORT_KS,
        )
        for k in REPORT_KS:
            sums[k] += float(metrics[f"standard_recall_at_{k}"])
    return {f"recall_at_{k}": sums[k] / q for k in REPORT_KS}


def _summary_value(block: dict[str, float], metric: str, k: int) -> float | None:
    key = f"mean_{metric}_at_{k}"
    if key in block:
        return float(block[key])
    return None


def _normalize_row(row: dict[str, Any], cfg: PublicUtilityConfig | None = None) -> dict[str, Any]:
    out = {k: row.get(k, "") for k in SUMMARY_FIELDS}
    if cfg is not None:
        out.setdefault("dataset", cfg.dataset)
        out.setdefault("config", cfg.config)
        out.setdefault("data_name", cfg.data_name)
        out.setdefault("M", cfg.M)
        out.setdefault("K", cfg.K)
        out.setdefault("top_k", cfg.top_k)
        out.setdefault("n_list", cfg.n_list)
        out.setdefault("n_probe", cfg.n_probe)
        out.setdefault("cluster_bound", cfg.cluster_bound)
        out.setdefault("scale_n", cfg.scale_n)
        out.setdefault("layout", cfg.layout or "none")
    if out.get("scheme", "") == "":
        out["scheme"] = "standard"
    try:
        num_base = int(float(out["num_base"])) if out.get("num_base", "") != "" else 0
        num_queries = int(float(out["num_queries"])) if out.get("num_queries", "") != "" else 0
        dim = int(float(out["dim"])) if out.get("dim", "") != "" else 0
        dataset = str(out.get("dataset", cfg.dataset if cfg else ""))
        out["full_base"] = str(
            compute_full_base(dataset, num_base, num_queries, dim)
        ).lower()
    except (TypeError, ValueError):
        out["full_base"] = "false"
    return out


def _row_from_summary(
    cfg: PublicUtilityConfig,
    *,
    scheme: str,
    summary: dict[str, dict[str, float]],
    num_base: int,
    num_queries: int,
    dim: int,
    index_size_bytes: int | None,
    trace_path: str,
    run_index: int = 0,
) -> dict[str, Any]:
    block = summary.get(scheme, {})
    build_time = block.get("mean_train_time")
    query_time = block.get("mean_query_time")
    qps = None
    if query_time and float(query_time) > 0:
        qps = float(num_queries) / float(query_time)

    row: dict[str, Any] = {
        "dataset": cfg.dataset,
        "config": cfg.config,
        "data_name": cfg.data_name,
        "scheme": scheme,
        "M": cfg.M,
        "K": cfg.K,
        "top_k": cfg.top_k,
        "n_list": cfg.n_list,
        "n_probe": cfg.n_probe,
        "cluster_bound": cfg.cluster_bound,
        "scale_n": cfg.scale_n,
        "layout": cfg.layout or "none",
        "num_base": num_base,
        "num_queries": num_queries,
        "dim": dim,
        "full_base": str(compute_full_base(cfg.dataset, num_base, num_queries, dim)).lower(),
        "recall_at_1": _summary_value(block, "recall", 1),
        "recall_at_10": _summary_value(block, "recall", 10),
        "recall_at_100": _summary_value(block, "recall", 100),
        "build_time_s": float(build_time) if build_time is not None else "",
        "query_time_s": float(query_time) if query_time is not None else "",
        "qps": qps if qps is not None else "",
        "index_size_bytes": index_size_bytes if index_size_bytes is not None else "",
        "trace_path": trace_path if scheme == "standard" else "",
        "run_index": run_index,
    }
    return row


def _row_from_trace(
    cfg: PublicUtilityConfig,
    trace_path: Path,
    *,
    recalls: dict[str, float],
) -> dict[str, Any]:
    with np.load(trace_path) as data:
        num_base = int(data["num_base"]) if "num_base" in data else int(data["pred"].shape[0])
        num_queries = int(data["num_queries"]) if "num_queries" in data else int(data["pred"].shape[0])
        dim = int(data["dim"]) if "dim" in data else EXPECTED_DIM.get(cfg.dataset, 0)
        index_size = int(data["index_size_bytes"]) if "index_size_bytes" in data else ""

    row = _normalize_row(
        {
            "dataset": cfg.dataset,
            "config": cfg.config,
            "data_name": cfg.data_name,
            "scheme": "standard",
            "M": cfg.M,
            "K": cfg.K,
            "top_k": cfg.top_k,
            "n_list": cfg.n_list,
            "n_probe": cfg.n_probe,
            "cluster_bound": cfg.cluster_bound,
            "scale_n": cfg.scale_n,
            "layout": cfg.layout or "none",
            "num_base": num_base,
            "num_queries": num_queries,
            "dim": dim,
            "recall_at_1": recalls["recall_at_1"],
            "recall_at_10": recalls["recall_at_10"],
            "recall_at_100": recalls["recall_at_100"],
            "build_time_s": "",
            "query_time_s": "",
            "qps": "",
            "index_size_bytes": index_size,
            "trace_path": str(trace_path),
        },
        cfg=cfg,
    )
    return row


def write_per_config(
    cfg: PublicUtilityConfig,
    metrics_rows: list[dict[str, Any]],
    output_dir: Path,
) -> None:
    summary_rows = [
        _normalize_row(r, cfg=cfg)
        for r in metrics_rows
        if r.get("scheme") == "standard"
    ]
    write_csv(per_config_metrics_path(output_dir, cfg), metrics_rows, METRICS_FIELDS)
    if summary_rows:
        write_csv(per_config_summary_path(output_dir, cfg), summary_rows, SUMMARY_FIELDS)
    print(f"Wrote per-config artifacts under {output_dir / 'per_config'}/{cfg.key}_*")


def recover_config_from_trace(
    cfg: PublicUtilityConfig,
    output_dir: Path,
    trace_path: Path,
) -> list[dict[str, Any]]:
    recalls = recall_from_trace(trace_path)
    standard_row = _row_from_trace(cfg, trace_path, recalls=recalls)
    print(
        f"recovered recalls from trace {trace_path.name}: "
        f"R@1={recalls['recall_at_1']:.4f} "
        f"R@10={recalls['recall_at_10']:.4f} "
        f"R@100={recalls['recall_at_100']:.4f} "
        "(build_time_s/query_time_s unavailable from trace)"
    )
    metrics_rows = [{**standard_row, "run_index": 0, "scheme": "standard"}]
    write_per_config(cfg, metrics_rows, output_dir)
    return metrics_rows


def should_skip_config(
    cfg: PublicUtilityConfig,
    output_dir: Path,
    *,
    skip_existing: bool,
    only_missing: bool,
) -> tuple[bool, str]:
    summary_path = per_config_summary_path(output_dir, cfg)
    metrics_path = per_config_metrics_path(output_dir, cfg)
    trace_path = trace_path_for(output_dir, cfg)

    if only_missing and summary_path.is_file():
        return True, f"per-config summary exists: {summary_path.name}"

    if skip_existing and summary_path.is_file():
        return True, f"per-config summary exists: {summary_path.name}"

    if skip_existing and summary_path.is_file() and metrics_path.is_file():
        return True, f"per-config metrics+summary exist: {cfg.key}"

    if skip_existing and trace_path.is_file() and summary_path.is_file():
        return True, f"trace and summary exist: {cfg.key}"

    return False, ""


def load_existing_config_rows(
    cfg: PublicUtilityConfig,
    output_dir: Path,
) -> list[dict[str, Any]] | None:
    metrics_path = per_config_metrics_path(output_dir, cfg)
    if metrics_path.is_file():
        return load_csv_rows(metrics_path)

    summary_path = per_config_summary_path(output_dir, cfg)
    trace_path = trace_path_for(output_dir, cfg)
    if summary_path.is_file():
        rows = load_csv_rows(summary_path)
        return [{**r, "run_index": 0} for r in rows]

    if trace_path.is_file():
        try:
            return recover_config_from_trace(cfg, output_dir, trace_path)
        except ValueError as exc:
            raise RuntimeError(
                f"trace exists but recall recovery failed for {cfg.key}: {exc}"
            ) from exc

    return None


def migrate_legacy_aggregates(output_dir: Path, *, force: bool = False) -> None:
    """Split legacy top-level CSV into per_config files if needed."""
    per_dir = output_dir / "per_config"
    if not force and any(per_dir.glob("*_summary.csv")):
        existing = []
        for path in per_dir.glob("*_summary.csv"):
            existing.extend(load_csv_rows(path))
        if existing and all(r.get("scheme", "standard") == "standard" for r in existing):
            return

    summary_src = output_dir / "sift_gist_utility_summary.csv"
    metrics_src = output_dir / "sift_gist_utility_metrics.csv"

    source_rows: list[dict[str, Any]] = []
    if summary_src.is_file():
        summary_rows = load_csv_rows(summary_src)
        if summary_rows and all(r.get("scheme", "standard") == "standard" for r in summary_rows):
            source_rows = summary_rows
    if not source_rows and metrics_src.is_file():
        source_rows = [
            r for r in load_csv_rows(metrics_src) if r.get("scheme", "standard") == "standard"
        ]

    if not source_rows:
        return

    if force and per_dir.exists():
        for path in per_dir.glob("*_summary.csv"):
            path.unlink(missing_ok=True)
        for path in per_dir.glob("*_metrics.csv"):
            path.unlink(missing_ok=True)

    metrics_by_key: dict[str, list[dict[str, Any]]] = {}
    if metrics_src.is_file():
        for row in load_csv_rows(metrics_src):
            key = f"{row.get('dataset')}_{row.get('config')}"
            metrics_by_key.setdefault(key, []).append(row)

    for row in source_rows:
        dataset = row.get("dataset", "")
        config = row.get("config", "")
        if not dataset or not config:
            continue
        cfg = next(
            (c for c in V3DB_PUBLIC_CONFIGS if c.dataset == dataset and c.config == config),
            None,
        )
        if cfg is None:
            continue
        normalized = _normalize_row(row, cfg=cfg)
        write_csv(per_config_summary_path(output_dir, cfg), [normalized], SUMMARY_FIELDS)
        metric_rows = metrics_by_key.get(cfg.key)
        if metric_rows:
            write_csv(
                per_config_metrics_path(output_dir, cfg),
                [{**_normalize_row(r, cfg=cfg), "run_index": 0} for r in metric_rows],
                METRICS_FIELDS,
            )
        elif not per_config_metrics_path(output_dir, cfg).is_file():
            write_csv(
                per_config_metrics_path(output_dir, cfg),
                [{**normalized, "run_index": 0}],
                METRICS_FIELDS,
            )

    if any(per_dir.glob("*_summary.csv")):
        print("migrated legacy CSV -> per_config/")


def aggregate_results(
    output_dir: Path,
    *,
    force_remigrate: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    migrate_legacy_aggregates(output_dir, force=force_remigrate)
    per_dir = output_dir / "per_config"
    all_metrics: list[dict[str, Any]] = []
    all_summary: list[dict[str, Any]] = []

    for cfg in V3DB_PUBLIC_CONFIGS:
        metrics_path = per_config_metrics_path(output_dir, cfg)
        summary_path = per_config_summary_path(output_dir, cfg)
        if metrics_path.is_file():
            all_metrics.extend(load_csv_rows(metrics_path))
        elif summary_path.is_file():
            all_metrics.extend({**r, "run_index": 0} for r in load_csv_rows(summary_path))
        elif trace_path_for(output_dir, cfg).is_file():
            rows = recover_config_from_trace(cfg, output_dir, trace_path_for(output_dir, cfg))
            all_metrics.extend(rows)

        if summary_path.is_file():
            all_summary.extend(_normalize_row(r) for r in load_csv_rows(summary_path))

    if not all_summary and all_metrics:
        all_summary = [
            _normalize_row(r)
            for r in all_metrics
            if r.get("scheme", "standard") == "standard"
        ]

    order = {(c.dataset, c.config): i for i, c in enumerate(V3DB_PUBLIC_CONFIGS)}
    all_summary.sort(key=lambda r: order.get((r.get("dataset", ""), r.get("config", "")), 99))
    all_metrics.sort(
        key=lambda r: (
            order.get((r.get("dataset", ""), r.get("config", "")), 99),
            r.get("scheme", ""),
        )
    )
    return all_metrics, all_summary


def build_summary_rows(metrics_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in metrics_rows:
        if row.get("scheme") != "standard":
            continue
        out.append(_normalize_row(row))
    return out


def run_config(
    cfg: PublicUtilityConfig,
    *,
    data_root: Path,
    output_dir: Path,
    num_runs: int,
    force_recompute: bool,
    export_traces: bool,
) -> list[dict[str, Any]]:
    print(f"\n=== {cfg.dataset} / {cfg.config} ===")
    ds = load_dataset(data_root, cfg.data_name)
    base = np.asarray(ds.base_vecs, dtype=np.float32)
    queries = np.asarray(ds.query_vecs, dtype=np.float32)
    gt = np.asarray(ds.gt_vecs, dtype=np.int64)
    n_base, dim = base.shape
    n_queries = int(queries.shape[0])
    print(f"base={base.shape} queries={queries.shape} gt={gt.shape}")
    print(f"full_base={compute_full_base(cfg.dataset, n_base, n_queries, dim)}")

    t0 = time.time()
    summary = run_accuracy_bench(
        base,
        queries,
        gt,
        top_k=cfg.top_k,
        name=cfg.bench_name,
        n_list=cfg.n_list,
        M=cfg.M,
        K=cfg.K,
        n_probe=cfg.n_probe,
        scale_n=cfg.scale_n,
        cluster_bound=cfg.cluster_bound,
        num_runs=num_runs,
        force_recompute=force_recompute,
        report_ks=REPORT_KS,
        layout=cfg.layout,
    )
    elapsed = time.time() - t0
    print(f"acc_bench finished in {elapsed:.1f}s")
    print(summary)

    trace_path = trace_path_for(output_dir, cfg)
    index_size: int | None = None
    if export_traces:
        if trace_path.exists() and not force_recompute:
            try:
                with np.load(trace_path) as data:
                    index_size = int(data["index_size_bytes"])
                print(f"using existing trace: {trace_path}")
            except (KeyError, OSError, ValueError):
                index_size = export_standard_traces(
                    cfg,
                    base=base,
                    queries=queries,
                    gt=gt,
                    trace_path=trace_path,
                )
        else:
            index_size = export_standard_traces(
                cfg,
                base=base,
                queries=queries,
                gt=gt,
                trace_path=trace_path,
            )
        print(f"trace saved: {trace_path}")

    rows: list[dict[str, Any]] = []
    for scheme in ("standard", "zk"):
        rows.append(
            _row_from_summary(
                cfg,
                scheme=scheme,
                summary=summary,
                num_base=n_base,
                num_queries=n_queries,
                dim=dim,
                index_size_bytes=index_size if scheme == "standard" else "",
                trace_path=str(trace_path) if export_traces and scheme == "standard" else "",
            )
        )
    write_per_config(cfg, rows, output_dir)
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run V3DB-aligned public utility baseline on SIFT1M/GIST1M."
    )
    parser.add_argument(
        "--datasets",
        default="sift1m,gist1m",
        help="Comma-separated: sift1m,gist1m",
    )
    parser.add_argument(
        "--configs",
        default="high-acc,zk-opt",
        help="Comma-separated: high-acc,zk-opt",
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("data"),
        help="Root containing sift/ and gist/ (default: data with V3DB symlinks).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/public_utility"),
    )
    parser.add_argument("--num-runs", type=int, default=1)
    parser.add_argument("--force-recompute", action="store_true")
    parser.add_argument(
        "--no-traces",
        action="store_true",
        help="Skip NPZ trace export (standard path predictions).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume mode: skip completed configs and aggregate existing results.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip configs with existing per-config outputs or recoverable traces.",
    )
    parser.add_argument(
        "--only-missing",
        action="store_true",
        help="Run only configs without per-config summary files.",
    )
    parser.add_argument(
        "--aggregate-only",
        action="store_true",
        help="Only aggregate per_config/ (and migrate legacy CSV) into top-level outputs.",
    )
    parser.add_argument(
        "--force-remigrate",
        action="store_true",
        help="Rebuild per_config/ from legacy top-level CSV even if per_config exists.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    data_root = args.data_root
    if not data_root.is_absolute():
        data_root = repo_root() / data_root

    output_dir = args.output_dir
    if not output_dir.is_absolute():
        output_dir = repo_root() / output_dir

    skip_existing = args.skip_existing or args.resume
    only_missing = args.only_missing or args.resume

    if args.aggregate_only:
        metrics_rows, summary_rows = aggregate_results(
            output_dir,
            force_remigrate=args.force_remigrate,
        )
        write_csv(output_dir / "sift_gist_utility_metrics.csv", metrics_rows, METRICS_FIELDS)
        write_csv(output_dir / "sift_gist_utility_summary.csv", summary_rows, SUMMARY_FIELDS)
        print(f"Aggregated {len(summary_rows)} summary row(s)")
        print(f"Wrote {output_dir / 'sift_gist_utility_summary.csv'}")
        return 0

    datasets = [d.strip() for d in args.datasets.split(",") if d.strip()]
    config_names = [c.strip() for c in args.configs.split(",") if c.strip()]
    configs = resolve_configs(datasets, config_names)
    if not configs:
        raise SystemExit(f"No configs matched datasets={datasets!r} configs={config_names!r}")

    all_rows: list[dict[str, Any]] = []
    for cfg in configs:
        skip, reason = should_skip_config(
            cfg,
            output_dir,
            skip_existing=skip_existing,
            only_missing=only_missing,
        )
        if skip:
            print(f"skip {cfg.key}: {reason}")
            existing = load_existing_config_rows(cfg, output_dir)
            if existing is None and trace_path_for(output_dir, cfg).is_file():
                existing = recover_config_from_trace(
                    cfg, output_dir, trace_path_for(output_dir, cfg)
                )
            if existing:
                all_rows.extend(existing)
            continue

        if skip_existing and not per_config_summary_path(output_dir, cfg).is_file():
            trace_path = trace_path_for(output_dir, cfg)
            if trace_path.is_file() and not args.force_recompute:
                print(f"recover {cfg.key} from existing trace")
                all_rows.extend(recover_config_from_trace(cfg, output_dir, trace_path))
                continue

        rows = run_config(
            cfg,
            data_root=data_root,
            output_dir=output_dir,
            num_runs=args.num_runs,
            force_recompute=args.force_recompute,
            export_traces=not args.no_traces,
        )
        all_rows.extend(rows)

    metrics_rows, summary_rows = aggregate_results(output_dir)
    write_csv(output_dir / "sift_gist_utility_metrics.csv", metrics_rows, METRICS_FIELDS)
    write_csv(output_dir / "sift_gist_utility_summary.csv", summary_rows, SUMMARY_FIELDS)
    print(f"\nWrote {output_dir / 'sift_gist_utility_metrics.csv'}")
    print(f"Wrote {output_dir / 'sift_gist_utility_summary.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
