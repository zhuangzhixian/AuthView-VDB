#!/usr/bin/env python3
"""Phase 9B: Full authorized-reference calibration on public datasets."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

from scripts.auth_calibration_lib import (
    CHECKPOINT_FIELDS,
    DATASET_SPECS,
    SUMMARY_FIELDS,
    aggregate_checkpoint_rows,
    append_csv,
    cap_queries_per_dataset,
    dataset_paths,
    estimate_calibration_cost,
    evaluate_calibration_query,
    load_completed_keys,
    load_csv,
    load_visibility_npz,
    mask_path_for,
    read_query_vector,
    write_csv,
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Calibrate full authorized reference.")
    parser.add_argument(
        "--calibration-queries",
        type=Path,
        default=Path("artifacts/auth_calibration/calibration_queries.csv"),
    )
    parser.add_argument("--data-root", type=Path, default=Path("data/public"))
    parser.add_argument("--overlay-dir", type=Path, default=Path("artifacts/auth_overlay"))
    parser.add_argument("--trace-dir", type=Path, default=Path("artifacts/public_utility/traces"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/auth_calibration"))
    parser.add_argument("--ks", default="1,10,100")
    parser.add_argument("--chunk-size", type=int, default=50_000)
    parser.add_argument("--max-queries-per-dataset", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--estimate-cost", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--no-faiss", action="store_true")
    return parser.parse_args(argv)


def load_trace(trace_dir: Path, dataset: str, config: str) -> tuple[np.ndarray, np.ndarray]:
    path = trace_dir / f"{dataset}_{config}_results.npz"
    with np.load(path, allow_pickle=False) as data:
        pred = np.asarray(data["pred"], dtype=np.int64)
        gt = np.asarray(data["gt"], dtype=np.int64)
    return pred, gt


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    data_root = args.data_root if args.data_root.is_absolute() else root / args.data_root
    overlay_dir = args.overlay_dir if args.overlay_dir.is_absolute() else root / args.overlay_dir
    trace_dir = args.trace_dir if args.trace_dir.is_absolute() else root / args.trace_dir
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    calib_path = (
        args.calibration_queries
        if args.calibration_queries.is_absolute()
        else root / args.calibration_queries
    )

    calib_rows = load_csv(calib_path)
    if not calib_rows:
        raise SystemExit(f"no calibration queries in {calib_path}")

    if args.max_queries_per_dataset > 0:
        calib_rows = cap_queries_per_dataset(
            calib_rows, args.max_queries_per_dataset, seed=42
        )

    ks = tuple(int(k.strip()) for k in args.ks.split(",") if k.strip())
    checkpoint_path = output_dir / "full_authorized_reference_checkpoint.csv"
    metrics_path = output_dir / "full_authorized_reference_metrics.csv"
    summary_path = output_dir / "full_authorized_reference_summary.csv"

    cost = estimate_calibration_cost(calib_rows, chunk_size=args.chunk_size)
    print(f"calibration queries: {cost['total_calibration_queries']}")
    print(f"by dataset: {cost['queries_by_dataset']}")
    print(f"estimated distance ops: {cost['estimated_distance_ops']:.3e}")
    print(f"chunk_size: {args.chunk_size}")

    if args.dry_run or args.estimate_cost:
        if args.dry_run:
            print("dry-run: no heavy computation performed")
        return 0

    completed = load_completed_keys(checkpoint_path) if (args.resume or args.skip_existing) else set()

    trace_cache: dict[tuple[str, str], tuple[np.ndarray, np.ndarray]] = {}
    mask_cache: dict[tuple[str, str, float], np.ndarray] = {}
    paths_cache: dict[str, dict[str, Path]] = {}
    new_rows: list[dict] = []
    t0 = time.time()

    for i, row in enumerate(calib_rows):
        dataset = row["dataset"]
        config = row["config"]
        policy_mode = row["policy_mode"]
        selectivity = float(row["selectivity"])
        query_id = int(row["query_id"])

        pending_ks = []
        for k in ks:
            key = (dataset, config, policy_mode, str(selectivity), str(query_id), str(k))
            if args.skip_existing and key in completed:
                continue
            pending_ks.append(k)
        if not pending_ks:
            continue

        if (dataset, config) not in trace_cache:
            trace_cache[(dataset, config)] = load_trace(trace_dir, dataset, config)
        pred, gt = trace_cache[(dataset, config)]

        mask_key = (dataset, policy_mode, selectivity)
        if mask_key not in mask_cache:
            mask_path = mask_path_for(overlay_dir, dataset, policy_mode, selectivity)
            visible, _ = load_visibility_npz(mask_path)
            mask_cache[mask_key] = visible
        visible = mask_cache[mask_key]

        if dataset not in paths_cache:
            paths_cache[dataset] = dataset_paths(data_root, dataset)
        paths = paths_cache[dataset]
        dim = int(DATASET_SPECS[dataset]["dim"])
        query = read_query_vector(paths["query"], dim, query_id)
        pred_row = pred[query_id]
        gt_row = gt[query_id]
        candidate_depth = int(pred.shape[1])

        eval_rows = evaluate_calibration_query(
            query=query,
            pred_row=pred_row,
            gt_row=gt_row,
            visible=visible,
            base_path=paths["base"],
            dim=dim,
            ks=pending_ks,
            candidate_depth=candidate_depth,
            chunk_size=args.chunk_size,
            use_faiss=not args.no_faiss,
        )
        batch: list[dict] = []
        for er in eval_rows:
            out = {
                "dataset": dataset,
                "config": config,
                "policy_mode": policy_mode,
                "selectivity": selectivity,
                "query_id": query_id,
                **er,
            }
            batch.append(out)
            new_rows.append(out)

        append_csv(checkpoint_path, batch, CHECKPOINT_FIELDS)
        for er in eval_rows:
            completed.add(
                (dataset, config, policy_mode, str(selectivity), str(query_id), str(er["k"]))
            )

        if (i + 1) % 10 == 0 or i + 1 == len(calib_rows):
            elapsed = time.time() - t0
            print(f"progress {i + 1}/{len(calib_rows)} elapsed={elapsed:.1f}s")

    all_checkpoint = load_csv(checkpoint_path)
    write_csv(metrics_path, all_checkpoint, CHECKPOINT_FIELDS)
    summary_rows = aggregate_checkpoint_rows(all_checkpoint)
    write_csv(summary_path, summary_rows, SUMMARY_FIELDS)
    print(f"Wrote {checkpoint_path} ({len(all_checkpoint)} rows)")
    print(f"Wrote {metrics_path}")
    print(f"Wrote {summary_path} ({len(summary_rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
