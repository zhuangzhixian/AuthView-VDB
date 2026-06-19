#!/usr/bin/env python3
"""Phase 9B: Select representative calibration queries from Phase 9A traces."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

from scripts.auth_calibration_lib import (
    CALIBRATION_QUERY_FIELDS,
    cap_queries_per_dataset,
    load_csv,
    load_visibility_npz,
    mask_path_for,
    select_calibration_queries,
    write_csv,
)
from scripts.auth_overlay_lib import DEFAULT_POLICY_MODES, DEFAULT_SELECTIVITIES


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_traces(trace_dir: Path) -> dict[tuple[str, str], tuple[np.ndarray, np.ndarray]]:
    out: dict[tuple[str, str], tuple[np.ndarray, np.ndarray]] = {}
    for path in sorted(trace_dir.glob("*_results.npz")):
        name = path.stem.replace("_results", "")
        if "_" not in name:
            continue
        dataset, config = name.rsplit("_", 1)
        with np.load(path, allow_pickle=False) as data:
            pred = np.asarray(data["pred"], dtype=np.int64)
            gt = np.asarray(data["gt"], dtype=np.int64)
        out[(dataset, config)] = (pred, gt)
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select authorized calibration queries.")
    parser.add_argument(
        "--auth-summary",
        type=Path,
        default=Path("artifacts/auth_overlay/public_trace_auth_summary.csv"),
    )
    parser.add_argument(
        "--auth-metrics",
        type=Path,
        default=Path("artifacts/auth_overlay/public_trace_auth_metrics.csv"),
    )
    parser.add_argument(
        "--trace-dir",
        type=Path,
        default=Path("artifacts/public_utility/traces"),
    )
    parser.add_argument(
        "--overlay-dir",
        type=Path,
        default=Path("artifacts/auth_overlay"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/auth_calibration/calibration_queries.csv"),
    )
    parser.add_argument("--queries-per-bucket", type=int, default=5)
    parser.add_argument("--max-queries-per-dataset", type=int, default=500)
    parser.add_argument("--k-select", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--policy-modes", default=",".join(DEFAULT_POLICY_MODES))
    parser.add_argument("--selectivities", default=",".join(str(s) for s in DEFAULT_SELECTIVITIES))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    trace_dir = args.trace_dir if args.trace_dir.is_absolute() else root / args.trace_dir
    overlay_dir = args.overlay_dir if args.overlay_dir.is_absolute() else root / args.overlay_dir
    output = args.output if args.output.is_absolute() else root / args.output

    # Summary/metrics are used for validation only (must exist for Phase 9B inputs).
    summary_path = args.auth_summary if args.auth_summary.is_absolute() else root / args.auth_summary
    metrics_path = args.auth_metrics if args.auth_metrics.is_absolute() else root / args.auth_metrics
    if not summary_path.is_file():
        raise SystemExit(f"missing auth summary: {summary_path}")
    if not metrics_path.is_file():
        raise SystemExit(f"missing auth metrics: {metrics_path}")
    _ = load_csv(summary_path)

    traces = load_traces(trace_dir)
    if not traces:
        raise SystemExit(f"no traces in {trace_dir}")

    policy_modes = [p.strip() for p in args.policy_modes.split(",") if p.strip()]
    selectivities = [float(s.strip()) for s in args.selectivities.split(",") if s.strip()]
    rng = np.random.default_rng(args.seed)

    all_rows: list[dict] = []
    for (dataset, config), (pred, gt) in sorted(traces.items()):
        depth = int(pred.shape[1])
        for policy_mode in policy_modes:
            for selectivity in selectivities:
                mask_path = mask_path_for(overlay_dir, dataset, policy_mode, selectivity)
                if not mask_path.is_file():
                    print(f"warning: missing mask {mask_path}", file=sys.stderr)
                    continue
                visible, _ = load_visibility_npz(mask_path)
                bucket_seed = int(rng.integers(0, 2**31 - 1))
                bucket_rng = np.random.default_rng(bucket_seed)
                rows = select_calibration_queries(
                    trace_pred=pred,
                    trace_gt=gt,
                    dataset=dataset,
                    config=config,
                    policy_mode=policy_mode,
                    selectivity=selectivity,
                    visible=visible,
                    candidate_depth=depth,
                    queries_per_bucket=args.queries_per_bucket,
                    rng=bucket_rng,
                    k_select=args.k_select,
                )
                all_rows.extend(rows)

    all_rows = cap_queries_per_dataset(
        all_rows, args.max_queries_per_dataset, args.seed
    )
    write_csv(output, all_rows, CALIBRATION_QUERY_FIELDS)
    print(f"Wrote {output} ({len(all_rows)} queries)")
    for ds in sorted({r["dataset"] for r in all_rows}):
        n = sum(1 for r in all_rows if r["dataset"] == ds)
        print(f"  {ds}: {n} queries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
