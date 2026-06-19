#!/usr/bin/env python3
"""Phase 9A: Evaluate authorization overlay on public benchmark traces."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import numpy as np

from scripts.auth_overlay_lib import (
    DEFAULT_KS,
    DEFAULT_POLICY_MODES,
    DEFAULT_SELECTIVITIES,
    METRICS_FIELDS,
    REFERENCE_SCOPE,
    evaluate_trace_with_visibility,
    load_visibility_npz,
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_summary_rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fieldnames: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def discover_traces(trace_dir: Path, summary_rows: list[dict]) -> list[tuple[str, str, Path]]:
    traces: list[tuple[str, str, Path]] = []
    for row in summary_rows:
        dataset = row["dataset"]
        config = row["config"]
        trace_path = row.get("trace_path", "")
        if trace_path:
            p = Path(trace_path)
            if not p.is_absolute():
                p = repo_root() / p
        else:
            p = trace_dir / f"{dataset}_{config}_results.npz"
        if p.is_file():
            traces.append((dataset, config, p))
    return traces


def discover_overlay_masks(overlay_dir: Path, dataset: str, policy_mode: str) -> list[tuple[float, Path]]:
    masks: list[tuple[float, Path]] = []
    pattern = f"{dataset}_{policy_mode}_sel"
    for path in sorted(overlay_dir.glob(f"{dataset}_{policy_mode}_sel*_visibility.npz")):
        name = path.name
        if not name.startswith(pattern):
            continue
        sel_part = name[len(pattern) :].split("_visibility.npz")[0]
        selectivity = float(sel_part.replace("p", "."))
        masks.append((selectivity, path))
    return masks


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate auth overlay on public traces.")
    parser.add_argument("--trace-dir", type=Path, default=Path("artifacts/public_utility/traces"))
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("artifacts/public_utility/sift_gist_utility_summary.csv"),
    )
    parser.add_argument("--overlay-dir", type=Path, default=Path("artifacts/auth_overlay"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/auth_overlay"))
    parser.add_argument("--policy-modes", default=",".join(DEFAULT_POLICY_MODES))
    parser.add_argument("--selectivities", default=",".join(str(s) for s in DEFAULT_SELECTIVITIES))
    parser.add_argument("--ks", default=",".join(str(k) for k in DEFAULT_KS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    trace_dir = args.trace_dir if args.trace_dir.is_absolute() else root / args.trace_dir
    summary_path = args.summary if args.summary.is_absolute() else root / args.summary
    overlay_dir = args.overlay_dir if args.overlay_dir.is_absolute() else root / args.overlay_dir
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir

    summary_rows = load_summary_rows(summary_path)
    traces = discover_traces(trace_dir, summary_rows)
    if not traces:
        raise SystemExit("no traces found")

    policy_modes = [p.strip() for p in args.policy_modes.split(",") if p.strip()]
    selectivities = [float(s.strip()) for s in args.selectivities.split(",") if s.strip()]
    ks = tuple(int(k.strip()) for k in args.ks.split(",") if k.strip())

    all_rows: list[dict] = []
    for dataset, config, trace_path in traces:
        with np.load(trace_path, allow_pickle=False) as data:
            pred = np.asarray(data["pred"], dtype=np.int64)
            gt = np.asarray(data["gt"], dtype=np.int64)
        candidate_depth = int(pred.shape[1])
        print(f"trace {dataset}/{config}: queries={pred.shape[0]} depth={candidate_depth}")

        for policy_mode in policy_modes:
            masks = discover_overlay_masks(overlay_dir, dataset, policy_mode)
            if not masks:
                print(f"warning: no masks for {dataset}/{policy_mode}", file=sys.stderr)
                continue
            for selectivity, mask_path in masks:
                if selectivity not in selectivities:
                    continue
                visible, _meta = load_visibility_npz(mask_path)
                aggregates = evaluate_trace_with_visibility(
                    pred=pred,
                    gt=gt,
                    visible=visible,
                    dataset=dataset,
                    config=config,
                    policy_mode=policy_mode,
                    selectivity=selectivity,
                    ks=ks,
                    candidate_depth=candidate_depth,
                )
                for agg in aggregates:
                    row = agg.to_row()
                    row["reference_scope"] = REFERENCE_SCOPE
                    all_rows.append(row)

    metrics_path = output_dir / "public_trace_auth_metrics.csv"
    summary_out = output_dir / "public_trace_auth_summary.csv"
    write_csv(metrics_path, all_rows, METRICS_FIELDS)
    write_csv(summary_out, all_rows, METRICS_FIELDS)
    print(f"Wrote {metrics_path} ({len(all_rows)} rows)")
    print(f"Wrote {summary_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
