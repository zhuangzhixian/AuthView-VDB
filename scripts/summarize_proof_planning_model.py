#!/usr/bin/env python3
"""
Aggregate proof-planning cost-model sweep metrics (medians per group).

Reads raw CSV from bench_proof_planning_model.py.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

SUMMARY_FIELDS = [
    "grouping_strategy",
    "purity_mode",
    "visible_ratio",
    "block_size",
    "cases",
    "median_region_count",
    "median_pure_region_ratio",
    "median_impure_region_ratio",
    "median_dist_reduction_plan",
    "median_dist_reduction_ideal",
    "median_plan_vs_masked_cost",
    "median_ideal_vs_masked_cost",
    "median_PA_plan",
    "median_PA_ideal",
    "all_planned_equals_masked",
    "all_validation_passed",
]


def _median(values: list[float]) -> float:
    if not values:
        raise ValueError("empty value list for median")
    return float(statistics.median(values))


def _bool_all(values: list[str]) -> str:
    return str(all(v.lower() == "true" for v in values)).lower()


def load_metrics(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def summarize(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        key = (
            row["grouping_strategy"],
            row["purity_mode"],
            row["visible_ratio"],
            row["block_size"],
        )
        grouped[key].append(row)

    summary: list[dict] = []
    for key in sorted(grouped):
        group = grouped[key]
        summary.append(
            {
                "grouping_strategy": key[0],
                "purity_mode": key[1],
                "visible_ratio": key[2],
                "block_size": key[3],
                "cases": len(group),
                "median_region_count": int(
                    round(_median([float(r["region_count"]) for r in group]))
                ),
                "median_pure_region_ratio": f"{_median([float(r['pure_region_ratio']) for r in group]):.6f}",
                "median_impure_region_ratio": f"{_median([float(r['impure_region_ratio']) for r in group]):.6f}",
                "median_dist_reduction_plan": f"{_median([float(r['dist_reduction_plan']) for r in group]):.6f}",
                "median_dist_reduction_ideal": f"{_median([float(r['dist_reduction_ideal']) for r in group]):.6f}",
                "median_plan_vs_masked_cost": f"{_median([float(r['plan_vs_masked_cost']) for r in group]):.6f}",
                "median_ideal_vs_masked_cost": f"{_median([float(r['ideal_vs_masked_cost']) for r in group]):.6f}",
                "median_PA_plan": f"{_median([float(r['PA_plan']) for r in group]):.6f}",
                "median_PA_ideal": f"{_median([float(r['PA_ideal']) for r in group]):.6f}",
                "all_planned_equals_masked": _bool_all(
                    [r["planned_equals_masked"] for r in group]
                ),
                "all_validation_passed": _bool_all(
                    [r["validation_passed"] for r in group]
                ),
            }
        )
    return summary


def write_summary(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize proof-planning cost-model sweep metrics."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/proof_planning_model_metrics.csv"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/proof_planning_model_summary.csv"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    raw = load_metrics(args.input)
    if not raw:
        print("error: empty input CSV", file=sys.stderr)
        return 1

    summary = summarize(raw)
    write_summary(summary, args.output)
    print(f"Wrote {len(summary)} summary rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
