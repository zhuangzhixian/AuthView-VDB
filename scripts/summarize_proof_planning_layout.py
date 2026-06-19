#!/usr/bin/env python3
"""Aggregate access-signature layout sweep metrics."""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

SUMMARY_FIELDS = [
    "workload_model",
    "physical_layout",
    "num_objects",
    "num_roles",
    "num_signatures",
    "merged_k",
    "cases",
    "median_effective_selectivity",
    "median_SA_commit",
    "median_PA_plan",
    "median_plan_vs_masked_cost",
    "q25_plan_vs_masked_cost",
    "q75_plan_vs_masked_cost",
    "median_impure_valid_ratio",
    "median_impure_region_ratio",
    "median_dist_reduction_plan",
    "median_stored_entries_norm",
    "all_planned_equals_masked",
    "all_validation_passed",
]


def _median(values: list[float]) -> float:
    return float(statistics.median(values))


def _quantile(values: list[float], q: float) -> float:
    return float(statistics.quantiles(values, n=4)[int(q * 4) - 1])


def _bool_all(values: list[str]) -> str:
    return str(all(v.lower() == "true" for v in values)).lower()


def _group_key(row: dict) -> tuple[str, ...]:
    return (
        row["workload_model"],
        row["physical_layout"],
        row["num_objects"],
        row["num_roles"],
        row["num_signatures"],
        row["merged_k"],
    )


def summarize(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[_group_key(row)].append(row)

    summary: list[dict] = []
    for key in sorted(grouped):
        group = grouped[key]
        costs = [float(r["plan_vs_masked_cost"]) for r in group]
        summary.append(
            {
                "workload_model": key[0],
                "physical_layout": key[1],
                "num_objects": key[2],
                "num_roles": key[3],
                "num_signatures": key[4],
                "merged_k": key[5],
                "cases": len(group),
                "median_effective_selectivity": f"{_median([float(r['effective_selectivity']) for r in group]):.6f}",
                "median_SA_commit": f"{_median([float(r['SA_commit']) for r in group]):.6f}",
                "median_PA_plan": f"{_median([float(r['PA_plan']) for r in group]):.6f}",
                "median_plan_vs_masked_cost": f"{_median(costs):.6f}",
                "q25_plan_vs_masked_cost": f"{_quantile(costs, 0.25):.6f}",
                "q75_plan_vs_masked_cost": f"{_quantile(costs, 0.75):.6f}",
                "median_impure_valid_ratio": f"{_median([float(r['impure_valid_ratio']) for r in group]):.6f}",
                "median_impure_region_ratio": f"{_median([float(r['impure_region_ratio']) for r in group]):.6f}",
                "median_dist_reduction_plan": f"{_median([float(r['dist_reduction_plan']) for r in group]):.6f}",
                "median_stored_entries_norm": f"{_median([float(r['stored_entries_norm']) for r in group]):.6f}",
                "all_planned_equals_masked": _bool_all(
                    [r["planned_equals_masked"] for r in group]
                ),
                "all_validation_passed": _bool_all(
                    [r["validation_passed"] for r in group]
                ),
            }
        )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize layout sweep metrics.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/proof_planning_layout_metrics_repaired.csv"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/proof_planning_layout_summary_repaired.csv"),
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    with args.input.open(newline="") as f:
        raw = list(csv.DictReader(f))
    if not raw:
        print("error: empty input", file=sys.stderr)
        return 1

    summary = summarize(raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary)
    print(f"Wrote {len(summary)} summary rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
