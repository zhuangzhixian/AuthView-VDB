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
    "workload_model",
    "grouping_strategy",
    "purity_mode",
    "locality",
    "visible_ratio",
    "block_size",
    "cases",
    "median_region_count",
    "median_pure_region_ratio",
    "median_impure_region_ratio",
    "median_impure_valid_ratio",
    "median_dist_reduction_plan",
    "median_dist_reduction_ideal",
    "median_plan_vs_masked_cost",
    "median_ideal_vs_masked_cost",
    "median_PA_plan",
    "median_PA_ideal",
    "all_planned_equals_masked",
    "all_validation_passed",
]

BETA_SUMMARY_FIELDS = [
    "workload_model",
    "grouping_strategy",
    "block_size",
    "visible_ratio",
    "locality",
    "cases",
    "median_effective_visible_ratio",
    "median_impure_valid_ratio",
    "median_pure_invisible_valid_ratio",
    "median_pure_visible_valid_ratio",
    "median_plan_vs_masked_cost",
    "q25_plan_vs_masked_cost",
    "q75_plan_vs_masked_cost",
    "median_dist_reduction_plan",
    "median_PA_plan",
    "all_validation_passed",
    "all_planned_equals_masked",
]


def _median(values: list[float]) -> float:
    if not values:
        raise ValueError("empty value list for median")
    return float(statistics.median(values))


def _quantile(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("empty value list for quantile")
    return float(statistics.quantiles(values, n=4)[int(q * 4) - 1])


def _bool_all(values: list[str]) -> str:
    return str(all(v.lower() == "true" for v in values)).lower()


def _impure_valid_ratio(row: dict) -> float:
    if row.get("effective_impure_valid_ratio"):
        return float(row["effective_impure_valid_ratio"])
    n_valid = int(row["N_valid"])
    if n_valid <= 0:
        return 0.0
    return int(row["impure_valid_count"]) / n_valid


def _effective_ratio(row: dict, field: str, fallback_num: str, fallback_den: str) -> float:
    if row.get(field):
        return float(row[field])
    n_valid = int(row.get("N_valid") or 0)
    if n_valid <= 0:
        return 0.0
    return int(row.get(fallback_num) or 0) / n_valid


def load_metrics(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def is_beta_locality(rows: list[dict]) -> bool:
    return bool(rows) and rows[0].get("workload_model") == "beta_locality"


def _legacy_group_key(row: dict) -> tuple[str, ...]:
    return (
        row.get("workload_model", "purity_sweep"),
        row["grouping_strategy"],
        row["purity_mode"],
        row.get("locality", ""),
        row["visible_ratio"],
        row["block_size"],
    )


def _beta_group_key(row: dict) -> tuple[str, ...]:
    return (
        row["workload_model"],
        row["grouping_strategy"],
        row["block_size"],
        row["visible_ratio"],
        row["locality"],
    )


def summarize_legacy(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[_legacy_group_key(row)].append(row)

    summary: list[dict] = []
    for key in sorted(grouped):
        group = grouped[key]
        summary.append(
            {
                "workload_model": key[0],
                "grouping_strategy": key[1],
                "purity_mode": key[2],
                "locality": key[3],
                "visible_ratio": key[4],
                "block_size": key[5],
                "cases": len(group),
                "median_region_count": int(
                    round(_median([float(r["region_count"]) for r in group]))
                ),
                "median_pure_region_ratio": f"{_median([float(r['pure_region_ratio']) for r in group]):.6f}",
                "median_impure_region_ratio": f"{_median([float(r['impure_region_ratio']) for r in group]):.6f}",
                "median_impure_valid_ratio": f"{_median([_impure_valid_ratio(r) for r in group]):.6f}",
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


def summarize_beta(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[_beta_group_key(row)].append(row)

    summary: list[dict] = []
    for key in sorted(grouped):
        group = grouped[key]
        costs = [float(r["plan_vs_masked_cost"]) for r in group]
        summary.append(
            {
                "workload_model": key[0],
                "grouping_strategy": key[1],
                "block_size": key[2],
                "visible_ratio": key[3],
                "locality": key[4],
                "cases": len(group),
                "median_effective_visible_ratio": f"{_median([float(r['effective_visible_ratio']) for r in group]):.6f}",
                "median_impure_valid_ratio": f"{_median([float(r['effective_impure_valid_ratio']) for r in group]):.6f}",
                "median_pure_invisible_valid_ratio": f"{_median([float(r['effective_pure_invisible_valid_ratio']) for r in group]):.6f}",
                "median_pure_visible_valid_ratio": f"{_median([float(r['effective_pure_visible_valid_ratio']) for r in group]):.6f}",
                "median_plan_vs_masked_cost": f"{_median(costs):.6f}",
                "q25_plan_vs_masked_cost": f"{_quantile(costs, 0.25):.6f}",
                "q75_plan_vs_masked_cost": f"{_quantile(costs, 0.75):.6f}",
                "median_dist_reduction_plan": f"{_median([float(r['dist_reduction_plan']) for r in group]):.6f}",
                "median_PA_plan": f"{_median([float(r['PA_plan']) for r in group]):.6f}",
                "all_validation_passed": _bool_all(
                    [r["validation_passed"] for r in group]
                ),
                "all_planned_equals_masked": _bool_all(
                    [r["planned_equals_masked"] for r in group]
                ),
            }
        )
    return summary


def summarize(rows: list[dict]) -> list[dict]:
    if is_beta_locality(rows):
        return summarize_beta(rows)
    return summarize_legacy(rows)


def summary_fields(rows: list[dict]) -> list[str]:
    if is_beta_locality(rows):
        return BETA_SUMMARY_FIELDS
    return SUMMARY_FIELDS


def write_summary(rows: list[dict], output: Path, fields: list[str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
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

    fields = summary_fields(raw)
    summary = summarize(raw)
    write_summary(summary, args.output, fields)
    print(f"Wrote {len(summary)} summary rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
