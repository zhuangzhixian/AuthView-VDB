#!/usr/bin/env python3
"""
Aggregate paper-ready AuthView ZK benchmark metrics (median + ratios).

Reads raw per-repeat CSV from bench_auth_paths.py; writes one summary row
per (workload, path) with median gates/prove_time/verify_time/proof_size.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

SUMMARY_FIELDS = [
    "num_vectors",
    "dim",
    "n_list",
    "n_probe",
    "slot_per_list",
    "top_k",
    "N_sel",
    "visible_ratio",
    "auth_tree_depth",
    "path",
    "n_repeats",
    "median_gates",
    "median_prove_time",
    "median_verify_time",
    "median_proof_size",
    "median_build_time",
    "policy_vs_baseline_gates",
    "committed_vs_baseline_gates",
    "slot_vs_committed_gates",
    "slot_vs_committed_prove_time",
]

PATH_NAMES = (
    "baseline",
    "auth_all_visible",
    "auth_policy",
    "auth_committed",
    "auth_slot_aligned",
)


def _median(values: list[float]) -> float:
    if not values:
        raise ValueError("empty value list for median")
    return float(statistics.median(values))


def _ratio(num: float, denom: float) -> str:
    if denom == 0:
        return ""
    return f"{num / denom:.6f}"


def load_metrics(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def summarize(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[int, ...], dict[str, list[dict]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        wkey = (
            int(row["num_vectors"]),
            int(row["dim"]),
            int(row["n_list"]),
            int(row["n_probe"]),
            int(row["slot_per_list"]),
            int(row["top_k"]),
        )
        grouped[wkey][row["path"]].append(row)

    summary: list[dict] = []
    for wkey in sorted(grouped):
        paths = grouped[wkey]

        medians: dict[str, dict[str, float]] = {}
        for path in PATH_NAMES:
            if path not in paths:
                continue
            reps = paths[path]
            medians[path] = {
                "gates": _median([float(r["gates"]) for r in reps]),
                "prove_time": _median([float(r["prove_time"]) for r in reps]),
                "verify_time": _median([float(r["verify_time"]) for r in reps]),
                "proof_size": _median([float(r["proof_size"]) for r in reps]),
                "build_time": _median([float(r["build_time"]) for r in reps]),
                "auth_tree_depth": int(reps[0]["auth_tree_depth"]),
                "n_repeats": len(reps),
                "N_sel": int(reps[0]["N_sel"]),
                "visible_ratio": reps[0]["visible_ratio"],
            }

        baseline_gates = medians.get("baseline", {}).get("gates")
        policy_gates = medians.get("auth_policy", {}).get("gates")
        committed_gates = medians.get("auth_committed", {}).get("gates")
        committed_prove = medians.get("auth_committed", {}).get("prove_time")
        slot_gates = medians.get("auth_slot_aligned", {}).get("gates")
        slot_prove = medians.get("auth_slot_aligned", {}).get("prove_time")

        for path in PATH_NAMES:
            if path not in medians:
                continue
            m = medians[path]
            out = {
                "num_vectors": wkey[0],
                "dim": wkey[1],
                "n_list": wkey[2],
                "n_probe": wkey[3],
                "slot_per_list": wkey[4],
                "top_k": wkey[5],
                "N_sel": m["N_sel"],
                "visible_ratio": m["visible_ratio"],
                "auth_tree_depth": m["auth_tree_depth"],
                "path": path,
                "n_repeats": m["n_repeats"],
                "median_gates": int(round(m["gates"])),
                "median_prove_time": f"{m['prove_time']:.9f}",
                "median_verify_time": f"{m['verify_time']:.9f}",
                "median_proof_size": int(round(m["proof_size"])),
                "median_build_time": f"{m['build_time']:.9f}",
                "policy_vs_baseline_gates": "",
                "committed_vs_baseline_gates": "",
                "slot_vs_committed_gates": "",
                "slot_vs_committed_prove_time": "",
            }
            if path == "auth_policy" and baseline_gates is not None and policy_gates is not None:
                out["policy_vs_baseline_gates"] = _ratio(policy_gates, baseline_gates)
            if path == "auth_committed" and baseline_gates is not None and committed_gates is not None:
                out["committed_vs_baseline_gates"] = _ratio(committed_gates, baseline_gates)
            if path == "auth_slot_aligned":
                if committed_gates is not None and slot_gates is not None:
                    out["slot_vs_committed_gates"] = _ratio(slot_gates, committed_gates)
                if committed_prove is not None and slot_prove is not None:
                    out["slot_vs_committed_prove_time"] = _ratio(slot_prove, committed_prove)
            summary.append(out)

    return summary


def write_summary(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize AuthView ZK benchmark metrics (median + ratios)."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/auth_zk_paper_ready_metrics.csv"),
        help="Raw metrics CSV from bench_auth_paths.py.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/auth_zk_paper_ready_summary.csv"),
        help="Summary CSV output path.",
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
    n_workloads = len({(r["n_probe"], r["slot_per_list"], r["top_k"]) for r in summary})
    print(
        f"Wrote {len(summary)} summary rows "
        f"({n_workloads} workloads × paths) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
