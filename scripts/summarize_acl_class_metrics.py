#!/usr/bin/env python3
"""
Aggregate ACL-class compression benchmark metrics (median + acl vs committed ratios).

Reads raw CSV from bench_acl_class_paths.py; writes one summary row per
(workload, N_acl, path).
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
    "N_acl",
    "N_acl_max",
    "acl_ratio",
    "visible_ratio",
    "path",
    "n_repeats",
    "median_gates",
    "median_prove_time",
    "median_verify_time",
    "median_proof_size",
    "median_build_time",
    "acl_vs_committed_gates",
    "acl_vs_committed_prove_time",
    "acl_vs_committed_proof_size",
]

PATH_NAMES = ("auth_committed", "auth_acl_class")


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
    grouped: dict[tuple[int, ...], dict[tuple[int, int], dict[str, list[dict]]]] = (
        defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
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
        n_acl = int(row["N_acl"])
        n_acl_max = int(row["N_acl_max"])
        grouped[wkey][(n_acl, n_acl_max)][row["path"]].append(row)

    summary: list[dict] = []
    for wkey in sorted(grouped):
        for (n_acl, n_acl_max), paths in sorted(grouped[wkey].items()):
            medians: dict[str, dict[str, float | int | str]] = {}
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
                    "n_repeats": len(reps),
                    "N_sel": int(reps[0]["N_sel"]),
                    "acl_ratio": reps[0]["acl_ratio"],
                    "visible_ratio": reps[0]["visible_ratio"],
                }

            committed = medians.get("auth_committed", {})
            acl = medians.get("auth_acl_class", {})
            committed_gates = committed.get("gates")
            committed_prove = committed.get("prove_time")
            committed_size = committed.get("proof_size")

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
                    "N_acl": n_acl,
                    "N_acl_max": n_acl_max,
                    "acl_ratio": m["acl_ratio"],
                    "visible_ratio": m["visible_ratio"],
                    "path": path,
                    "n_repeats": m["n_repeats"],
                    "median_gates": int(round(float(m["gates"]))),
                    "median_prove_time": f"{float(m['prove_time']):.9f}",
                    "median_verify_time": f"{float(m['verify_time']):.9f}",
                    "median_proof_size": int(round(float(m["proof_size"]))),
                    "median_build_time": f"{float(m['build_time']):.9f}",
                    "acl_vs_committed_gates": "",
                    "acl_vs_committed_prove_time": "",
                    "acl_vs_committed_proof_size": "",
                }
                if path == "auth_acl_class":
                    if committed_gates is not None:
                        out["acl_vs_committed_gates"] = _ratio(
                            float(m["gates"]), float(committed_gates)
                        )
                    if committed_prove is not None:
                        out["acl_vs_committed_prove_time"] = _ratio(
                            float(m["prove_time"]), float(committed_prove)
                        )
                    if committed_size is not None:
                        out["acl_vs_committed_proof_size"] = _ratio(
                            float(m["proof_size"]), float(committed_size)
                        )
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
        description="Summarize ACL-class compression benchmark metrics."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/auth_zk_acl_class_metrics.csv"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/auth_zk_acl_class_summary.csv"),
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
    n_groups = len(
        {
            (
                r["n_probe"],
                r["slot_per_list"],
                r["top_k"],
                r["N_acl"],
            )
            for r in summary
        }
    )
    print(
        f"Wrote {len(summary)} summary rows "
        f"({n_groups} workload×N_acl groups × paths) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
