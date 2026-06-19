#!/usr/bin/env python3
"""
Phase 7C: Plot RQ6 proof scaling figures from paper-ready summary CSV.

Real ZK measurements — not cost model. Does not re-run proofs.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

MAIN_PLOT_FILES = (
    "main_proof_scaling_gates.pdf",
    "main_proof_scaling_time.pdf",
)

PATH_ORDER = (
    "baseline",
    "auth_all_visible",
    "auth_policy",
    "auth_committed",
    "auth_slot_aligned",
)

PATH_LABELS = {
    "baseline": "Content-only",
    "auth_all_visible": "Auth-mask",
    "auth_policy": "Policy",
    "auth_committed": "Committed-auth",
    "auth_slot_aligned": "Slot-aligned",
}

PATH_COLORS = {
    "baseline": "#888888",
    "auth_all_visible": "#A8A8A8",
    "auth_policy": "#C4B5A0",
    "auth_committed": "#45A8BB",
    "auth_slot_aligned": "#CB5623",
}

FIG_W = 4.4
FIG_H = 2.7
FS_LABEL = 9.5
FS_TICK = 8.5
FS_LEGEND = 8.0
GRID_ALPHA = 0.16
GRID_LW = 0.55
LINE_LW = 1.6
MARKER_SIZE = 4.0


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _metric(row: dict, *keys: str) -> float:
    for key in keys:
        if key in row and row[key] not in ("", None):
            return float(row[key])
    return 0.0


def aggregate_by_path_n_sel(rows: list[dict]) -> dict[str, dict[int, float]]:
    """Group by (path, N_sel); median metric across workloads sharing N_sel."""
    grouped: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in rows:
        path = row["path"]
        if path not in PATH_ORDER:
            continue
        n_sel = int(float(row["N_sel"]))
        grouped[(path, n_sel)].append(row)

    out: dict[str, dict[int, float]] = {p: {} for p in PATH_ORDER}
    for (path, n_sel), group in grouped.items():
        vals = [_metric(r, "median_gates", "gates") for r in group]
        out[path][n_sel] = float(statistics.median(vals))
    return out


def aggregate_prove_by_path_n_sel(rows: list[dict]) -> dict[str, dict[int, float]]:
    grouped: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in rows:
        path = row["path"]
        if path not in PATH_ORDER:
            continue
        n_sel = int(float(row["N_sel"]))
        grouped[(path, n_sel)].append(row)

    out: dict[str, dict[int, float]] = {p: {} for p in PATH_ORDER}
    for (path, n_sel), group in grouped.items():
        vals = [_metric(r, "median_prove_time", "prove_time") for r in group]
        out[path][n_sel] = float(statistics.median(vals))
    return out


def distinct_n_sel_values(rows: list[dict]) -> list[int]:
    return sorted({int(float(r["N_sel"])) for r in rows})


def _require_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except ImportError as exc:
        raise SystemExit("matplotlib required (pip install matplotlib)") from exc


def _style_axes(ax, *, ylabel: str = "", xlabel: str = "") -> None:
    ax.tick_params(labelsize=FS_TICK)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=FS_LABEL)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=FS_LABEL)
    ax.grid(True, alpha=GRID_ALPHA, linewidth=GRID_LW)


def plot_scaling_lines(
    series: dict[str, dict[int, float]],
    *,
    ylabel: str,
    output: Path,
) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))

    for path in PATH_ORDER:
        points = series.get(path, {})
        if not points:
            continue
        xs = sorted(points)
        ys = [points[x] for x in xs]
        ax.plot(
            xs,
            ys,
            color=PATH_COLORS[path],
            marker="o",
            linewidth=LINE_LW,
            markersize=MARKER_SIZE,
            label=PATH_LABELS[path],
            solid_capstyle="round",
        )

    _style_axes(ax, xlabel=r"$N_{\mathrm{sel}}$", ylabel=ylabel)
    ax.legend(
        loc="upper left",
        fontsize=FS_LEGEND,
        framealpha=0.9,
        handlelength=1.4,
        borderpad=0.35,
    )
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_all(rows: list[dict], output_dir: Path) -> list[Path]:
    if not rows:
        raise ValueError("empty input CSV")

    output_dir.mkdir(parents=True, exist_ok=True)
    gates = aggregate_by_path_n_sel(rows)
    prove = aggregate_prove_by_path_n_sel(rows)

    outputs = [
        output_dir / MAIN_PLOT_FILES[0],
        output_dir / MAIN_PLOT_FILES[1],
    ]
    plot_scaling_lines(gates, ylabel="Median gates", output=outputs[0])
    plot_scaling_lines(prove, ylabel="Prove time (s)", output=outputs[1])
    return outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot RQ6 proof scaling figures (Phase 7C)."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/auth_zk_paper_ready_summary.csv"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/figures"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    outputs = plot_all(load_csv(args.input), args.output_dir)
    for path in outputs:
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
