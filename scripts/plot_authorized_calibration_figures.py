#!/usr/bin/env python3
"""Phase 9B: Plot full authorized-reference calibration figures."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

FIG_W = 5.2
FIG_H = 2.8
FS_LABEL = 9.5
FS_TICK = 8.5
GRID_ALPHA = 0.16
GRID_LW = 0.55

POLICY_COLORS = {
    "uniform_random": "#45A8BB",
    "clustered_acl": "#CB5623",
    "skewed_acl": "#888888",
}
POLICY_LABELS = {
    "uniform_random": "Uniform",
    "clustered_acl": "Clustered ACL",
    "skewed_acl": "Skewed ACL",
}
CONFIG_ORDER = [
    ("sift1m", "high-acc"),
    ("sift1m", "zk-opt"),
    ("gist1m", "high-acc"),
    ("gist1m", "zk-opt"),
]


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _f(row: dict, key: str, default: float = 0.0) -> float:
    raw = row.get(key, "")
    if raw in ("", None):
        return default
    return float(raw)


def _require_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except ImportError as exc:
        raise SystemExit("matplotlib required") from exc


def _style_axes(ax, *, ylabel: str = "", xlabel: str = "") -> None:
    ax.tick_params(labelsize=FS_TICK)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=FS_LABEL)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=FS_LABEL)
    ax.grid(True, axis="y", alpha=GRID_ALPHA, linewidth=GRID_LW)


def plot_calibration_gaps(rows: list[dict], output: Path, *, k: int = 10) -> None:
    plt = _require_matplotlib()
    rows = [r for r in rows if int(float(r.get("k", 0))) == k]
    fig, axes = plt.subplots(2, 2, figsize=(FIG_W * 1.5, FIG_H * 1.6), sharex=True)
    axes_flat = axes.flatten()
    selectivities = sorted({round(_f(r, "selectivity"), 4) for r in rows})

    for ax, (dataset, config) in zip(axes_flat, CONFIG_ORDER):
        panel = [r for r in rows if r["dataset"] == dataset and r["config"] == config]
        for policy in ("uniform_random", "clustered_acl", "skewed_acl"):
            sub = [r for r in panel if r["policy_mode"] == policy]
            if not sub:
                continue
            xs = [_f(r, "selectivity") for r in sub]
            cand_gap = [_f(r, "candidate_full_recall_gap") for r in sub]
            post_gap = [_f(r, "post_full_recall_gap") for r in sub]
            order = sorted(range(len(xs)), key=lambda i: xs[i])
            xs = [xs[i] for i in order]
            cand_gap = [cand_gap[i] for i in order]
            post_gap = [post_gap[i] for i in order]
            ax.plot(
                xs,
                cand_gap,
                marker="o",
                markersize=3,
                linewidth=1.0,
                linestyle="-",
                color=POLICY_COLORS[policy],
                label=f"{POLICY_LABELS[policy]} cand−full",
            )
            ax.plot(
                xs,
                post_gap,
                marker="s",
                markersize=3,
                linewidth=1.0,
                linestyle="--",
                color=POLICY_COLORS[policy],
                alpha=0.75,
            )
        ds = "SIFT1M" if dataset == "sift1m" else "GIST1M"
        ax.set_title(f"{ds} {config}", fontsize=FS_LABEL)
        ax.axhline(0.0, color="#cccccc", linewidth=0.6)
        _style_axes(ax, xlabel="Selectivity", ylabel="Recall gap vs full" if ax is axes_flat[0] else "")
        ax.set_xticks(selectivities)

    handles, labels = axes_flat[0].get_legend_handles_labels()
    if handles:
        fig.legend(handles[:3], labels[:3], loc="upper center", ncol=3, fontsize=FS_TICK, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot auth calibration figure.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/auth_calibration/full_authorized_reference_summary.csv"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/figures"))
    parser.add_argument("--k", type=int, default=10)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    input_path = args.input if args.input.is_absolute() else root / args.input
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    rows = load_csv(input_path)
    if not rows:
        raise SystemExit(f"no rows in {input_path}")
    out = output_dir / "main_authorized_reference_calibration.pdf"
    plot_calibration_gaps(rows, out, k=args.k)
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
