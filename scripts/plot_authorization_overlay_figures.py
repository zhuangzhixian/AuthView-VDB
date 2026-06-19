#!/usr/bin/env python3
"""Phase 9A: Plot authorization overlay utility gap and underfill figures."""

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
        raise SystemExit("matplotlib required (pip install matplotlib)") from exc


def _style_axes(ax, *, ylabel: str = "", xlabel: str = "") -> None:
    ax.tick_params(labelsize=FS_TICK)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=FS_LABEL)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=FS_LABEL)
    ax.grid(True, axis="y", alpha=GRID_ALPHA, linewidth=GRID_LW)


def filter_rows(rows: list[dict], *, k: int) -> list[dict]:
    return [r for r in rows if int(float(r.get("k", 0))) == k]


def plot_metric_by_selectivity(
    rows: list[dict],
    *,
    metric_key: str,
    ylabel: str,
    output: Path,
    k: int = 10,
) -> None:
    plt = _require_matplotlib()
    rows = filter_rows(rows, k=k)
    fig, axes = plt.subplots(1, len(CONFIG_ORDER), figsize=(FIG_W * 1.6, FIG_H), sharey=True)
    if len(CONFIG_ORDER) == 1:
        axes = [axes]

    selectivities = sorted({round(_f(r, "selectivity"), 4) for r in rows})

    for ax, (dataset, config) in zip(axes, CONFIG_ORDER):
        panel_rows = [r for r in rows if r["dataset"] == dataset and r["config"] == config]
        for policy in ("uniform_random", "clustered_acl", "skewed_acl"):
            policy_rows = [r for r in panel_rows if r["policy_mode"] == policy]
            if not policy_rows:
                continue
            xs = [_f(r, "selectivity") for r in policy_rows]
            ys = [_f(r, metric_key) for r in policy_rows]
            order = sorted(range(len(xs)), key=lambda i: xs[i])
            xs = [xs[i] for i in order]
            ys = [ys[i] for i in order]
            ax.plot(
                xs,
                ys,
                marker="o",
                markersize=4,
                linewidth=1.2,
                color=POLICY_COLORS[policy],
                label=POLICY_LABELS[policy],
            )
        ds_label = "SIFT1M" if dataset == "sift1m" else "GIST1M"
        ax.set_title(f"{ds_label} {config}", fontsize=FS_LABEL)
        _style_axes(ax, xlabel="Selectivity", ylabel=ylabel if ax is axes[0] else "")
        ax.set_xticks(selectivities)

    handles, labels = axes[0].get_legend_handles_labels()
    if handles:
        fig.legend(handles, labels, loc="upper center", ncol=3, fontsize=FS_TICK, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot auth overlay figures.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/auth_overlay/public_trace_auth_summary.csv"),
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

    plot_metric_by_selectivity(
        rows,
        metric_key="utility_gap",
        ylabel=f"Utility gap @k={args.k}",
        output=output_dir / "main_auth_overlay_utility_gap.pdf",
        k=args.k,
    )
    plot_metric_by_selectivity(
        rows,
        metric_key="underfill_rate",
        ylabel=f"Underfill rate @k={args.k}",
        output=output_dir / "main_auth_overlay_underfill.pdf",
        k=args.k,
    )
    print(f"Wrote {output_dir / 'main_auth_overlay_utility_gap.pdf'}")
    print(f"Wrote {output_dir / 'main_auth_overlay_underfill.pdf'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
