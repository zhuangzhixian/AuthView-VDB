#!/usr/bin/env python3
"""
Phase 8C: Plot public utility recall figure from summary CSV.

Plaintext IVF-PQ utility (standard scheme) — RQ1 main figure.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import numpy as np

FIG_W = 5.2
FIG_H = 2.8
FS_LABEL = 9.5
FS_TICK = 8.5
GRID_ALPHA = 0.16
GRID_LW = 0.55

RECALL_COLORS = ("#888888", "#45A8BB", "#CB5623")
RECALL_LABELS = ("Recall@1", "Recall@10", "Recall@100")


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


def _label(row: dict) -> str:
    ds = row.get("dataset", "").replace("1m", "").upper()
    cfg = row.get("config", "")
    return f"{ds}\n{cfg}"


def filter_standard_rows(rows: list[dict]) -> list[dict]:
    if not rows:
        return rows
    if "scheme" in rows[0]:
        return [r for r in rows if r.get("scheme", "standard") == "standard"]
    return rows


def plot_recall(rows: list[dict], output: Path) -> None:
    plt = _require_matplotlib()
    rows = filter_standard_rows(rows)
    order = [
        ("sift1m", "high-acc"),
        ("sift1m", "zk-opt"),
        ("gist1m", "high-acc"),
        ("gist1m", "zk-opt"),
    ]
    by_key = {(r["dataset"], r["config"]): r for r in rows}
    labels = []
    r1, r10, r100 = [], [], []
    for key in order:
        row = by_key.get(key)
        if row is None:
            continue
        labels.append(_label(row))
        r1.append(_f(row, "recall_at_1"))
        r10.append(_f(row, "recall_at_10"))
        r100.append(_f(row, "recall_at_100"))

    if not labels:
        raise ValueError("no summary rows to plot")

    x = np.arange(len(labels))  # type: ignore[name-defined]
    width = 0.22
    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    ax.bar(x - width, r1, width, label=RECALL_LABELS[0], color=RECALL_COLORS[0], edgecolor="white", linewidth=0.4)
    ax.bar(x, r10, width, label=RECALL_LABELS[1], color=RECALL_COLORS[1], edgecolor="white", linewidth=0.4)
    ax.bar(x + width, r100, width, label=RECALL_LABELS[2], color=RECALL_COLORS[2], edgecolor="white", linewidth=0.4)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=FS_TICK)
    ax.set_ylim(0.0, 1.05)
    _style_axes(ax, ylabel="Recall", xlabel="Dataset / config")
    ax.legend(fontsize=FS_TICK, frameon=False, loc="lower right")
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot public utility recall figure.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/public_utility/sift_gist_utility_summary.csv"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/figures"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    input_path = args.input if args.input.is_absolute() else root / args.input
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = load_csv(input_path)
    out = output_dir / "main_public_utility_recall.pdf"
    plot_recall(rows, out)
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
