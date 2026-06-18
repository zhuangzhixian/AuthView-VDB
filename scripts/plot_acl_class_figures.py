#!/usr/bin/env python3
"""
Phase 7B: Plot RQ3 ACL-class compression figures from summary CSV.

Real ZK measurements — not cost model. Does not re-run proofs.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

MAIN_PLOT_FILES = ("main_acl_class_compression.pdf",)
OPTIONAL_PLOT_FILES = ("main_acl_class_prove_time.pdf",)

N_ACL_ORDER = (1, 2, 4, 8, 16, 32, 64)

FIG_W = 4.0
FIG_H = 2.6
FS_LABEL = 9.5
FS_TICK = 8.5
GRID_ALPHA = 0.16
GRID_LW = 0.55
LINE_COLOR = "#45A8BB"
LINE_LW = 1.7
MARKER_SIZE = 4.5


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _f(row: dict, key: str, default: float = 0.0) -> float:
    raw = row.get(key, "")
    if raw in ("", None):
        return default
    return float(raw)


def filter_workload(
    rows: list[dict],
    *,
    n_probe: int | None,
    slot_per_list: int | None,
) -> list[dict]:
    out = rows
    if n_probe is not None:
        out = [r for r in out if int(float(r["n_probe"])) == n_probe]
    if slot_per_list is not None:
        out = [r for r in out if int(float(r["slot_per_list"])) == slot_per_list]
    return out


def acl_class_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["path"] == "auth_acl_class"]


def gates_ratio_series(rows: list[dict]) -> list[tuple[int, float]]:
    by_n_acl = {int(float(r["N_acl"])): r for r in rows}
    series: list[tuple[int, float]] = []
    for n_acl in N_ACL_ORDER:
        if n_acl not in by_n_acl:
            continue
        ratio = _f(by_n_acl[n_acl], "acl_vs_committed_gates")
        if ratio <= 0:
            continue
        series.append((n_acl, ratio))
    return series


def prove_ratio_series(rows: list[dict]) -> list[tuple[int, float]]:
    by_n_acl = {int(float(r["N_acl"])): r for r in rows}
    series: list[tuple[int, float]] = []
    for n_acl in N_ACL_ORDER:
        if n_acl not in by_n_acl:
            continue
        ratio = _f(by_n_acl[n_acl], "acl_vs_committed_prove_time")
        if ratio <= 0:
            continue
        series.append((n_acl, ratio))
    return series


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


def plot_gates_compression(series: list[tuple[int, float]], output: Path) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    xs = [s[0] for s in series]
    ys = [s[1] for s in series]
    ax.plot(
        xs,
        ys,
        color=LINE_COLOR,
        marker="o",
        linewidth=LINE_LW,
        markersize=MARKER_SIZE,
        solid_capstyle="round",
    )
    ax.axhline(1.0, color="#666666", linestyle="--", linewidth=0.8, alpha=0.65)
    ax.set_xticks(xs)
    ax.set_xticklabels([str(k) for k in xs])
    _style_axes(ax, xlabel=r"$N_{\mathrm{acl}}$", ylabel="Norm. gates (committed = 1.0)")
    ymax = max(ys) if ys else 1.05
    ax.set_ylim(0.85, max(1.05, ymax * 1.08))
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_prove_compression(series: list[tuple[int, float]], output: Path) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    xs = [s[0] for s in series]
    ys = [s[1] for s in series]
    ax.plot(
        xs,
        ys,
        color="#CB5623",
        marker="s",
        linewidth=LINE_LW,
        markersize=MARKER_SIZE,
        solid_capstyle="round",
    )
    ax.axhline(1.0, color="#666666", linestyle="--", linewidth=0.8, alpha=0.65)
    ax.set_xticks(xs)
    ax.set_xticklabels([str(k) for k in xs])
    _style_axes(ax, xlabel=r"$N_{\mathrm{acl}}$", ylabel="Prove ratio (committed = 1.0)")
    ymax = max(ys) if ys else 1.05
    ax.set_ylim(0.85, max(1.05, ymax * 1.08))
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_all(
    rows: list[dict],
    output_dir: Path,
    *,
    n_probe: int | None = 4,
    slot_per_list: int | None = 64,
    include_prove: bool = True,
) -> list[Path]:
    if not rows:
        raise ValueError("empty input CSV")

    workload = filter_workload(rows, n_probe=n_probe, slot_per_list=slot_per_list)
    acl_rows = acl_class_rows(workload)
    if not acl_rows:
        raise ValueError("no auth_acl_class rows in selected workload")

    gates_series = gates_ratio_series(acl_rows)
    if not gates_series:
        raise ValueError("no gates ratio data")

    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = [output_dir / MAIN_PLOT_FILES[0]]
    plot_gates_compression(gates_series, outputs[0])

    if include_prove:
        prove_series = prove_ratio_series(acl_rows)
        if prove_series:
            prove_out = output_dir / OPTIONAL_PLOT_FILES[0]
            plot_prove_compression(prove_series, prove_out)
            outputs.append(prove_out)

    return outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot RQ3 ACL-class compression figures (Phase 7B)."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/auth_zk_acl_class_summary_repeat3.csv"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/figures"),
    )
    parser.add_argument("--n-probe", type=int, default=4)
    parser.add_argument("--slot-per-list", type=int, default=64)
    parser.add_argument("--no-prove-figure", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    outputs = plot_all(
        load_csv(args.input),
        args.output_dir,
        n_probe=args.n_probe,
        slot_per_list=args.slot_per_list,
        include_prove=not args.no_prove_figure,
    )
    for path in outputs:
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
