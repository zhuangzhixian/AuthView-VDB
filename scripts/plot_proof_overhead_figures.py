#!/usr/bin/env python3
"""
Phase 7A: Plot RQ2 proof overhead figures from paper-ready summary CSV.

Real ZK measurements — not cost model. Does not re-run proofs.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

MAIN_PLOT_FILES = (
    "main_proof_overhead_gates.pdf",
    "main_proof_overhead_time.pdf",
)

OPTIONAL_PLOT_FILES = ("main_proof_overhead_size.pdf",)

PATH_ORDER = (
    "baseline",
    "auth_all_visible",
    "auth_policy",
    "auth_committed",
    "auth_slot_aligned",
    "auth_acl_class",
)

PATH_SHORT_LABELS = {
    "baseline": "Content-only",
    "auth_all_visible": "Auth-mask",
    "auth_policy": "Policy",
    "auth_committed": "Committed",
    "auth_slot_aligned": "Slot-aligned",
    "auth_acl_class": "ACL-class",
}

# Muted bar palette (one color family)
BAR_COLORS = (
    "#888888",
    "#A8A8A8",
    "#C4B5A0",
    "#45A8BB",
    "#6B9DB8",
    "#CB5623",
)

FIG_W = 4.2
FIG_H = 2.6
FS_LABEL = 9.5
FS_TICK = 8.5
GRID_ALPHA = 0.16
GRID_LW = 0.55


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _f(row: dict, key: str, default: float = 0.0) -> float:
    raw = row.get(key, "")
    if raw in ("", None):
        return default
    return float(raw)


def _metric(row: dict, *keys: str) -> float:
    for key in keys:
        if key in row and row[key] not in ("", None):
            return float(row[key])
    return 0.0


def filter_workload(
    rows: list[dict],
    *,
    n_probe: int | None,
    slot_per_list: int | None,
    n_sel: int | None,
) -> list[dict]:
    out = rows
    if n_probe is not None:
        out = [r for r in out if int(float(r["n_probe"])) == n_probe]
    if slot_per_list is not None:
        out = [r for r in out if int(float(r["slot_per_list"])) == slot_per_list]
    if n_sel is not None:
        out = [r for r in out if int(float(r["N_sel"])) == n_sel]
    return out


def pick_representative_workload(rows: list[dict]) -> tuple[int, int, int]:
    """Prefer n_probe=4, slot_per_list=64 (N_sel=256) if present."""
    preferred = filter_workload(rows, n_probe=4, slot_per_list=64, n_sel=None)
    if preferred:
        r0 = preferred[0]
        return int(float(r0["n_probe"])), int(float(r0["slot_per_list"])), int(float(r0["N_sel"]))
    r0 = rows[0]
    return int(float(r0["n_probe"])), int(float(r0["slot_per_list"])), int(float(r0["N_sel"]))


def rows_by_path(workload_rows: list[dict]) -> dict[str, dict]:
    by_path: dict[str, dict] = {}
    for row in workload_rows:
        by_path[row["path"]] = row
    return by_path


def ordered_paths(by_path: dict[str, dict]) -> list[str]:
    return [p for p in PATH_ORDER if p in by_path]


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


def plot_gates_normalized(
    by_path: dict[str, dict],
    paths: list[str],
    output: Path,
) -> None:
    plt = _require_matplotlib()
    baseline_gates = _metric(by_path["baseline"], "median_gates", "gates")
    if baseline_gates <= 0:
        raise ValueError("baseline gates must be positive")

    labels = [PATH_SHORT_LABELS.get(p, p) for p in paths]
    values = [_metric(by_path[p], "median_gates", "gates") / baseline_gates for p in paths]
    colors = [BAR_COLORS[i % len(BAR_COLORS)] for i in range(len(paths))]

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    x = range(len(paths))
    ax.bar(x, values, color=colors, width=0.62, edgecolor="white", linewidth=0.4)
    ax.axhline(1.0, color="#666666", linestyle="--", linewidth=0.8, alpha=0.65)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=FS_TICK)
    _style_axes(ax, ylabel="Norm. gates")
    ax.set_ylim(0.0, max(values) * 1.12 if values else 1.05)
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_prove_time(
    by_path: dict[str, dict],
    paths: list[str],
    output: Path,
) -> None:
    plt = _require_matplotlib()
    labels = [PATH_SHORT_LABELS.get(p, p) for p in paths]
    values = [_metric(by_path[p], "median_prove_time", "prove_time") for p in paths]
    colors = [BAR_COLORS[i % len(BAR_COLORS)] for i in range(len(paths))]

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    x = range(len(paths))
    ax.bar(x, values, color=colors, width=0.62, edgecolor="white", linewidth=0.4)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=FS_TICK)
    _style_axes(ax, ylabel="Prove time (s)")
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_proof_size(
    by_path: dict[str, dict],
    paths: list[str],
    output: Path,
) -> None:
    plt = _require_matplotlib()
    labels = [PATH_SHORT_LABELS.get(p, p) for p in paths]
    values_kb = [
        _metric(by_path[p], "median_proof_size", "proof_size") / 1024.0 for p in paths
    ]
    colors = [BAR_COLORS[i % len(BAR_COLORS)] for i in range(len(paths))]

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    x = range(len(paths))
    ax.bar(x, values_kb, color=colors, width=0.62, edgecolor="white", linewidth=0.4)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=FS_TICK)
    _style_axes(ax, ylabel="Proof size (KB)")
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_all(
    rows: list[dict],
    output_dir: Path,
    *,
    n_probe: int | None,
    slot_per_list: int | None,
    include_size: bool = True,
) -> list[Path]:
    if not rows:
        raise ValueError("empty input CSV")

    if n_probe is None and slot_per_list is None:
        n_probe, slot_per_list, _ = pick_representative_workload(rows)

    workload = filter_workload(rows, n_probe=n_probe, slot_per_list=slot_per_list, n_sel=None)
    if not workload:
        raise ValueError("no rows match workload filter")

    by_path = rows_by_path(workload)
    if "baseline" not in by_path:
        raise ValueError("baseline path missing in selected workload")

    paths = ordered_paths(by_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    outputs = [
        output_dir / MAIN_PLOT_FILES[0],
        output_dir / MAIN_PLOT_FILES[1],
    ]
    plot_gates_normalized(by_path, paths, outputs[0])
    plot_prove_time(by_path, paths, outputs[1])

    if include_size:
        size_out = output_dir / OPTIONAL_PLOT_FILES[0]
        plot_proof_size(by_path, paths, size_out)
        outputs.append(size_out)

    return outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot RQ2 proof overhead figures (Phase 7A).")
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
    parser.add_argument("--n-probe", type=int, default=None)
    parser.add_argument("--slot-per-list", type=int, default=None)
    parser.add_argument("--no-size-figure", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    rows = load_csv(args.input)
    outputs = plot_all(
        rows,
        args.output_dir,
        n_probe=args.n_probe,
        slot_per_list=args.slot_per_list,
        include_size=not args.no_size_figure,
    )
    for path in outputs:
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
