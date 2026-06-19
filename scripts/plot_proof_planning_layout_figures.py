#!/usr/bin/env python3
"""
Phase 6B-2.14: Veda-style separate subfigure PDFs for access-signature layout.

Each figure is a standalone PDF for LaTeX subfigure composition.
Plaintext cost-model — NOT ZK gates.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

MAIN_PLOT_FILES = (
    "main_merged_k_knob.pdf",
    "main_cost_breakdown_clean.pdf",
    "main_impure_fallback_clean.pdf",
)

OPTIONAL_PLOT_FILES = ("main_sa_pa_frontier_clean.pdf",)

FORBIDDEN_PLOT_FILES = (
    "main_layout_tradeoff_multipanel.pdf",
    "main_selectivity_sensitivity.pdf",
    "repaired_selectivity_sensitivity.pdf",
)

MERGED_K_ASC = (1, 2, 4, 8, 16, 64)
MERGED_K_LABEL = {1, 4, 16, 64}
FRONTIER_XLIM = (0.95, 1.55)

# Veda-style palette
COLOR_AUTH = "#F1D097"
COLOR_DIST = "#45A8BB"
COLOR_MASK = "#CB5623"
COLOR_PA = "#CB5623"
COLOR_SA = "#45A8BB"
COLOR_MERGED = "#CB5623"
COLOR_REF = "#666666"

FIG_W = 3.35
FIG_H = 2.55
FS_LABEL = 9.5
FS_TICK = 8.5
FS_LEGEND = 8.5
GRID_ALPHA = 0.16
GRID_LW = 0.55
LINE_LW = 1.7
MARKER_SIZE = 4.0

COST_COMPONENTS = (
    ("auth_region", "Auth/region", COLOR_AUTH),
    ("distance_adc", "Distance/ADC", COLOR_DIST),
    ("mask_topk", "Mask + top-k", COLOR_MASK),
)

COST_BREAKDOWN_SPECS = (
    ("global", 0, "Global"),
    ("merged_k", 16, "k=16"),
    ("merged_k", 4, "k=4"),
    ("merged_k", 1, "k=1"),
    ("acl_signature", 0, "ACL"),
)

COST_BREAKDOWN_LABELS = tuple(spec[2] for spec in COST_BREAKDOWN_SPECS)


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _f(row: dict, key: str, default: float = 0.0) -> float:
    raw = row.get(key, "")
    if raw in ("", None):
        return default
    return float(raw)


def _median(values: list[float]) -> float:
    return float(statistics.median(values))


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


def _role_selectivity_map(metrics: list[dict]) -> dict[int, float]:
    by_role: dict[int, list[float]] = defaultdict(list)
    for row in metrics:
        by_role[int(row["query_role"])].append(_f(row, "effective_selectivity"))
    return {role: _median(vals) for role, vals in by_role.items()}


def pick_query_role_for_selectivity(
    metrics: list[dict],
    target: float = 0.5,
) -> int:
    role_map = _role_selectivity_map(metrics)
    if not role_map:
        return 0
    return min(role_map, key=lambda r: abs(role_map[r] - target))


def filter_metrics_by_role(metrics: list[dict], query_role: int) -> list[dict]:
    return [r for r in metrics if int(r["query_role"]) == query_role]


def aggregate_layout_points(
    metrics: list[dict],
) -> dict[tuple[str, int], dict[str, float]]:
    grouped: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in metrics:
        layout = row["physical_layout"]
        mk = int(row["merged_k"]) if layout == "merged_k" else 0
        grouped[(layout, mk)].append(row)

    out: dict[tuple[str, int], dict[str, float]] = {}
    for key, rows in grouped.items():
        region = _median([_f(r, "estimated_region_cost") for r in rows])
        vis = _median([_f(r, "estimated_visibility_cost") for r in rows])
        out[key] = {
            "SA_commit": _median([_f(r, "SA_commit") for r in rows]),
            "PA_plan": _median([_f(r, "PA_plan") for r in rows]),
            "impure_valid_ratio": _median([_f(r, "impure_valid_ratio") for r in rows]),
            "estimated_cost_plan": _median(
                [_f(r, "estimated_cost_plan") for r in rows]
            ),
            "auth_region": region + vis,
            "distance_adc": _median([_f(r, "estimated_distance_cost") for r in rows]),
            "mask_topk": _median([_f(r, "estimated_mask_topk_cost") for r in rows]),
        }
    return out


def _get_point(
    points: dict[tuple[str, int], dict[str, float]],
    layout: str,
    merged_k: int = 0,
) -> dict[str, float] | None:
    return points.get((layout, merged_k))


def _merged_k_series(
    points: dict[tuple[str, int], dict[str, float]],
) -> list[tuple[int, dict[str, float]]]:
    return [
        (k, pt)
        for k in MERGED_K_ASC
        if (pt := _get_point(points, "merged_k", k)) is not None
    ]


def plot_main_merged_k_knob(
    points: dict[tuple[str, int], dict[str, float]],
    output: Path,
) -> None:
    plt = _require_matplotlib()
    series = _merged_k_series(points)
    ks = [k for k, _ in series]
    pa = [pt["PA_plan"] for _, pt in series]
    sa = [pt["SA_commit"] for _, pt in series]
    x = list(range(len(ks)))

    fig, ax_pa = plt.subplots(figsize=(FIG_W, FIG_H))
    ax_sa = ax_pa.twinx()

    line_pa = ax_pa.plot(
        x,
        pa,
        color=COLOR_PA,
        marker="o",
        linewidth=LINE_LW,
        markersize=MARKER_SIZE,
        label=r"$PA_{\mathrm{plan}}$",
        solid_capstyle="round",
    )
    line_sa = ax_sa.plot(
        x,
        sa,
        color=COLOR_SA,
        marker="s",
        linewidth=LINE_LW,
        markersize=MARKER_SIZE,
        linestyle="--",
        label=r"$SA_{\mathrm{commit}}$",
        solid_capstyle="round",
    )

    ax_pa.set_xticks(x)
    ax_pa.set_xticklabels([str(k) for k in ks])
    _style_axes(ax_pa, xlabel="Merged-k", ylabel=r"$PA_{\mathrm{plan}}$")
    ax_sa.set_ylabel(r"$SA_{\mathrm{commit}}$", fontsize=FS_LABEL, color=COLOR_SA)
    ax_pa.tick_params(axis="y", labelcolor=COLOR_PA)
    ax_sa.tick_params(axis="y", labelcolor=COLOR_SA, labelsize=FS_TICK)

    lines = line_pa + line_sa
    ax_pa.legend(
        [ln for ln in lines],
        [ln.get_label() for ln in lines],
        loc="upper left",
        fontsize=FS_LEGEND,
        framealpha=0.9,
        handlelength=1.6,
        borderpad=0.35,
    )
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_main_cost_breakdown_clean(
    points: dict[tuple[str, int], dict[str, float]],
    output: Path,
) -> None:
    plt = _require_matplotlib()
    global_pt = _get_point(points, "global", 0)
    if global_pt is None:
        raise ValueError("global layout missing for normalization")

    global_total = global_pt["estimated_cost_plan"]
    if global_total <= 0:
        raise ValueError("global estimated_cost_plan must be positive")

    labels: list[str] = []
    stacks: dict[str, list[float]] = {key: [] for key, _, _ in COST_COMPONENTS}

    for layout, mk, label in COST_BREAKDOWN_SPECS:
        pt = _get_point(points, layout, mk)
        if pt is None:
            continue
        labels.append(label)
        for key, _, _ in COST_COMPONENTS:
            stacks[key].append(pt[key] / global_total)

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    x = list(range(len(labels)))
    bottom = [0.0] * len(labels)

    for key, comp_label, color in COST_COMPONENTS:
        heights = stacks[key]
        ax.bar(x, heights, bottom=bottom, label=comp_label, color=color, width=0.58)
        bottom = [b + h for b, h in zip(bottom, heights)]

    ax.axhline(1.0, color="#888888", linestyle="--", linewidth=0.8, alpha=0.55)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=FS_TICK)
    ax.set_ylim(0.0, 1.05)
    _style_axes(ax, ylabel="Norm. cost")
    ax.legend(
        loc="upper right",
        fontsize=FS_LEGEND,
        framealpha=0.9,
        handlelength=1.2,
        borderpad=0.3,
    )
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_main_impure_fallback_clean(
    points: dict[tuple[str, int], dict[str, float]],
    output: Path,
) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))

    series = _merged_k_series(points)
    if series:
        mk_imp = [pt["impure_valid_ratio"] for _, pt in series]
        mk_pa = [pt["PA_plan"] for _, pt in series]
        ax.plot(
            mk_imp,
            mk_pa,
            color=COLOR_MERGED,
            linewidth=LINE_LW,
            marker="o",
            markersize=MARKER_SIZE,
            label="Merged-k",
            solid_capstyle="round",
        )

    for layout, marker in (("global", "^"), ("acl_signature", "s")):
        pt = _get_point(points, layout, 0)
        if pt is None:
            continue
        ax.scatter(
            pt["impure_valid_ratio"],
            pt["PA_plan"],
            c=COLOR_REF,
            marker=marker,
            s=28,
            edgecolors="white",
            linewidths=0.3,
            zorder=3,
        )

    _style_axes(
        ax,
        xlabel=r"$N_{\mathrm{impure}}/N_{\mathrm{valid}}$",
        ylabel=r"$PA_{\mathrm{plan}}$",
    )
    ax.set_xlim(-0.02, 1.02)
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


def plot_main_sa_pa_frontier_clean(
    points: dict[tuple[str, int], dict[str, float]],
    output: Path,
) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))

    series = _merged_k_series(points)
    if series:
        mk_x = [pt["SA_commit"] for _, pt in series]
        mk_y = [pt["PA_plan"] for _, pt in series]
        ax.plot(
            mk_x,
            mk_y,
            color=COLOR_MERGED,
            linewidth=LINE_LW,
            linestyle="-",
            zorder=2,
            label="Merged-k",
        )
        for k, pt in series:
            ax.scatter(
                pt["SA_commit"],
                pt["PA_plan"],
                c=COLOR_MERGED,
                marker="o",
                s=22,
                edgecolors="white",
                linewidths=0.25,
                zorder=3,
            )
            if k in MERGED_K_LABEL:
                ax.annotate(
                    f"k={k}",
                    (pt["SA_commit"], pt["PA_plan"]),
                    textcoords="offset points",
                    xytext=(3, 3),
                    fontsize=7,
                    color="#444444",
                )

    for layout, marker in (("global", "^"), ("acl_signature", "s")):
        pt = _get_point(points, layout, 0)
        if pt is None:
            continue
        label = "Global" if layout == "global" else "ACL"
        ax.scatter(
            pt["SA_commit"],
            pt["PA_plan"],
            c=COLOR_REF,
            marker=marker,
            s=32,
            label=label,
            edgecolors="white",
            linewidths=0.3,
            zorder=4,
        )

    ax.axhline(1.0, color=COLOR_SA, linestyle="--", linewidth=0.9, alpha=0.6, zorder=1)

    ax.set_xlim(*FRONTIER_XLIM)
    _style_axes(ax, xlabel=r"$SA_{\mathrm{commit}}$", ylabel=r"$PA_{\mathrm{plan}}$")
    ax.legend(
        loc="upper right",
        fontsize=FS_LEGEND,
        framealpha=0.9,
        handlelength=1.2,
        borderpad=0.35,
    )
    fig.tight_layout(pad=0.4)
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_all_subfigures(
    metrics_rows: list[dict],
    output_dir: Path,
    *,
    include_optional_frontier: bool = True,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    query_role = pick_query_role_for_selectivity(metrics_rows, 0.5)
    role_metrics = filter_metrics_by_role(metrics_rows, query_role)
    points = aggregate_layout_points(role_metrics)

    outputs = [output_dir / name for name in MAIN_PLOT_FILES]
    plot_main_merged_k_knob(points, outputs[0])
    plot_main_cost_breakdown_clean(points, outputs[1])
    plot_main_impure_fallback_clean(points, outputs[2])

    if include_optional_frontier:
        opt = output_dir / OPTIONAL_PLOT_FILES[0]
        plot_main_sa_pa_frontier_clean(points, opt)
        outputs.append(opt)

    return outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot Veda-style layout subfigures (Phase 6B-2.14)."
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("artifacts/proof_planning_layout_summary_repaired.csv"),
    )
    parser.add_argument(
        "--metrics",
        type=Path,
        default=Path("artifacts/proof_planning_layout_metrics_repaired.csv"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/figures"),
    )
    parser.add_argument(
        "--no-optional-frontier",
        action="store_true",
        help="Skip optional SA/PA frontier subfigure.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.summary.is_file():
        print(f"error: summary not found: {args.summary}", file=sys.stderr)
        return 1
    if not args.metrics.is_file():
        print(f"error: metrics not found: {args.metrics}", file=sys.stderr)
        return 1

    summary_rows = load_csv(args.summary)
    metrics_rows = load_csv(args.metrics)
    if not summary_rows or not metrics_rows:
        print("error: empty input CSV", file=sys.stderr)
        return 1

    outputs = plot_all_subfigures(
        metrics_rows,
        args.output_dir,
        include_optional_frontier=not args.no_optional_frontier,
    )
    for path in outputs:
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
