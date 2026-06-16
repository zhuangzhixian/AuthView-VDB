#!/usr/bin/env python3
"""
Phase 6B-2.5–2.8: Plot proof-planning cost-model figures for paper drafts.

Reads metrics or summary CSV; prefers metrics CSV for breakdown and derived ratios.
Outputs PDF figures under artifacts/figures/.

These plots show plaintext cost-model ratios, NOT measured ZK gate counts.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

BETA_MAIN_PLOT_FILES = (
    "proof_planning_heatmap_cost.pdf",
    "proof_planning_cost_breakdown.pdf",
    "proof_planning_degradation_curve.pdf",
    "proof_planning_granularity_sensitivity.pdf",
)

LOCALITY_MAIN_PLOT_FILES = (
    "proof_planning_locality_vs_cost.pdf",
    "proof_planning_visibility_vs_cost_by_locality.pdf",
    "proof_planning_impure_ratio_vs_cost.pdf",
    "proof_planning_region_granularity_tradeoff.pdf",
)

APPENDIX_PLOT_FILES = ("proof_planning_pa_appendix.pdf",)

VIS_RATIO_COLORS = {
    0.05: "#9467bd",
    0.1: "#1f77b4",
    0.25: "#ff7f0e",
    0.5: "#2ca02c",
    0.75: "#d62728",
    0.9: "#8c564b",
}

LOCALITY_STYLES = {
    0.0: {"color": "#d62728", "marker": "^", "linestyle": ":"},
    0.25: {"color": "#bcbd22", "marker": "v", "linestyle": "-."},
    0.5: {"color": "#ff7f0e", "marker": "s", "linestyle": "--"},
    0.75: {"color": "#9467bd", "marker": "D", "linestyle": "-."},
    1.0: {"color": "#1f77b4", "marker": "o", "linestyle": "-"},
}


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def resolve_metrics_path(input_path: Path) -> Path:
    """Prefer companion metrics CSV when given a summary path."""
    if "summary" in input_path.name:
        stem = input_path.name.replace("_summary.csv", "_metrics.csv")
        candidate = input_path.with_name(stem)
        if candidate.is_file():
            return candidate
    rows = load_csv(input_path) if input_path.is_file() else []
    if rows and "pure_invisible_valid_count" in rows[0]:
        return input_path
    return input_path


def resolve_summary_path(input_path: Path) -> Path:
    if "summary" in input_path.name:
        return input_path
    stem = input_path.name.replace("_metrics.csv", "_summary.csv")
    candidate = input_path.with_name(stem)
    if candidate.is_file():
        return candidate
    return input_path


def workload_model(rows: list[dict]) -> str:
    if not rows:
        return ""
    return rows[0].get("workload_model", "purity_sweep")


def is_beta_locality(rows: list[dict]) -> bool:
    return workload_model(rows) == "beta_locality"


def is_locality_sweep(rows: list[dict]) -> bool:
    return workload_model(rows) == "locality_sweep"


def _require_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except ImportError as exc:
        raise SystemExit(
            "matplotlib is required for plot_proof_planning_figures.py "
            "(pip install matplotlib)"
        ) from exc


def _near(a: float, b: float, tol: float = 0.02) -> bool:
    return abs(a - b) <= tol


def _f(row: dict, key: str, default: float = 0.0) -> float:
    raw = row.get(key, "")
    if raw in ("", None):
        return default
    return float(raw)


def enrich_metrics_rows(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        n_valid = int(row.get("N_valid") or 0)
        pi = int(row.get("pure_invisible_valid_count") or 0)
        pv = int(row.get("pure_visible_valid_count") or 0)
        imp = int(row.get("impure_valid_count") or 0)
        loc_raw = row.get("locality", "")
        locality_f = float(loc_raw) if loc_raw not in ("", None) else -1.0
        visible_ratio = _f(row, "visible_ratio")
        if n_valid <= 0:
            pi_ratio = pv_ratio = imp_ratio = 0.0
        else:
            pi_ratio = pi / n_valid
            pv_ratio = pv / n_valid
            imp_ratio = imp / n_valid
        out.append(
            {
                **row,
                "visible_ratio_f": visible_ratio,
                "locality_f": locality_f,
                "block_size_i": int(row.get("block_size") or 0),
                "plan_vs_masked_cost_f": _f(row, "plan_vs_masked_cost"),
                "dist_reduction_plan_f": _f(row, "dist_reduction_plan"),
                "PA_plan_f": _f(row, "PA_plan"),
                "impure_valid_ratio_f": _f(row, "effective_impure_valid_ratio", imp_ratio),
                "pure_invisible_valid_ratio_f": _f(
                    row, "effective_pure_invisible_valid_ratio", pi_ratio
                ),
                "pure_visible_valid_ratio_f": _f(
                    row, "effective_pure_visible_valid_ratio", pv_ratio
                ),
                "effective_visible_ratio_f": _f(row, "effective_visible_ratio"),
                "region_count_f": float(row.get("region_count") or 0),
                "estimated_region_cost_f": _f(row, "estimated_region_cost"),
                "estimated_visibility_cost_f": _f(row, "estimated_visibility_cost"),
                "estimated_distance_cost_f": _f(row, "estimated_distance_cost"),
                "estimated_mask_topk_cost_f": _f(row, "estimated_mask_topk_cost"),
            }
        )
    return out


def enrich_summary_rows(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        loc_raw = row.get("locality", "")
        locality_f = float(loc_raw) if loc_raw not in ("", None) else -1.0
        out.append(
            {
                **row,
                "visible_ratio_f": _f(row, "visible_ratio"),
                "locality_f": locality_f,
                "block_size_i": int(row.get("block_size") or 0),
                "plan_vs_masked_cost_f": _f(
                    row, "median_plan_vs_masked_cost", _f(row, "plan_vs_masked_cost")
                ),
                "impure_valid_ratio_f": _f(
                    row, "median_impure_valid_ratio", _f(row, "impure_valid_ratio")
                ),
                "dist_reduction_plan_f": _f(
                    row, "median_dist_reduction_plan", _f(row, "dist_reduction_plan")
                ),
                "PA_plan_f": _f(row, "median_PA_plan", _f(row, "PA_plan")),
            }
        )
    return out


def enrich_rows(rows: list[dict]) -> list[dict]:
    if rows and "median_plan_vs_masked_cost" in rows[0]:
        return enrich_summary_rows(rows)
    return enrich_metrics_rows(rows)


def _ivf_rows(rows: list[dict]) -> list[dict]:
    return [
        r
        for r in rows
        if r["grouping_strategy"] == "ivf_list" and r["block_size_i"] == 0
    ]


def plot_heatmap_cost(summary_rows: list[dict], output: Path) -> None:
    """Main Fig 1: visible ratio × locality heatmap (ivf_list)."""
    plt = _require_matplotlib()
    import numpy as np

    base = enrich_summary_rows(summary_rows)
    ivf = _ivf_rows(base)
    if not ivf:
        raise ValueError("no ivf_list rows for heatmap")

    locs = sorted({r["locality_f"] for r in ivf})
    vrs = sorted({r["visible_ratio_f"] for r in ivf})
    grid = np.full((len(locs), len(vrs)), float("nan"))
    for r in ivf:
        i = locs.index(r["locality_f"])
        j = vrs.index(r["visible_ratio_f"])
        grid[i, j] = r["plan_vs_masked_cost_f"]

    fig, ax = plt.subplots(figsize=(7.0, 4.5))
    im = ax.imshow(grid, aspect="auto", origin="lower", cmap="viridis_r", vmin=0.0, vmax=1.05)
    ax.set_xticks(range(len(vrs)))
    ax.set_xticklabels([f"{v:.2f}" for v in vrs], rotation=45, ha="right")
    ax.set_yticks(range(len(locs)))
    ax.set_yticklabels([f"{v:.2f}" for v in locs])
    ax.set_xlabel(r"Configured visible ratio ($N_{\mathrm{vis}}/N_{\mathrm{valid}}$)")
    ax.set_ylabel("Access locality (cost model)")
    ax.set_title("Proof-planning cost heatmap (IVF-list, cost model)")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Median planned / masked cost (cost model)")
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def _mean_breakdown(metrics_rows: list[dict]) -> dict[str, float]:
    keys = (
        "estimated_region_cost_f",
        "estimated_visibility_cost_f",
        "estimated_distance_cost_f",
        "estimated_mask_topk_cost_f",
    )
    n = len(metrics_rows)
    return {k: sum(r[k] for r in metrics_rows) / n for k in keys}


def plot_cost_breakdown(metrics_rows: list[dict], output: Path) -> None:
    """Main Fig 2: stacked planned cost components for representative scenarios."""
    plt = _require_matplotlib()
    parsed = enrich_metrics_rows(metrics_rows)
    ivf = _ivf_rows(parsed)

    scenarios = [
        ("Low loc, vr=0.25", 0.0, 0.25),
        ("High loc, vr=0.25", 1.0, 0.25),
        ("High loc, vr=0.5", 1.0, 0.5),
        ("Low loc, vr=0.5", 0.0, 0.5),
    ]
    labels: list[str] = []
    region: list[float] = []
    vis: list[float] = []
    dist: list[float] = []
    mask_topk: list[float] = []

    for label, loc, vr in scenarios:
        subset = [
            r
            for r in ivf
            if _near(r["locality_f"], loc) and _near(r["visible_ratio_f"], vr)
        ]
        if not subset:
            continue
        avg = _mean_breakdown(subset)
        labels.append(label)
        region.append(avg["estimated_region_cost_f"])
        vis.append(avg["estimated_visibility_cost_f"])
        dist.append(avg["estimated_distance_cost_f"])
        mask_topk.append(avg["estimated_mask_topk_cost_f"])

    if not labels:
        raise ValueError("no rows for cost breakdown scenarios")

    fig, ax = plt.subplots(figsize=(7.0, 4.5))
    x = range(len(labels))
    ax.bar(x, region, label="Region certificates", color="#1f77b4")
    bottom = region
    ax.bar(x, vis, bottom=bottom, label="Visibility eval", color="#ff7f0e")
    bottom = [b + v for b, v in zip(bottom, vis)]
    ax.bar(x, dist, bottom=bottom, label="Distance / ADC", color="#2ca02c")
    bottom = [b + d for b, d in zip(bottom, dist)]
    ax.bar(x, mask_topk, bottom=bottom, label="Mask + top-k", color="#d62728")

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylabel("Planned work units (cost model)")
    ax.set_title("Planned cost breakdown by access locality (cost model)")
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_degradation_curve(summary_rows: list[dict], output: Path) -> None:
    """Main Fig 3: impure ratio vs cost — planner degrades under mixing."""
    plt = _require_matplotlib()
    parsed = enrich_summary_rows(summary_rows)

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    for loc in (0.0, 0.25, 0.5, 0.75, 1.0):
        subset = [r for r in parsed if _near(r["locality_f"], loc)]
        if not subset:
            continue
        style = LOCALITY_STYLES.get(loc, LOCALITY_STYLES[1.0])
        ax.scatter(
            [r["impure_valid_ratio_f"] for r in subset],
            [r["plan_vs_masked_cost_f"] for r in subset],
            c=style["color"],
            marker=style["marker"],
            label=f"locality={loc:.2f}",
            alpha=0.75,
            s=36,
            edgecolors="white",
            linewidths=0.3,
        )

    ax.set_xlabel(
        r"Median impure valid ratio ($N_{\mathrm{impure}}/N_{\mathrm{valid}}$)"
    )
    ax.set_ylabel("Median planned / masked cost (cost model)")
    ax.set_title("Impure fallback degrades planner to baseline (cost model)")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle=":")
    ax.set_xlim(-0.02, 1.02)
    ax.legend(loc="best", fontsize=8, ncol=2)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_granularity_sensitivity(summary_rows: list[dict], output: Path) -> None:
    """Main Fig 4: fixed_block block size vs cost by locality."""
    plt = _require_matplotlib()
    parsed = enrich_summary_rows(summary_rows)
    target_vr = 0.25
    target_locs = (0.0, 0.5, 1.0)

    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    for loc in target_locs:
        subset = [
            r
            for r in parsed
            if r["grouping_strategy"] == "fixed_block"
            and _near(r["locality_f"], loc)
            and _near(r["visible_ratio_f"], target_vr)
            and r["block_size_i"] > 0
        ]
        if not subset:
            continue
        subset = sorted(subset, key=lambda r: r["block_size_i"])
        style = LOCALITY_STYLES[loc]
        ax.plot(
            [r["block_size_i"] for r in subset],
            [r["plan_vs_masked_cost_f"] for r in subset],
            label=f"locality={loc:.1f}",
            color=style["color"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            linewidth=1.8,
            markersize=6,
        )

    ax.set_xlabel("Block size (fixed_block grouping)")
    ax.set_ylabel("Median planned / masked cost (cost model)")
    ax.set_title(
        rf"Region granularity sensitivity ($N_{{\mathrm{{vis}}}}/N_{{\mathrm{{valid}}}}\approx{target_vr:.2f}$, cost model)"
    )
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle=":")
    ax.legend(loc="best", fontsize=9)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_locality_vs_cost(rows: list[dict], output: Path) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    base = _ivf_rows(rows)
    target_vrs = (0.1, 0.25, 0.5, 0.75)

    for vr in target_vrs:
        subset = [r for r in base if _near(r["visible_ratio_f"], vr)]
        if not subset:
            continue
        subset = sorted(subset, key=lambda r: r["locality_f"])
        color = VIS_RATIO_COLORS.get(vr, "#333333")
        ax.plot(
            [r["locality_f"] for r in subset],
            [r["plan_vs_masked_cost_f"] for r in subset],
            label=rf"$N_{{\mathrm{{vis}}}}/N_{{\mathrm{{valid}}}}\approx{vr:.2f}$",
            color=color,
            marker="o",
            linewidth=1.8,
            markersize=5,
        )

    ax.set_xlabel("Access locality (cost model)")
    ax.set_ylabel("Planned / masked cost (cost model)")
    ax.set_title("Proof-planning cost vs access locality (IVF-list grouping)")
    ax.set_xlim(-0.02, 1.02)
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle=":")
    ax.legend(loc="best", fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_visibility_vs_cost_by_locality(rows: list[dict], output: Path) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    base = _ivf_rows(rows)
    target_locs = (0.0, 0.5, 1.0)

    for loc in target_locs:
        subset = [r for r in base if _near(r["locality_f"], loc)]
        if not subset:
            continue
        subset = sorted(subset, key=lambda r: r["visible_ratio_f"])
        style = LOCALITY_STYLES[loc]
        ax.plot(
            [r["visible_ratio_f"] for r in subset],
            [r["plan_vs_masked_cost_f"] for r in subset],
            label=f"locality={loc:.1f}",
            color=style["color"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            linewidth=1.8,
            markersize=5,
        )

    ax.set_xlabel(r"$N_{\mathrm{vis}} / N_{\mathrm{valid}}$ (visible ratio)")
    ax.set_ylabel("Planned / masked cost (cost model)")
    ax.set_title("Visibility–locality interaction (IVF-list grouping)")
    ax.set_xlim(-0.02, 1.02)
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle=":")
    ax.legend(loc="best", fontsize=9)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_impure_ratio_vs_cost(rows: list[dict], output: Path) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(6.5, 4.0))

    for loc in (0.0, 0.5, 1.0):
        subset = [r for r in rows if _near(r["locality_f"], loc)]
        if not subset:
            continue
        style = LOCALITY_STYLES[loc]
        ax.scatter(
            [r["impure_valid_ratio_f"] for r in subset],
            [r["plan_vs_masked_cost_f"] for r in subset],
            c=style["color"],
            marker=style["marker"],
            label=f"locality={loc:.1f}",
            alpha=0.65,
            s=24,
            edgecolors="white",
            linewidths=0.2,
        )

    ax.set_xlabel(
        r"Impure valid candidate ratio ($N_{\mathrm{impure}}/N_{\mathrm{valid}}$)"
    )
    ax.set_ylabel("Planned / masked cost (cost model)")
    ax.set_title("Impure fallback drives cost increase (cost model)")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle=":")
    ax.set_xlim(-0.02, 1.02)
    ax.legend(loc="best", fontsize=9)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_region_granularity_tradeoff(rows: list[dict], output: Path) -> None:
    plt = _require_matplotlib()
    fig, axes = plt.subplots(1, 2, figsize=(10.0, 4.0))
    target_locs = (0.0, 0.5, 1.0)

    for loc in target_locs:
        subset = [
            r
            for r in rows
            if r["grouping_strategy"] == "fixed_block"
            and _near(r["locality_f"], loc)
            and _near(r["visible_ratio_f"], 0.5)
            and r["block_size_i"] > 0
        ]
        if not subset:
            continue
        subset = sorted(subset, key=lambda r: r["block_size_i"])
        style = LOCALITY_STYLES[loc]
        label = f"locality={loc:.1f}"
        axes[0].plot(
            [r["block_size_i"] for r in subset],
            [r["region_count_f"] for r in subset],
            label=label,
            color=style["color"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            linewidth=1.8,
        )
        axes[1].plot(
            [r["block_size_i"] for r in subset],
            [r["plan_vs_masked_cost_f"] for r in subset],
            label=label,
            color=style["color"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            linewidth=1.8,
        )

    axes[0].set_xlabel("Block size (fixed_block grouping)")
    axes[0].set_ylabel("Region count (cost model)")
    axes[0].set_title(r"$N_{\mathrm{vis}}/N_{\mathrm{valid}} \approx 0.5$")
    axes[0].grid(True, alpha=0.3)
    axes[0].legend(fontsize=8)

    axes[1].set_xlabel("Block size (fixed_block grouping)")
    axes[1].set_ylabel("Planned / masked cost (cost model)")
    axes[1].axhline(1.0, color="gray", linewidth=0.8, linestyle=":")
    axes[1].grid(True, alpha=0.3)
    axes[1].legend(fontsize=8)

    fig.suptitle("Region granularity trade-off (cost model)", fontsize=10)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_pa_appendix(rows: list[dict], output: Path) -> None:
    plt = _require_matplotlib()
    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    filtered = [r for r in rows if r["visible_ratio_f"] >= 0.1]
    base = _ivf_rows(filtered)

    for loc in (0.0, 0.5, 1.0):
        subset = [r for r in base if _near(r["locality_f"], loc)]
        if not subset:
            continue
        subset = sorted(subset, key=lambda r: r["visible_ratio_f"])
        style = LOCALITY_STYLES[loc]
        ax.plot(
            [r["visible_ratio_f"] for r in subset],
            [r["PA_plan_f"] for r in subset],
            label=f"locality={loc:.1f}",
            color=style["color"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            linewidth=1.8,
        )

    ax.set_xlabel(r"$N_{\mathrm{vis}}/N_{\mathrm{valid}}$ ($\geq 0.1$; cost-model PA)")
    ax.set_ylabel(r"$PA_{\mathrm{plan}}$ (cost-model PA, not ZK gates)")
    ax.set_title("Appendix: cost-model proof amplification")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle=":")
    ax.legend(loc="best", fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, format="pdf")
    plt.close(fig)


def plot_beta_all(
    summary_rows: list[dict],
    metrics_rows: list[dict],
    output_dir: Path,
    *,
    include_pa: bool,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = [output_dir / name for name in BETA_MAIN_PLOT_FILES]
    plot_heatmap_cost(summary_rows, outputs[0])
    plot_cost_breakdown(metrics_rows, outputs[1])
    plot_degradation_curve(summary_rows, outputs[2])
    plot_granularity_sensitivity(summary_rows, outputs[3])
    if include_pa:
        pa_path = output_dir / APPENDIX_PLOT_FILES[0]
        plot_pa_appendix(enrich_metrics_rows(metrics_rows), pa_path)
        outputs.append(pa_path)
    return outputs


def plot_locality_all(rows: list[dict], output_dir: Path, *, include_pa: bool) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    parsed = enrich_metrics_rows(rows)
    outputs = [output_dir / name for name in LOCALITY_MAIN_PLOT_FILES]
    plot_locality_vs_cost(parsed, outputs[0])
    plot_visibility_vs_cost_by_locality(parsed, outputs[1])
    plot_impure_ratio_vs_cost(parsed, outputs[2])
    plot_region_granularity_tradeoff(parsed, outputs[3])
    if include_pa:
        pa_path = output_dir / APPENDIX_PLOT_FILES[0]
        plot_pa_appendix(parsed, pa_path)
        outputs.append(pa_path)
    return outputs


def plot_all(
    input_path: Path,
    output_dir: Path,
    *,
    include_pa_appendix: bool = True,
) -> list[Path]:
    summary_path = resolve_summary_path(input_path)
    metrics_path = resolve_metrics_path(input_path)

    summary_rows = load_csv(summary_path) if summary_path.is_file() else []
    metrics_rows = load_csv(metrics_path) if metrics_path.is_file() else summary_rows

    if not summary_rows and not metrics_rows:
        raise ValueError("empty input CSV")

    model = workload_model(summary_rows or metrics_rows)
    if model == "beta_locality":
        if not summary_rows:
            summary_rows = metrics_rows
        return plot_beta_all(
            summary_rows,
            metrics_rows,
            output_dir,
            include_pa=include_pa_appendix,
        )
    if model == "locality_sweep":
        return plot_locality_all(metrics_rows, output_dir, include_pa=include_pa_appendix)
    raise ValueError(
        f"unsupported workload_model={model!r}; use beta_locality or locality_sweep"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot proof-planning cost-model figures (Phase 6B-2.8)."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/proof_planning_beta_summary.csv"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/figures"),
    )
    parser.add_argument(
        "--no-pa-appendix",
        action="store_true",
        help="Skip optional PA appendix figure.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    outputs = plot_all(
        args.input,
        args.output_dir,
        include_pa_appendix=not args.no_pa_appendix,
    )
    for path in outputs:
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
