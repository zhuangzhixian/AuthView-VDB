#!/usr/bin/env python3
"""Phase 9C: Build paper-ready evaluation inventory from artifacts (no heavy computation)."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

FIGURE_REGISTRY: dict[str, dict[str, str]] = {
    "main_public_utility_recall.pdf": {
        "phase": "8C",
        "title": "Public IVF-PQ utility (SIFT1M/GIST1M)",
        "purpose": "RQ1 unrestricted baseline recall@k on full public benchmarks",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 2",
        "readiness": "ready",
        "caveat": "Unrestricted utility only; not authorized-view",
        "action_needed": "Caption: full-base SIFT1M 10k queries, GIST1M 1k queries",
    },
    "main_auth_overlay_utility_gap.pdf": {
        "phase": "9A",
        "title": "Authorization utility gap vs selectivity",
        "purpose": "Post-filter vs candidate-level authorized recall gap",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 1, Claim 2",
        "readiness": "ready",
        "caveat": "reference_scope=candidate_level (pred depth 100)",
        "action_needed": "State candidate-level scope in caption",
    },
    "main_auth_overlay_underfill.pdf": {
        "phase": "9A",
        "title": "Post-filter underfill rate vs selectivity",
        "purpose": "Quantify post-filter semantic failure (underfill)",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 1",
        "readiness": "ready",
        "caveat": "candidate_level trace overlay",
        "action_needed": "Pair with utility gap figure",
    },
    "main_authorized_reference_calibration.pdf": {
        "phase": "9B",
        "title": "Candidate vs full authorized reference calibration gap",
        "purpose": "Bound Phase 9A approximation vs full-base exact L2",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 3",
        "readiness": "ready",
        "caveat": "Query calibration subset (~572 queries), not full trace",
        "action_needed": "Label as query calibration; full_base=true on base",
    },
    "main_proof_overhead_gates.pdf": {
        "phase": "7A",
        "title": "Proof overhead — gates",
        "purpose": "RQ2 ZK gate count by auth path vs baseline",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Synthetic micro-workloads; measured ZK",
        "action_needed": "Label V3DB-shaped content-only baseline",
    },
    "main_proof_overhead_time.pdf": {
        "phase": "7A",
        "title": "Proof overhead — prove/verify time",
        "purpose": "RQ2 prove and verify latency",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Synthetic workloads",
        "action_needed": "Same as gates figure",
    },
    "main_proof_overhead_size.pdf": {
        "phase": "7A",
        "title": "Proof overhead — proof size",
        "purpose": "RQ2 proof size by path",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Synthetic workloads",
        "action_needed": "Optional main if space",
    },
    "main_acl_class_compression.pdf": {
        "phase": "7B",
        "title": "ACL-class compression vs N_acl",
        "purpose": "RQ3 gate reduction when N_acl << N_sel",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 4",
        "readiness": "partial",
        "caveat": "repeat=1 in some runs; verify repeat=3 CSV",
        "action_needed": "Confirm repeat=3 summary in caption",
    },
    "main_acl_class_prove_time.pdf": {
        "phase": "7B",
        "title": "ACL-class prove time",
        "purpose": "RQ3 time benefit of ACL-class path",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 4",
        "readiness": "partial",
        "caveat": "Paired with compression figure",
        "action_needed": "Same repeat caveat",
    },
    "main_proof_scaling_gates.pdf": {
        "phase": "7C",
        "title": "Proof scaling — gates vs N_sel",
        "purpose": "RQ6 configuration trade-offs",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Synthetic grid",
        "action_needed": "Cross-ref Table 2",
    },
    "main_proof_scaling_time.pdf": {
        "phase": "7C",
        "title": "Proof scaling — time vs N_sel",
        "purpose": "RQ6 scaling latency",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Synthetic grid",
        "action_needed": "Optional main",
    },
    "main_merged_k_knob.pdf": {
        "phase": "6",
        "title": "Merged-k design knob (SA/PA tradeoff)",
        "purpose": "RQ4 proof-planning cost model",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Plaintext cost model, NOT measured ZK gates",
        "action_needed": "Mandatory cost-model disclaimer in caption",
    },
    "main_cost_breakdown_clean.pdf": {
        "phase": "6",
        "title": "Proof-planning cost breakdown",
        "purpose": "RQ4 component-level savings",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Cost model only",
        "action_needed": "Cost-model disclaimer",
    },
    "main_impure_fallback_clean.pdf": {
        "phase": "6",
        "title": "Impure fallback drives PA_plan",
        "purpose": "RQ4 purity region analysis",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Cost model only",
        "action_needed": "Appendix subfigure",
    },
    "main_sa_pa_frontier_clean.pdf": {
        "phase": "6",
        "title": "SA/PA planning frontier",
        "purpose": "Design-space overview",
        "recommended_placement": "internal_only",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Oracle off-scale; exploratory",
        "action_needed": "Do not use in main unless revised",
    },
}

TABLE_REGISTRY: dict[str, dict[str, str]] = {
    "table_public_utility_summary.tex": {
        "phase": "8C",
        "title": "Public utility baseline summary",
        "purpose": "Full-base SIFT1M/GIST1M IVF-PQ recall and QPS",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 2",
        "readiness": "ready",
        "caveat": "Unrestricted baseline; V3DB-aligned configs",
        "action_needed": "Table 1 / RQ1 setup",
    },
    "table_auth_overlay_summary.tex": {
        "phase": "9A",
        "title": "Authorization overlay summary",
        "purpose": "Post-filter vs candidate-level at R@10",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 1, Claim 2",
        "readiness": "ready",
        "caveat": "candidate_level reference_scope",
        "action_needed": "Caption scope disclaimer",
    },
    "table_authorized_reference_calibration.tex": {
        "phase": "9B",
        "title": "Full authorized reference calibration",
        "purpose": "Post/candidate/full recall comparison",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 3",
        "readiness": "ready",
        "caveat": "Query-calibrated subset; full_base on corpus",
        "action_needed": "Distinguish query calibration vs base truncation",
    },
    "table_proof_overhead.tex": {
        "phase": "7A",
        "title": "Proof overhead by path",
        "purpose": "RQ2 median gates/time/size",
        "recommended_placement": "main_paper",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Synthetic workloads",
        "action_needed": "Table 2 in blueprint",
    },
    "table_acl_class_summary.tex": {
        "phase": "7B",
        "title": "ACL-class path summary",
        "purpose": "RQ3 N_acl sweep",
        "recommended_placement": "main_paper",
        "readiness": "partial",
        "caveat": "Check repeat count",
        "action_needed": "Table 4 ablation",
    },
    "table_proof_scaling_summary.tex": {
        "phase": "7C",
        "title": "Proof scaling summary",
        "purpose": "RQ6 N_sel scaling",
        "recommended_placement": "appendix",
        "supported_claim": "Claim 4",
        "readiness": "ready",
        "caveat": "Synthetic grid",
        "action_needed": "Appendix scaling",
    },
}

RESULT_REGISTRY: dict[str, dict[str, str]] = {
    "sift_gist_utility_summary.csv": {
        "phase": "8C",
        "module": "public_utility_baseline",
        "reference_scope": "unrestricted_baseline",
        "full_base_expected": "true",
        "description": "Phase 8C full-base public IVF-PQ utility",
    },
    "public_trace_auth_summary.csv": {
        "phase": "9A",
        "module": "authorization_overlay",
        "reference_scope": "candidate_level",
        "full_base_expected": "trace_on_full_base",
        "description": "Phase 9A auth overlay on Phase 8C traces",
    },
    "full_authorized_reference_summary.csv": {
        "phase": "9B",
        "module": "authorized_reference_calibration",
        "reference_scope": "full_base_calibration",
        "full_base_expected": "true",
        "description": "Phase 9B full-base exact authorized top-k calibration",
    },
}

FIGURE_FIELDS = (
    "artifact_path",
    "artifact_type",
    "phase",
    "title",
    "purpose",
    "recommended_placement",
    "supported_claim",
    "readiness",
    "caveat",
    "action_needed",
    "exists",
    "size_bytes",
)

RESULT_FIELDS = (
    "artifact_path",
    "phase",
    "module",
    "row_count",
    "columns",
    "reference_scope",
    "full_base",
    "num_base",
    "num_queries",
    "datasets",
    "key_metrics_summary",
    "description",
    "exists",
)


def load_csv_rows(path: Path) -> tuple[list[dict], list[str]]:
    if not path.is_file():
        return [], []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        return list(reader), fieldnames


def summarize_public_utility(rows: list[dict]) -> str:
    if not rows:
        return ""
    parts = []
    for r in rows:
        parts.append(
            f"{r.get('dataset')}/{r.get('config')}: R@10={float(r.get('recall_at_10', 0)):.3f}"
        )
    return "; ".join(parts)


def summarize_auth_overlay(rows: list[dict]) -> str:
    k10 = [r for r in rows if str(r.get("k")) == "10" and float(r.get("selectivity", 0)) == 0.1]
    if not k10:
        return ""
    gaps = [float(r.get("utility_gap", 0)) for r in k10]
    under = [float(r.get("underfill_rate", 0)) for r in k10]
    return f"k=10 sel=0.1: utility_gap mean={sum(gaps)/len(gaps):.3f}; underfill mean={sum(under)/len(under):.3f}"


def summarize_auth_calibration(rows: list[dict]) -> str:
    k10 = [r for r in rows if str(r.get("k")) == "10"]
    if not k10:
        return ""
    cand_gap = [float(r.get("candidate_full_recall_gap", 0)) for r in k10]
    post_gap = [float(r.get("post_full_recall_gap", 0)) for r in k10]
    return (
        f"k=10: candidate_full_gap mean={sum(cand_gap)/len(cand_gap):.3f}; "
        f"post_full_gap mean={sum(post_gap)/len(post_gap):.3f}"
    )


def infer_full_base(rows: list[dict], fieldnames: list[str]) -> str:
    if "full_base" in fieldnames and rows:
        vals = {str(r.get("full_base", "")).lower() for r in rows}
        if vals == {"true"}:
            return "true"
        if "true" in vals:
            return "mixed"
        return vals.pop() if len(vals) == 1 else "unknown"
    if "num_base" in fieldnames and rows:
        bases = {r.get("num_base") for r in rows}
        if bases == {"1000000"}:
            return "true"
    return "n/a"


def infer_reference_scope(rows: list[dict], fieldnames: list[str], default: str) -> str:
    if "reference_scope" in fieldnames and rows:
        vals = sorted({r.get("reference_scope", "") for r in rows if r.get("reference_scope")})
        return "|".join(vals) if vals else default
    return default


def build_figure_inventory(figures_dir: Path) -> list[dict]:
    rows: list[dict] = []
    pdfs = sorted(figures_dir.glob("*.pdf"))
    seen: set[str] = set()
    for path in pdfs:
        name = path.name
        seen.add(name)
        meta = FIGURE_REGISTRY.get(name, {})
        rows.append(
            {
                "artifact_path": str(path),
                "artifact_type": "figure",
                "phase": meta.get("phase", "unknown"),
                "title": meta.get("title", name),
                "purpose": meta.get("purpose", ""),
                "recommended_placement": meta.get("recommended_placement", "internal_only"),
                "supported_claim": meta.get("supported_claim", ""),
                "readiness": meta.get("readiness", "unknown"),
                "caveat": meta.get("caveat", ""),
                "action_needed": meta.get("action_needed", "Add registry entry"),
                "exists": True,
                "size_bytes": path.stat().st_size,
            }
        )
    for name, meta in sorted(FIGURE_REGISTRY.items()):
        if name in seen:
            continue
        rows.append(
            {
                "artifact_path": str(figures_dir / name),
                "artifact_type": "figure",
                "phase": meta.get("phase", ""),
                "title": meta.get("title", name),
                "purpose": meta.get("purpose", ""),
                "recommended_placement": meta.get("recommended_placement", "internal_only"),
                "supported_claim": meta.get("supported_claim", ""),
                "readiness": "missing",
                "caveat": meta.get("caveat", ""),
                "action_needed": meta.get("action_needed", "Generate figure"),
                "exists": False,
                "size_bytes": 0,
            }
        )
    return rows


def build_table_inventory(tables_dir: Path) -> list[dict]:
    rows: list[dict] = []
    tex_files = sorted(tables_dir.glob("*.tex"))
    seen: set[str] = set()
    for path in tex_files:
        name = path.name
        seen.add(name)
        meta = TABLE_REGISTRY.get(name, {})
        rows.append(
            {
                "artifact_path": str(path),
                "artifact_type": "table",
                "phase": meta.get("phase", "unknown"),
                "title": meta.get("title", name),
                "purpose": meta.get("purpose", ""),
                "recommended_placement": meta.get("recommended_placement", "internal_only"),
                "supported_claim": meta.get("supported_claim", ""),
                "readiness": meta.get("readiness", "unknown"),
                "caveat": meta.get("caveat", ""),
                "action_needed": meta.get("action_needed", "Add registry entry"),
                "exists": True,
                "size_bytes": path.stat().st_size,
            }
        )
    for name, meta in sorted(TABLE_REGISTRY.items()):
        if name in seen:
            continue
        rows.append(
            {
                "artifact_path": str(tables_dir / name),
                "artifact_type": "table",
                "phase": meta.get("phase", ""),
                "title": meta.get("title", name),
                "purpose": meta.get("purpose", ""),
                "recommended_placement": meta.get("recommended_placement", "internal_only"),
                "supported_claim": meta.get("supported_claim", ""),
                "readiness": "missing",
                "caveat": meta.get("caveat", ""),
                "action_needed": meta.get("action_needed", "Generate table"),
                "exists": False,
                "size_bytes": 0,
            }
        )
    return rows


def build_result_inventory(
    *,
    public_utility: Path,
    auth_overlay: Path,
    auth_calibration: Path,
) -> list[dict]:
    sources = [
        (public_utility, "public_utility/sift_gist_utility_summary.csv"),
        (auth_overlay, "auth_overlay/public_trace_auth_summary.csv"),
        (auth_calibration, "auth_calibration/full_authorized_reference_summary.csv"),
    ]
    rows: list[dict] = []
    for path, key in sources:
        name = path.name
        meta = RESULT_REGISTRY.get(name, {})
        csv_rows, fieldnames = load_csv_rows(path)
        exists = path.is_file()
        summary_fn = {
            "sift_gist_utility_summary.csv": summarize_public_utility,
            "public_trace_auth_summary.csv": summarize_auth_overlay,
            "full_authorized_reference_summary.csv": summarize_auth_calibration,
        }.get(name, lambda _: "")

        num_base = ""
        num_queries = ""
        datasets = ""
        if csv_rows:
            if "num_base" in fieldnames:
                num_base = str(sorted({r.get("num_base", "") for r in csv_rows}))
            if "num_queries" in fieldnames:
                num_queries = str(sorted({r.get("num_queries", "") for r in csv_rows}))
            if "dataset" in fieldnames:
                datasets = "|".join(sorted({r.get("dataset", "") for r in csv_rows}))

        rows.append(
            {
                "artifact_path": str(path),
                "phase": meta.get("phase", ""),
                "module": meta.get("module", ""),
                "row_count": len(csv_rows),
                "columns": "|".join(fieldnames),
                "reference_scope": infer_reference_scope(
                    csv_rows, fieldnames, meta.get("reference_scope", "")
                ),
                "full_base": infer_full_base(csv_rows, fieldnames),
                "num_base": num_base,
                "num_queries": num_queries,
                "datasets": datasets,
                "key_metrics_summary": summary_fn(csv_rows),
                "description": meta.get("description", ""),
                "exists": exists,
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict], fieldnames: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build evaluation inventory CSVs.")
    parser.add_argument("--figures-dir", type=Path, default=Path("artifacts/figures"))
    parser.add_argument("--tables-dir", type=Path, default=Path("artifacts/tables"))
    parser.add_argument(
        "--public-utility",
        type=Path,
        default=Path("artifacts/public_utility/sift_gist_utility_summary.csv"),
    )
    parser.add_argument(
        "--auth-overlay",
        type=Path,
        default=Path("artifacts/auth_overlay/public_trace_auth_summary.csv"),
    )
    parser.add_argument(
        "--auth-calibration",
        type=Path,
        default=Path("artifacts/auth_calibration/full_authorized_reference_summary.csv"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/evaluation_inventory"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[1]

    def resolve(p: Path) -> Path:
        return p if p.is_absolute() else root / p

    figures_dir = resolve(args.figures_dir)
    tables_dir = resolve(args.tables_dir)
    output_dir = resolve(args.output_dir)

    figure_rows = build_figure_inventory(figures_dir)
    table_rows = build_table_inventory(tables_dir)
    combined = figure_rows + table_rows

    result_rows = build_result_inventory(
        public_utility=resolve(args.public_utility),
        auth_overlay=resolve(args.auth_overlay),
        auth_calibration=resolve(args.auth_calibration),
    )

    fig_table_path = output_dir / "figure_table_inventory.csv"
    result_path = output_dir / "result_summary_inventory.csv"
    write_csv(fig_table_path, combined, FIGURE_FIELDS)
    write_csv(result_path, result_rows, RESULT_FIELDS)

    print(f"Wrote {fig_table_path} ({len(combined)} rows)")
    print(f"Wrote {result_path} ({len(result_rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
