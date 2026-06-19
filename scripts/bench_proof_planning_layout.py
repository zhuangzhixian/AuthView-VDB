#!/usr/bin/env python3
"""
Phase 6B-2.10: Access-signature layout proof-planning sweep (repaired model).

Plaintext cost-model only — not ZK gates. No figure generation in this phase.
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

from auth_reference.attacks import DEFAULT_CHECKPOINT
from auth_reference.layout_planning_reference import (
    AccessSignatureConfig,
    PhysicalLayout,
    build_access_signature_workload,
    evaluate_layout,
)
from auth_reference.proof_planning_reference import DEFAULT_COST_PARAMS

CSV_FIELDS = [
    "case_id",
    "workload_model",
    "physical_layout",
    "num_objects",
    "num_roles",
    "num_signatures",
    "query_role",
    "merged_k",
    "seed",
    "n_lists",
    "slot_per_list",
    "N_slots",
    "N_valid",
    "N_vis",
    "N_invis",
    "effective_selectivity",
    "total_memberships",
    "stored_entries_norm",
    "region_count",
    "pure_visible_regions",
    "pure_invisible_regions",
    "impure_regions",
    "pure_visible_region_ratio",
    "pure_invisible_region_ratio",
    "impure_region_ratio",
    "pure_visible_valid_ratio",
    "pure_invisible_valid_ratio",
    "impure_valid_ratio",
    "N_dist_masked",
    "N_dist_plan",
    "N_dist_ideal",
    "dist_reduction_plan",
    "dist_reduction_ideal",
    "estimated_cost_masked",
    "estimated_cost_plan",
    "estimated_cost_ideal",
    "estimated_region_cost",
    "estimated_visibility_cost",
    "estimated_distance_cost",
    "estimated_mask_topk_cost",
    "SA_commit",
    "PA_plan",
    "PA_ideal",
    "plan_vs_masked_cost",
    "ideal_vs_masked_cost",
    "planned_equals_masked",
    "validation_passed",
]

BASE_LAYOUTS: tuple[PhysicalLayout, ...] = (
    "global",
    "acl_signature",
    "oracle_authorized_view",
)


def _parse_int_list(value: str) -> list[int]:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected at least one integer")
    return [int(p) for p in parts]


def _safe_ratio(num: float, denom: float) -> float:
    if denom == 0:
        return 0.0
    return num / denom


def evaluate_case(
    *,
    case_id: str,
    physical_layout: PhysicalLayout,
    workload_config: AccessSignatureConfig,
    query_role: int,
    merged_k: int,
    n_lists: int,
    slot_per_list: int,
    top_k: int,
    cost_params: dict[str, int],
) -> dict[str, object]:
    workload = build_access_signature_workload(
        workload_config,
        n_lists=n_lists,
        slot_per_list=slot_per_list,
    )
    mk = merged_k if physical_layout == "merged_k" else 1
    result = evaluate_layout(
        physical_layout,
        workload,
        query_role,
        DEFAULT_CHECKPOINT,
        merged_k=mk,
        top_k=top_k,
        cost_params=cost_params,
    )
    plan = result.plan
    dist_red_ideal = _safe_ratio(
        float(plan.N_dist_masked - plan.N_dist_ideal), float(plan.N_dist_masked)
    )

    return {
        "case_id": case_id,
        "workload_model": "access_signature_layout",
        "physical_layout": physical_layout,
        "num_objects": workload_config.num_objects,
        "num_roles": workload_config.num_roles,
        "num_signatures": workload_config.num_signatures,
        "query_role": query_role,
        "merged_k": merged_k if physical_layout == "merged_k" else 0,
        "seed": workload_config.seed,
        "n_lists": workload.n_lists,
        "slot_per_list": workload.slot_per_list,
        "N_slots": plan.N_slots,
        "N_valid": plan.N_valid,
        "N_vis": plan.N_vis,
        "N_invis": plan.N_invis,
        "effective_selectivity": f"{result.effective_selectivity:.6f}",
        "total_memberships": result.total_memberships,
        "stored_entries_norm": f"{result.stored_entries_norm:.6f}",
        "region_count": result.num_regions,
        "pure_visible_regions": plan.N_pure_visible_regions,
        "pure_invisible_regions": plan.N_pure_invisible_regions,
        "impure_regions": plan.N_impure_regions,
        "pure_visible_region_ratio": f"{result.pure_visible_region_ratio:.6f}",
        "pure_invisible_region_ratio": f"{result.pure_invisible_region_ratio:.6f}",
        "impure_region_ratio": f"{result.impure_region_ratio:.6f}",
        "pure_visible_valid_ratio": f"{result.pure_visible_valid_ratio:.6f}",
        "pure_invisible_valid_ratio": f"{result.pure_invisible_valid_ratio:.6f}",
        "impure_valid_ratio": f"{result.impure_valid_ratio:.6f}",
        "N_dist_masked": plan.N_dist_masked,
        "N_dist_plan": plan.N_dist_plan,
        "N_dist_ideal": plan.N_dist_ideal,
        "dist_reduction_plan": f"{result.dist_reduction_plan:.6f}",
        "dist_reduction_ideal": f"{dist_red_ideal:.6f}",
        "estimated_cost_masked": plan.estimated_cost_masked,
        "estimated_cost_plan": plan.estimated_cost_plan,
        "estimated_cost_ideal": plan.estimated_cost_ideal_visible_compaction,
        "estimated_region_cost": result.estimated_region_cost,
        "estimated_visibility_cost": result.estimated_visibility_cost,
        "estimated_distance_cost": result.estimated_distance_cost,
        "estimated_mask_topk_cost": result.estimated_mask_topk_cost,
        "SA_commit": f"{result.SA_commit:.6f}",
        "PA_plan": f"{result.PA_plan:.6f}",
        "PA_ideal": f"{result.PA_ideal:.6f}",
        "plan_vs_masked_cost": f"{result.plan_vs_masked_cost:.6f}",
        "ideal_vs_masked_cost": f"{result.ideal_vs_masked_cost:.6f}",
        "planned_equals_masked": str(result.planned_equals_masked).lower(),
        "validation_passed": str(result.validation_passed).lower(),
    }


def _grid_dims(num_objects: int) -> tuple[int, int]:
    n_lists = max(1, int(math.sqrt(num_objects)))
    while n_lists * ((num_objects + n_lists - 1) // n_lists) < num_objects:
        n_lists += 1
    slot_per_list = (num_objects + n_lists - 1) // n_lists
    return n_lists, slot_per_list


def run_layout_benchmark(args: argparse.Namespace) -> list[dict[str, object]]:
    cost_params = dict(DEFAULT_COST_PARAMS)
    rows: list[dict[str, object]] = []
    n_lists, slot_per_list = _grid_dims(args.num_objects)

    layout_configs: list[tuple[PhysicalLayout, int]] = []
    for layout in args.layouts:
        if layout == "merged_k":
            continue
        layout_configs.append((layout, 0))
    for mk in args.merged_k_list:
        layout_configs.append(("merged_k", mk))

    query_roles = (
        list(range(args.num_roles))
        if args.query_roles == "all"
        else _parse_int_list(args.query_roles)
    )

    for layout, mk in layout_configs:
        for query_role in query_roles:
            for seed in args.seeds:
                config = AccessSignatureConfig(
                    num_objects=args.num_objects,
                    num_roles=args.num_roles,
                    num_signatures=args.num_signatures,
                    seed=seed,
                )
                case_id = (
                    f"{layout}_r{query_role}_mk{mk}_s{seed}"
                    f"_o{args.num_objects}_sig{args.num_signatures}"
                )
                row = evaluate_case(
                    case_id=case_id,
                    physical_layout=layout,
                    workload_config=config,
                    query_role=query_role,
                    merged_k=mk if layout == "merged_k" else 0,
                    n_lists=n_lists,
                    slot_per_list=slot_per_list,
                    top_k=args.top_k,
                    cost_params=cost_params,
                )
                rows.append(row)
    return rows


def write_csv(rows: list[dict[str, object]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Access-signature layout proof-planning sweep (Phase 6B-2.10)."
    )
    parser.add_argument("--num-objects", type=int, default=4096)
    parser.add_argument("--num-roles", type=int, default=16)
    parser.add_argument("--num-signatures", type=int, default=64)
    parser.add_argument(
        "--layouts",
        type=lambda s: [x.strip() for x in s.split(",") if x.strip()],
        default=",".join(BASE_LAYOUTS),
    )
    parser.add_argument(
        "--merged-k-list",
        type=_parse_int_list,
        default=_parse_int_list("1,2,4,8,16,64"),
    )
    parser.add_argument(
        "--query-roles",
        type=str,
        default="all",
        help="Comma-separated role ids or 'all'.",
    )
    parser.add_argument(
        "--seeds",
        type=_parse_int_list,
        default=_parse_int_list("0,1,2,3,4"),
    )
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/proof_planning_layout_metrics_repaired.csv"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    allowed = set(BASE_LAYOUTS) | {"merged_k"}
    for layout in args.layouts:
        if layout not in allowed:
            raise ValueError(f"unknown layout: {layout}")

    rows = run_layout_benchmark(args)
    write_csv(rows, args.output)
    print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
