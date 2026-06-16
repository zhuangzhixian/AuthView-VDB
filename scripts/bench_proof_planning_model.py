#!/usr/bin/env python3
"""
Phase 6B-2: Access-aware proof planning cost-model sweep (plaintext only).

Generates deterministic synthetic candidates, builds proof plans under multiple
grouping strategies and purity modes, and writes relative cost-model metrics CSV.
Does not call Rust, PyO3, or ZK APIs.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

from auth_reference.acl_class import ACLClassLabel, ObjectClassBinding
from auth_reference.attacks import DEFAULT_CHECKPOINT, DEFAULT_USER
from auth_reference.policy import compute_visibility
from auth_reference.proof_planning_reference import (
    DEFAULT_COST_PARAMS,
    build_proof_plan,
    compare_planned_vs_masked_reference,
    validate_proof_plan,
)
from auth_reference.records import AuthLabel, CandidateRecord

CSV_FIELDS = [
    "case_id",
    "grouping_strategy",
    "purity_mode",
    "block_size",
    "n_lists",
    "slot_per_list",
    "N_slots",
    "N_valid",
    "N_vis",
    "N_invis",
    "visible_ratio",
    "region_count",
    "pure_visible_regions",
    "pure_invisible_regions",
    "impure_regions",
    "pure_region_ratio",
    "pure_visible_ratio",
    "pure_invisible_ratio",
    "impure_region_ratio",
    "pure_visible_valid_count",
    "pure_invisible_valid_count",
    "impure_valid_count",
    "N_dist_masked",
    "N_dist_plan",
    "N_dist_ideal",
    "dist_reduction_plan",
    "dist_reduction_ideal",
    "estimated_cost_masked",
    "estimated_cost_plan",
    "estimated_cost_ideal",
    "plan_vs_masked_cost",
    "ideal_vs_masked_cost",
    "PA_plan",
    "PA_ideal",
    "planned_equals_masked",
    "validation_passed",
]


def _parse_float_list(value: str) -> list[float]:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected at least one float")
    return [float(p) for p in parts]


def _parse_str_list(value: str) -> list[str]:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected at least one token")
    return parts


def _parse_int_list(value: str) -> list[int]:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected at least one integer")
    return [int(p) for p in parts]


def _visible_label() -> AuthLabel:
    return AuthLabel(
        tenant="acme",
        project="proj-a",
        level=2,
        state="active",
        epoch=DEFAULT_CHECKPOINT.epoch,
    )


def _invisible_label() -> AuthLabel:
    return AuthLabel(
        tenant="other",
        project="proj-a",
        level=2,
        state="active",
        epoch=DEFAULT_CHECKPOINT.epoch,
    )


def _cluster_units(
    n_valid: int,
    n_lists: int,
    slot_per_list: int,
    grouping_strategy: str,
    block_size: int,
) -> list[list[int]]:
    """Partition valid slot indices 0..n_valid-1 into clustering units."""
    valid_slots: list[tuple[int, int, int]] = []
    idx = 0
    for lid in range(n_lists):
        for sid in range(slot_per_list):
            if idx >= n_valid:
                break
            valid_slots.append((idx, lid, sid))
            idx += 1
        if idx >= n_valid:
            break

    units: list[list[int]] = []
    if grouping_strategy == "ivf_list":
        by_list: dict[int, list[int]] = defaultdict(list)
        for vi, lid, _ in valid_slots:
            by_list[lid].append(vi)
        for lid in sorted(by_list):
            units.append(by_list[lid])
    elif grouping_strategy == "acl_class":
        by_list = defaultdict(list)
        for vi, lid, _ in valid_slots:
            by_list[lid].append(vi)
        for lid in sorted(by_list):
            units.append(by_list[lid])
    elif grouping_strategy == "fixed_block":
        ordered = [vi for vi, _, _ in valid_slots]
        for start in range(0, len(ordered), block_size):
            units.append(ordered[start : start + block_size])
    else:
        raise ValueError(f"unknown grouping_strategy: {grouping_strategy}")
    return units


def assign_visibility_bits(
    n_valid: int,
    n_lists: int,
    slot_per_list: int,
    target_visible_ratio: float,
    purity_mode: str,
    grouping_strategy: str,
    block_size: int,
) -> list[bool]:
    """Deterministic visibility assignment for valid slot indices."""
    n_vis = int(round(n_valid * target_visible_ratio))
    n_vis = max(0, min(n_valid, n_vis))
    vis = [False] * n_valid

    if n_valid == 0:
        return vis

    if purity_mode == "clustered":
        units = _cluster_units(
            n_valid, n_lists, slot_per_list, grouping_strategy, block_size
        )
        assigned = 0
        for unit in units:
            if assigned + len(unit) <= n_vis:
                for i in unit:
                    vis[i] = True
                assigned += len(unit)
            elif assigned < n_vis:
                remaining = n_vis - assigned
                for i in unit[:remaining]:
                    vis[i] = True
                assigned += remaining
                break
            else:
                break
    elif purity_mode == "mixed":
        if n_vis == 0:
            pass
        elif n_vis == n_valid:
            vis = [True] * n_valid
        else:
            period = max(1, n_valid // n_vis)
            for i in range(n_valid):
                if sum(vis) >= n_vis:
                    break
                if i % period == 0:
                    vis[i] = True
            i = 0
            while sum(vis) < n_vis and i < n_valid:
                if not vis[i]:
                    vis[i] = True
                i += 1
    elif purity_mode == "adversarial_mixed":
        if n_vis == 0:
            pass
        elif n_vis == n_valid:
            vis = [True] * n_valid
        else:
            units = _cluster_units(
                n_valid, n_lists, slot_per_list, grouping_strategy, block_size
            )
            for unit in units:
                for j, slot_idx in enumerate(unit):
                    vis[slot_idx] = j % 2 == 0
            current = sum(vis)
            if current > n_vis:
                for slot_idx in range(n_valid - 1, -1, -1):
                    if current <= n_vis:
                        break
                    if vis[slot_idx]:
                        vis[slot_idx] = False
                        current -= 1
            elif current < n_vis:
                for slot_idx in range(n_valid):
                    if current >= n_vis:
                        break
                    if not vis[slot_idx]:
                        vis[slot_idx] = True
                        current += 1
    else:
        raise ValueError(f"unknown purity_mode: {purity_mode}")

    return vis


def build_synthetic_candidates(
    n_valid: int,
    n_lists: int,
    slot_per_list: int,
    target_visible_ratio: float,
    purity_mode: str,
    grouping_strategy: str,
    block_size: int,
) -> tuple[list[CandidateRecord], dict[int, ObjectClassBinding], dict[int, ACLClassLabel]]:
    """Build deterministic probe-major candidate grid with ACL bindings."""
    n_slots = n_lists * slot_per_list
    if n_valid > n_slots:
        raise ValueError(f"n_valid={n_valid} exceeds grid capacity {n_slots}")

    visibility = assign_visibility_bits(
        n_valid,
        n_lists,
        slot_per_list,
        target_visible_ratio,
        purity_mode,
        grouping_strategy,
        block_size,
    )

    candidates: list[CandidateRecord] = []
    bindings: dict[int, ObjectClassBinding] = {}
    class_labels: dict[int, ACLClassLabel] = {}

    valid_idx = 0
    for lid in range(n_lists):
        for sid in range(slot_per_list):
            flat = lid * slot_per_list + sid
            cid = 10_000 + flat
            is_valid = valid_idx < n_valid
            if is_valid:
                label = _visible_label() if visibility[valid_idx] else _invisible_label()
                valid_idx += 1
            else:
                label = _invisible_label()

            candidates.append(
                CandidateRecord(
                    cid=cid,
                    list_id=lid,
                    slot_id=sid,
                    valid=is_valid,
                    distance=1000 + flat,
                    label=label,
                )
            )

            if is_valid:
                class_id = 100 + lid
                bindings[cid] = ObjectClassBinding(
                    cid=cid, acl_class_id=class_id, epoch=DEFAULT_CHECKPOINT.epoch
                )
                if class_id not in class_labels:
                    class_labels[class_id] = ACLClassLabel(
                        acl_class_id=class_id,
                        tenant_id=1,
                        project_id=10,
                        required_clearance=2,
                        state="active",
                        epoch=DEFAULT_CHECKPOINT.epoch,
                    )

    return candidates, bindings, class_labels


def _oracle_authorized_cost(n_vis: int, cost_params: dict[str, int]) -> int:
    c_dist = cost_params["C_dist"]
    c_topk = cost_params["C_topk_per_candidate"]
    return max(1, n_vis) * (c_dist + c_topk)


def _region_valid_counts(plan) -> tuple[int, int, int]:
    pv = pi = imp = 0
    for region in plan.regions:
        if region.region_type == "pure_visible":
            pv += region.valid_count
        elif region.region_type == "pure_invisible":
            pi += region.valid_count
        else:
            imp += region.valid_count
    return pv, pi, imp


def _safe_ratio(num: float, denom: float) -> float:
    if denom == 0:
        return 0.0
    return num / denom


def evaluate_case(
    *,
    case_id: str,
    grouping_strategy: str,
    purity_mode: str,
    block_size: int,
    n_valid: int,
    n_lists: int,
    slot_per_list: int,
    target_visible_ratio: float,
    top_k: int,
    cost_params: dict[str, int],
) -> dict[str, object]:
    candidates, bindings, _ = build_synthetic_candidates(
        n_valid=n_valid,
        n_lists=n_lists,
        slot_per_list=slot_per_list,
        target_visible_ratio=target_visible_ratio,
        purity_mode=purity_mode,
        grouping_strategy=grouping_strategy,
        block_size=block_size,
    )
    n_valid = sum(1 for c in candidates if c.valid)
    n_vis = sum(
        1
        for c in candidates
        if c.valid
        and compute_visibility(DEFAULT_USER, c.label, DEFAULT_CHECKPOINT) == 1
    )

    effective_block = block_size if grouping_strategy == "fixed_block" else 16
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy=grouping_strategy,
        block_size=effective_block,
        bindings=bindings,
        n_probe=n_lists,
        slots_per_list=slot_per_list,
    )
    validation = validate_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=top_k,
        n_probe=n_lists,
        slots_per_list=slot_per_list,
    )
    comparison = compare_planned_vs_masked_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k,
        n_probe=n_lists,
        slots_per_list=slot_per_list,
    )

    n_regions = len(plan.regions)
    pv_valid, pi_valid, imp_valid = _region_valid_counts(plan)

    dist_red_plan = _safe_ratio(
        float(plan.N_dist_masked - plan.N_dist_plan), float(plan.N_dist_masked)
    )
    dist_red_ideal = _safe_ratio(
        float(plan.N_dist_masked - plan.N_dist_ideal), float(plan.N_dist_masked)
    )
    plan_vs_masked = _safe_ratio(
        float(plan.estimated_cost_plan), float(plan.estimated_cost_masked)
    )
    ideal_vs_masked = _safe_ratio(
        float(plan.estimated_cost_ideal_visible_compaction),
        float(plan.estimated_cost_masked),
    )

    oracle = _oracle_authorized_cost(plan.N_vis, cost_params)
    pa_plan = _safe_ratio(float(plan.estimated_cost_plan), float(oracle))
    pa_ideal = _safe_ratio(
        float(plan.estimated_cost_ideal_visible_compaction), float(oracle)
    )

    return {
        "case_id": case_id,
        "grouping_strategy": grouping_strategy,
        "purity_mode": purity_mode,
        "block_size": block_size,
        "n_lists": n_lists,
        "slot_per_list": slot_per_list,
        "N_slots": plan.N_slots,
        "N_valid": plan.N_valid,
        "N_vis": plan.N_vis,
        "N_invis": plan.N_invis,
        "visible_ratio": f"{plan.visible_ratio:.6f}",
        "region_count": n_regions,
        "pure_visible_regions": plan.N_pure_visible_regions,
        "pure_invisible_regions": plan.N_pure_invisible_regions,
        "impure_regions": plan.N_impure_regions,
        "pure_region_ratio": f"{plan.pure_region_ratio:.6f}",
        "pure_visible_ratio": f"{_safe_ratio(plan.N_pure_visible_regions, n_regions):.6f}",
        "pure_invisible_ratio": f"{_safe_ratio(plan.N_pure_invisible_regions, n_regions):.6f}",
        "impure_region_ratio": f"{plan.impure_region_ratio:.6f}",
        "pure_visible_valid_count": pv_valid,
        "pure_invisible_valid_count": pi_valid,
        "impure_valid_count": imp_valid,
        "N_dist_masked": plan.N_dist_masked,
        "N_dist_plan": plan.N_dist_plan,
        "N_dist_ideal": plan.N_dist_ideal,
        "dist_reduction_plan": f"{dist_red_plan:.6f}",
        "dist_reduction_ideal": f"{dist_red_ideal:.6f}",
        "estimated_cost_masked": plan.estimated_cost_masked,
        "estimated_cost_plan": plan.estimated_cost_plan,
        "estimated_cost_ideal": plan.estimated_cost_ideal_visible_compaction,
        "plan_vs_masked_cost": f"{plan_vs_masked:.6f}",
        "ideal_vs_masked_cost": f"{ideal_vs_masked:.6f}",
        "PA_plan": f"{pa_plan:.6f}",
        "PA_ideal": f"{pa_ideal:.6f}",
        "planned_equals_masked": str(comparison["equivalent"]).lower(),
        "validation_passed": str(validation.valid).lower(),
    }


def run_benchmark(args: argparse.Namespace) -> list[dict[str, object]]:
    n_valid = args.n_valid
    n_lists = args.n_lists
    slot_per_list = args.slot_per_list
    if n_valid > n_lists * slot_per_list:
        raise ValueError(
            f"n_valid={n_valid} exceeds grid {n_lists}×{slot_per_list}"
        )

    cost_params = dict(DEFAULT_COST_PARAMS)
    rows: list[dict[str, object]] = []

    for grouping in args.grouping_strategies:
        for purity in args.purity_modes:
            for vr in args.visible_ratios:
                block_sizes = (
                    args.block_sizes
                    if grouping == "fixed_block"
                    else [args.block_sizes[0]]
                )
                for bs in block_sizes:
                    vr_tag = str(vr).replace(".", "p")
                    case_id = (
                        f"{grouping}_{purity}_vr{vr_tag}_bs{bs}"
                        f"_nl{n_lists}_spl{slot_per_list}"
                    )
                    row = evaluate_case(
                        case_id=case_id,
                        grouping_strategy=grouping,
                        purity_mode=purity,
                        block_size=bs,
                        n_valid=n_valid,
                        n_lists=n_lists,
                        slot_per_list=slot_per_list,
                        target_visible_ratio=vr,
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
        description="Proof-planning plaintext cost-model sweep (Phase 6B-2)."
    )
    parser.add_argument("--n-valid", type=int, default=256)
    parser.add_argument("--n-lists", type=int, default=4)
    parser.add_argument("--slot-per-list", type=int, default=64)
    parser.add_argument(
        "--visible-ratios",
        type=_parse_float_list,
        default=_parse_float_list("0.0,0.1,0.25,0.5,0.75,1.0"),
    )
    parser.add_argument(
        "--grouping-strategies",
        type=_parse_str_list,
        default=_parse_str_list("acl_class,ivf_list,fixed_block"),
    )
    parser.add_argument(
        "--purity-modes",
        type=_parse_str_list,
        default=_parse_str_list("clustered,mixed,adversarial_mixed"),
    )
    parser.add_argument(
        "--block-sizes",
        type=_parse_int_list,
        default=_parse_int_list("16"),
    )
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/proof_planning_model_metrics.csv"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.n_valid != args.n_lists * args.slot_per_list:
        args.n_valid = args.n_lists * args.slot_per_list

    rows = run_benchmark(args)
    write_csv(rows, args.output)
    print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
