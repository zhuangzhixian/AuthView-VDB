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
import random
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
    "workload_model",
    "grouping_strategy",
    "purity_mode",
    "locality",
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
    "estimated_region_cost",
    "estimated_visibility_cost",
    "estimated_distance_cost",
    "estimated_mask_topk_cost",
    "seed",
    "effective_visible_ratio",
    "effective_impure_valid_ratio",
    "effective_pure_invisible_valid_ratio",
    "effective_pure_visible_valid_ratio",
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


def _spread_indices(m: int, k: int) -> list[int]:
    """Evenly spread k visible positions within a unit of size m."""
    if k <= 0:
        return []
    if k >= m:
        return list(range(m))
    if k == 1:
        return [m // 2]
    step = (m - 1) / (k - 1)
    raw = [int(round(i * step)) for i in range(k)]
    used: set[int] = set()
    result: list[int] = []
    for idx in raw:
        pos = max(0, min(m - 1, idx))
        while pos in used and pos < m - 1:
            pos += 1
        while pos in used and pos > 0:
            pos -= 1
        used.add(pos)
        result.append(pos)
    while len(result) < k:
        for p in range(m):
            if p not in used:
                used.add(p)
                result.append(p)
                break
    return sorted(result)


def _unit_visible_positions(m: int, k: int, locality: float) -> set[int]:
    """Visible slot positions within one region unit."""
    if k <= 0:
        return set()
    if k >= m:
        return set(range(m))
    if locality >= 1.0 - 1e-9:
        return set(range(k))
    if locality <= 1e-9:
        return set(_spread_indices(m, k))

    clustered = list(range(k))
    spread = _spread_indices(m, k)
    positions: set[int] = set()
    for j in range(k):
        pos = int(round(locality * clustered[j] + (1.0 - locality) * spread[j]))
        pos = max(0, min(m - 1, pos))
        while pos in positions:
            pos = (pos + 1) % m
        positions.add(pos)
    while len(positions) < k:
        for p in range(m):
            if p not in positions:
                positions.add(p)
                break
    return positions


def _unit_visible_counts_clustered(
    units: list[list[int]],
    n_vis: int,
) -> list[int]:
    """Per-unit visible counts from clustered global fill."""
    counts: list[int] = []
    assigned = 0
    for unit in units:
        if assigned + len(unit) <= n_vis:
            counts.append(len(unit))
            assigned += len(unit)
        elif assigned < n_vis:
            counts.append(n_vis - assigned)
            assigned = n_vis
        else:
            counts.append(0)
    return counts


def _unit_visible_counts_spread(
    units: list[list[int]],
    n_vis: int,
) -> list[int]:
    """Spread visible slots across units round-robin (inter-unit mixing)."""
    if not units:
        return []
    caps = [len(unit) for unit in units]
    n_vis = max(0, min(n_vis, sum(caps)))
    counts = [0] * len(units)
    remaining = n_vis
    u = 0
    while remaining > 0:
        progressed = False
        for _ in range(len(units)):
            if remaining <= 0:
                break
            if counts[u] < caps[u]:
                counts[u] += 1
                remaining -= 1
                progressed = True
            u = (u + 1) % len(units)
        if not progressed:
            break
    return counts


def _adjust_unit_counts(
    counts: list[int],
    caps: list[int],
    n_vis: int,
) -> list[int]:
    """Clamp per-unit counts and preserve exact global n_vis."""
    adjusted = [max(0, min(counts[i], caps[i])) for i in range(len(counts))]
    delta = n_vis - sum(adjusted)
    if delta > 0:
        order = sorted(
            range(len(adjusted)),
            key=lambda i: caps[i] - adjusted[i],
            reverse=True,
        )
        for i in order:
            if delta <= 0:
                break
            room = caps[i] - adjusted[i]
            if room <= 0:
                continue
            add = min(room, delta)
            adjusted[i] += add
            delta -= add
    elif delta < 0:
        order = sorted(range(len(adjusted)), key=lambda i: adjusted[i], reverse=True)
        for i in order:
            if delta >= 0:
                break
            take = min(adjusted[i], -delta)
            adjusted[i] -= take
            delta += take
    if sum(adjusted) != n_vis:
        raise ValueError(
            f"cannot assign n_vis={n_vis} with caps={caps}, got {adjusted}"
        )
    return adjusted


def _unit_visible_counts_locality(
    units: list[list[int]],
    n_vis: int,
    locality: float,
) -> list[int]:
    """Interpolate per-unit visible counts between clustered and spread."""
    if locality >= 1.0 - 1e-9:
        return _unit_visible_counts_clustered(units, n_vis)
    if locality <= 1e-9:
        return _unit_visible_counts_spread(units, n_vis)

    clustered = _unit_visible_counts_clustered(units, n_vis)
    spread = _unit_visible_counts_spread(units, n_vis)
    caps = [len(unit) for unit in units]
    raw = [
        locality * clustered[i] + (1.0 - locality) * spread[i]
        for i in range(len(units))
    ]
    floors = [int(r) for r in raw]
    remainder = n_vis - sum(floors)
    order = sorted(
        range(len(units)),
        key=lambda i: raw[i] - floors[i],
        reverse=True,
    )
    counts = floors[:]
    for j in range(max(0, remainder)):
        counts[order[j % len(units)]] += 1
    return _adjust_unit_counts(counts, caps, n_vis)


BETA_MAX_CONCENTRATION = 100.0
BETA_MIN_CONCENTRATION = 0.2


def _sample_beta(alpha: float, beta: float, rng: random.Random) -> float:
    """Sample from Beta(alpha, beta) via Gamma ratio (stdlib only)."""
    alpha = max(alpha, 1e-6)
    beta = max(beta, 1e-6)
    x = rng.gammavariate(alpha, 1.0)
    y = rng.gammavariate(beta, 1.0)
    return x / (x + y)


def assign_visibility_beta_locality(
    n_valid: int,
    n_lists: int,
    slot_per_list: int,
    target_visible_ratio: float,
    grouping_strategy: str,
    block_size: int,
    locality: float,
    seed: int,
    *,
    max_concentration: float = BETA_MAX_CONCENTRATION,
    min_concentration: float = BETA_MIN_CONCENTRATION,
) -> list[bool]:
    """
    Beta-binomial region-probability visibility model (Phase 6B-2.8).

    For each region r, sample p_r ~ Beta(alpha, beta) with mean=target_visible_ratio.
    Concentration decreases with locality so low locality yields impure mixed regions.
    """
    rho = target_visible_ratio
    vis = [False] * n_valid
    if n_valid == 0:
        return vis
    if rho <= 1e-9:
        return vis
    if rho >= 1.0 - 1e-9:
        return [True] * n_valid

    concentration = max_concentration * (1.0 - locality) + min_concentration
    alpha = max(rho * concentration, 1e-6)
    beta_param = max((1.0 - rho) * concentration, 1e-6)

    rng = random.Random(seed)
    units = _cluster_units(
        n_valid, n_lists, slot_per_list, grouping_strategy, block_size
    )
    for unit in units:
        p_r = _sample_beta(alpha, beta_param, rng)
        for slot_idx in unit:
            vis[slot_idx] = rng.random() < p_r
    return vis


def assign_visibility_locality(
    n_valid: int,
    n_lists: int,
    slot_per_list: int,
    target_visible_ratio: float,
    grouping_strategy: str,
    block_size: int,
    locality: float,
) -> list[bool]:
    """
    Locality-aware visibility assignment.

    locality=1: visibility clustered within regions (pure blocks).
    locality=0: visibility spread within regions (impure blocks).
    """
    n_vis = int(round(n_valid * target_visible_ratio))
    n_vis = max(0, min(n_valid, n_vis))
    vis = [False] * n_valid
    if n_valid == 0:
        return vis

    units = _cluster_units(
        n_valid, n_lists, slot_per_list, grouping_strategy, block_size
    )
    unit_counts = _unit_visible_counts_locality(units, n_vis, locality)
    for unit, k in zip(units, unit_counts):
        m = len(unit)
        positions = _unit_visible_positions(m, k, locality)
        for j, slot_idx in enumerate(unit):
            if j in positions:
                vis[slot_idx] = True
    return vis


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
    *,
    locality: float | None = None,
    beta_seed: int | None = None,
) -> tuple[list[CandidateRecord], dict[int, ObjectClassBinding], dict[int, ACLClassLabel]]:
    """Build deterministic probe-major candidate grid with ACL bindings."""
    n_slots = n_lists * slot_per_list
    if n_valid > n_slots:
        raise ValueError(f"n_valid={n_valid} exceeds grid capacity {n_slots}")

    if beta_seed is not None:
        assert locality is not None
        visibility = assign_visibility_beta_locality(
            n_valid,
            n_lists,
            slot_per_list,
            target_visible_ratio,
            grouping_strategy,
            block_size,
            locality,
            beta_seed,
        )
    elif locality is not None:
        visibility = assign_visibility_locality(
            n_valid,
            n_lists,
            slot_per_list,
            target_visible_ratio,
            grouping_strategy,
            block_size,
            locality,
        )
    else:
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


def _plan_cost_breakdown(plan, cost_params: dict[str, int]) -> dict[str, int]:
    """Decompose planned cost into region / visibility / distance / mask+topk."""
    c_dist = cost_params["C_dist"]
    c_vis = cost_params["C_vis"]
    c_mask = cost_params["C_mask"]
    c_pure = cost_params["C_region_pure"]
    c_impure = cost_params["C_region_impure"]
    c_topk = cost_params["C_topk_per_candidate"]

    region_cost = 0
    visibility_cost = 0
    distance_cost = 0
    mask_cost = 0
    for region in plan.regions:
        if region.region_type == "pure_visible":
            region_cost += c_pure
            distance_cost += region.valid_count * c_dist
        elif region.region_type == "pure_invisible":
            region_cost += c_pure
        else:
            region_cost += c_impure
            visibility_cost += region.valid_count * c_vis
            distance_cost += region.valid_count * c_dist
            mask_cost += region.valid_count * c_mask
    topk_cost = plan.N_valid * c_topk
    return {
        "estimated_region_cost": region_cost,
        "estimated_visibility_cost": visibility_cost,
        "estimated_distance_cost": distance_cost,
        "estimated_mask_topk_cost": mask_cost + topk_cost,
    }


def evaluate_case(
    *,
    case_id: str,
    workload_model: str,
    grouping_strategy: str,
    purity_mode: str,
    locality: str,
    block_size: int,
    n_valid: int,
    n_lists: int,
    slot_per_list: int,
    target_visible_ratio: float,
    top_k: int,
    cost_params: dict[str, int],
    locality_value: float | None = None,
    seed: int | None = None,
) -> dict[str, object]:
    candidates, bindings, _ = build_synthetic_candidates(
        n_valid=n_valid,
        n_lists=n_lists,
        slot_per_list=slot_per_list,
        target_visible_ratio=target_visible_ratio,
        purity_mode=purity_mode,
        grouping_strategy=grouping_strategy,
        block_size=block_size,
        locality=locality_value,
        beta_seed=seed,
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
    breakdown = _plan_cost_breakdown(plan, cost_params)

    eff_vis = _safe_ratio(float(plan.N_vis), float(plan.N_valid))
    eff_imp = _safe_ratio(float(imp_valid), float(plan.N_valid))
    eff_pi = _safe_ratio(float(pi_valid), float(plan.N_valid))
    eff_pv = _safe_ratio(float(pv_valid), float(plan.N_valid))

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
        "workload_model": workload_model,
        "grouping_strategy": grouping_strategy,
        "purity_mode": purity_mode,
        "locality": locality,
        "block_size": _csv_block_size(grouping_strategy, block_size),
        "n_lists": n_lists,
        "slot_per_list": slot_per_list,
        "N_slots": plan.N_slots,
        "N_valid": plan.N_valid,
        "N_vis": plan.N_vis,
        "N_invis": plan.N_invis,
        "visible_ratio": f"{target_visible_ratio:.6f}",
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
        "estimated_region_cost": breakdown["estimated_region_cost"],
        "estimated_visibility_cost": breakdown["estimated_visibility_cost"],
        "estimated_distance_cost": breakdown["estimated_distance_cost"],
        "estimated_mask_topk_cost": breakdown["estimated_mask_topk_cost"],
        "seed": "" if seed is None else seed,
        "effective_visible_ratio": f"{eff_vis:.6f}",
        "effective_impure_valid_ratio": f"{eff_imp:.6f}",
        "effective_pure_invisible_valid_ratio": f"{eff_pi:.6f}",
        "effective_pure_visible_valid_ratio": f"{eff_pv:.6f}",
        "plan_vs_masked_cost": f"{plan_vs_masked:.6f}",
        "ideal_vs_masked_cost": f"{ideal_vs_masked:.6f}",
        "PA_plan": f"{pa_plan:.6f}",
        "PA_ideal": f"{pa_ideal:.6f}",
        "planned_equals_masked": str(comparison["equivalent"]).lower(),
        "validation_passed": str(validation.valid).lower(),
    }


def _block_sizes_for_grouping(
    grouping: str,
    block_sizes: list[int],
) -> list[int]:
    """fixed_block sweeps all block sizes; other strategies use 0 (NA)."""
    if grouping == "fixed_block":
        return block_sizes
    return [0]


def _csv_block_size(grouping: str, block_size: int) -> int:
    """Record block_size in CSV; non-fixed-block strategies use 0."""
    return block_size if grouping == "fixed_block" else 0


def run_beta_benchmark(args: argparse.Namespace) -> list[dict[str, object]]:
    """Beta-binomial locality sweep (Phase 6B-2.8 paper workload)."""
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
        for loc in args.locality_values:
            for vr in args.visible_ratios:
                for bs in _block_sizes_for_grouping(grouping, args.block_sizes):
                    for seed in args.seeds:
                        plan_bs = bs if grouping == "fixed_block" else 16
                        csv_bs = _csv_block_size(grouping, bs)
                        vr_tag = str(vr).replace(".", "p")
                        loc_tag = str(loc).replace(".", "p")
                        case_id = (
                            f"{grouping}_beta_loc{loc_tag}_vr{vr_tag}_bs{csv_bs}"
                            f"_s{seed}_nl{n_lists}_spl{slot_per_list}"
                        )
                        row = evaluate_case(
                            case_id=case_id,
                            workload_model="beta_locality",
                            grouping_strategy=grouping,
                            purity_mode="beta_locality",
                            locality=f"{loc:.6f}",
                            block_size=plan_bs,
                            n_valid=n_valid,
                            n_lists=n_lists,
                            slot_per_list=slot_per_list,
                            target_visible_ratio=vr,
                            top_k=args.top_k,
                            cost_params=cost_params,
                            locality_value=loc,
                            seed=seed,
                        )
                        rows.append(row)
    return rows


def run_locality_benchmark(args: argparse.Namespace) -> list[dict[str, object]]:
    """Locality-aware sweep (Phase 6B-2.7 default paper workload)."""
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
        for loc in args.locality_values:
            for vr in args.visible_ratios:
                for bs in _block_sizes_for_grouping(grouping, args.block_sizes):
                    plan_bs = bs if grouping == "fixed_block" else 16
                    csv_bs = _csv_block_size(grouping, bs)
                    vr_tag = str(vr).replace(".", "p")
                    loc_tag = str(loc).replace(".", "p")
                    case_id = (
                        f"{grouping}_loc{loc_tag}_vr{vr_tag}_bs{csv_bs}"
                        f"_nl{n_lists}_spl{slot_per_list}"
                    )
                    row = evaluate_case(
                        case_id=case_id,
                        workload_model="locality_sweep",
                        grouping_strategy=grouping,
                        purity_mode="locality",
                        locality=f"{loc:.6f}",
                        block_size=plan_bs,
                        n_valid=n_valid,
                        n_lists=n_lists,
                        slot_per_list=slot_per_list,
                        target_visible_ratio=vr,
                        top_k=args.top_k,
                        cost_params=cost_params,
                        locality_value=loc,
                    )
                    rows.append(row)
    return rows


def run_purity_benchmark(args: argparse.Namespace) -> list[dict[str, object]]:
    """Legacy purity-mode sweep (Phase 6B-2)."""
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
                for bs in _block_sizes_for_grouping(grouping, args.block_sizes):
                    plan_bs = bs if grouping == "fixed_block" else 16
                    csv_bs = _csv_block_size(grouping, bs)
                    vr_tag = str(vr).replace(".", "p")
                    case_id = (
                        f"{grouping}_{purity}_vr{vr_tag}_bs{csv_bs}"
                        f"_nl{n_lists}_spl{slot_per_list}"
                    )
                    row = evaluate_case(
                        case_id=case_id,
                        workload_model="purity_sweep",
                        grouping_strategy=grouping,
                        purity_mode=purity,
                        locality="",
                        block_size=plan_bs,
                        n_valid=n_valid,
                        n_lists=n_lists,
                        slot_per_list=slot_per_list,
                        target_visible_ratio=vr,
                        top_k=args.top_k,
                        cost_params=cost_params,
                    )
                    rows.append(row)
    return rows


def run_benchmark(args: argparse.Namespace) -> list[dict[str, object]]:
    if args.workload_model == "beta_locality":
        return run_beta_benchmark(args)
    if args.workload_model == "locality_sweep":
        return run_locality_benchmark(args)
    return run_purity_benchmark(args)


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
        default=_parse_float_list("0.0,0.05,0.1,0.25,0.5,0.75,0.9,1.0"),
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
        default=_parse_int_list("8,16,32,64"),
    )
    parser.add_argument(
        "--locality-values",
        type=_parse_float_list,
        default=_parse_float_list("0.0,0.25,0.5,0.75,1.0"),
    )
    parser.add_argument(
        "--workload-model",
        choices=("purity_sweep", "locality_sweep", "beta_locality"),
        default="purity_sweep",
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
