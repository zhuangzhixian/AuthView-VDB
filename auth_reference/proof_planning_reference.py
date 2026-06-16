"""Access-structure-aware proof planning plaintext reference (Phase 6B-1).

Constructs pure_visible / pure_invisible / impure regions over a fixed candidate
grid and verifies planned execution equals masked-distance baseline top-k.

This module is a plaintext oracle + cost model only; it does not modify ZK circuits.
Static fixed-shape circuits do not reduce gates from per-candidate mux alone.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from auth_reference.acl_class import ObjectClassBinding, build_acl_fixtures_from_candidates
from auth_reference.policy import compute_visibility
from auth_reference.records import (
    CandidateRecord,
    Checkpoint,
    ScoredCandidate,
    UserContext,
)
from auth_reference.reference import (
    DEFAULT_D_MAX,
    authorized_topk,
    check_candidate_coverage,
    compute_masked_distance,
    run_authorized_reference,
)

RegionType = Literal["pure_visible", "pure_invisible", "impure"]
GroupingStrategy = Literal["acl_class", "ivf_list", "fixed_block"]

# Default relative cost weights (plaintext model; not measured ZK gates).
DEFAULT_COST_PARAMS: dict[str, int] = {
    "C_dist": 10,
    "C_vis": 3,
    "C_mask": 1,
    "C_region_pure": 5,
    "C_region_impure": 2,
    "C_topk_per_candidate": 1,
    "C_compact": 5,
}


@dataclass(frozen=True)
class ProofRegion:
    """One proof region in Plan(q, U, sigma)."""

    region_id: int
    region_type: RegionType
    region_key: str
    grouping_strategy: GroupingStrategy
    candidate_indices: tuple[int, ...]
    valid_count: int
    visible_count: int
    invisible_count: int
    estimated_distance_count: int
    estimated_visibility_count: int


@dataclass
class ProofPlan:
    """Proof plan over reference candidate slots with cost-model metadata."""

    regions: list[ProofRegion]
    grouping_strategy: GroupingStrategy
    N_slots: int
    N_valid: int
    N_vis: int
    N_invis: int
    N_pure_visible_regions: int
    N_pure_invisible_regions: int
    N_impure_regions: int
    pure_region_ratio: float
    impure_region_ratio: float
    visible_ratio: float
    estimated_cost_masked: int
    estimated_cost_plan: int
    estimated_cost_ideal_visible_compaction: int
    N_dist_masked: int
    N_dist_plan: int
    N_dist_ideal: int


@dataclass
class PlannedReferenceResult:
    """Output of run_authorized_reference_planned."""

    top_k_cids: list[int]
    scored: list[ScoredCandidate]
    plan: ProofPlan
    checkpoint: Checkpoint
    user: UserContext


@dataclass
class PlanValidationResult:
    """Result of validate_proof_plan."""

    valid: bool
    errors: list[str] = field(default_factory=list)


def _visibility_map(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
) -> dict[int, int]:
    return {
        idx: compute_visibility(user, candidates[idx].label, checkpoint)
        for idx in range(len(candidates))
    }


def _classify_region_type(
    visibilities: list[int],
    *,
    valid_count: int,
) -> RegionType:
    """Derive region type from committed visibility of valid slots only."""
    if valid_count == 0:
        return "impure"
    if all(v == 1 for v in visibilities):
        return "pure_visible"
    if all(v == 0 for v in visibilities):
        return "pure_invisible"
    return "impure"


def _region_distance_and_visibility_counts(
    region_type: RegionType,
    valid_count: int,
    visible_count: int,
) -> tuple[int, int]:
    """Conservative plaintext cost counters per region."""
    if region_type == "pure_visible":
        return valid_count, 0
    if region_type == "pure_invisible":
        return 0, 0
    return valid_count, valid_count


def _make_region(
    region_id: int,
    region_key: str,
    grouping_strategy: GroupingStrategy,
    indices: list[int],
    candidates: list[CandidateRecord],
    vis_map: dict[int, int],
) -> ProofRegion:
    valid_indices = [i for i in indices if candidates[i].valid]
    valid_count = len(valid_indices)
    visible_count = sum(1 for i in valid_indices if vis_map[i] == 1)
    invisible_count = valid_count - visible_count
    visibilities = [vis_map[i] for i in valid_indices]
    region_type = _classify_region_type(visibilities, valid_count=valid_count)
    dist_count, vis_count = _region_distance_and_visibility_counts(
        region_type, valid_count, visible_count
    )
    return ProofRegion(
        region_id=region_id,
        region_type=region_type,
        region_key=region_key,
        grouping_strategy=grouping_strategy,
        candidate_indices=tuple(sorted(indices)),
        valid_count=valid_count,
        visible_count=visible_count,
        invisible_count=invisible_count,
        estimated_distance_count=dist_count,
        estimated_visibility_count=vis_count,
    )


def _group_indices_ivf_list(candidates: list[CandidateRecord]) -> dict[str, list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for idx, c in enumerate(candidates):
        groups[f"list-{c.list_id}"].append(idx)
    return groups


def _group_indices_fixed_block(
    candidates: list[CandidateRecord],
    block_size: int,
) -> dict[str, list[int]]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    ordered = sorted(
        range(len(candidates)),
        key=lambda i: (candidates[i].list_id, candidates[i].slot_id),
    )
    groups: dict[str, list[int]] = {}
    for block_idx in range(0, len(ordered), block_size):
        chunk = ordered[block_idx : block_idx + block_size]
        groups[f"block-{block_idx // block_size}"] = chunk
    return groups


def _group_indices_acl_class(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
) -> dict[str, list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for idx, c in enumerate(candidates):
        if not c.valid:
            groups[f"invalid-list-{c.list_id}"].append(idx)
            continue
        binding = bindings.get(c.cid)
        if binding is None:
            raise ValueError(f"missing ACL binding for valid cid={c.cid}")
        groups[f"acl-{binding.acl_class_id}"].append(idx)
    return groups


def build_proof_plan(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    grouping_strategy: GroupingStrategy = "acl_class",
    block_size: int = 16,
    bindings: dict[int, ObjectClassBinding] | None = None,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
) -> ProofPlan:
    """
    Build a proof plan partitioning candidate slots into typed regions.

    Invalid slots are included in regions for coverage but do not affect purity
    classification (only valid slots determine pure_visible / pure_invisible).
    """
    check_candidate_coverage(
        candidates, n_probe=n_probe, slots_per_list=slots_per_list
    )
    if not candidates:
        raise ValueError("empty candidate set")

    if grouping_strategy == "acl_class":
        if bindings is None:
            bindings, _ = build_acl_fixtures_from_candidates(candidates)
        groups = _group_indices_acl_class(candidates, bindings)
    elif grouping_strategy == "ivf_list":
        groups = _group_indices_ivf_list(candidates)
    elif grouping_strategy == "fixed_block":
        groups = _group_indices_fixed_block(candidates, block_size)
    else:
        raise ValueError(f"unknown grouping_strategy: {grouping_strategy}")

    vis_map = _visibility_map(candidates, user, checkpoint)
    regions: list[ProofRegion] = []
    for region_id, (region_key, indices) in enumerate(sorted(groups.items())):
        if not indices:
            continue
        regions.append(
            _make_region(
                region_id,
                region_key,
                grouping_strategy,
                indices,
                candidates,
                vis_map,
            )
        )

    n_slots = len(candidates)
    n_valid = sum(1 for c in candidates if c.valid)
    n_vis = sum(
        1
        for i, c in enumerate(candidates)
        if c.valid and vis_map[i] == 1
    )
    n_invis = n_valid - n_vis

    n_pv = sum(1 for r in regions if r.region_type == "pure_visible")
    n_pi = sum(1 for r in regions if r.region_type == "pure_invisible")
    n_imp = sum(1 for r in regions if r.region_type == "impure")
    n_regions = len(regions)

    plan = ProofPlan(
        regions=regions,
        grouping_strategy=grouping_strategy,
        N_slots=n_slots,
        N_valid=n_valid,
        N_vis=n_vis,
        N_invis=n_invis,
        N_pure_visible_regions=n_pv,
        N_pure_invisible_regions=n_pi,
        N_impure_regions=n_imp,
        pure_region_ratio=(n_pv + n_pi) / n_regions if n_regions else 0.0,
        impure_region_ratio=n_imp / n_regions if n_regions else 0.0,
        visible_ratio=n_vis / n_valid if n_valid else 0.0,
        estimated_cost_masked=0,
        estimated_cost_plan=0,
        estimated_cost_ideal_visible_compaction=0,
        N_dist_masked=n_valid,
        N_dist_plan=sum(r.estimated_distance_count for r in regions),
        N_dist_ideal=n_vis,
    )
    costs = estimate_proof_plan_cost(plan)
    plan.estimated_cost_masked = costs["estimated_cost_masked"]
    plan.estimated_cost_plan = costs["estimated_cost_plan"]
    plan.estimated_cost_ideal_visible_compaction = costs[
        "estimated_cost_ideal_visible_compaction"
    ]
    return plan


def _score_slot_in_region(
    candidate: CandidateRecord,
    region: ProofRegion,
    user: UserContext,
    checkpoint: Checkpoint,
    d_max: int,
) -> ScoredCandidate:
    """Apply planned execution semantics for one slot."""
    visibility = compute_visibility(user, candidate.label, checkpoint)

    if not candidate.valid:
        hat, masked = compute_masked_distance(
            candidate.distance, candidate.valid, visibility, d_max
        )
    elif region.region_type == "pure_visible":
        hat, masked = compute_masked_distance(
            candidate.distance, candidate.valid, 1, d_max
        )
    elif region.region_type == "pure_invisible":
        hat, masked = compute_masked_distance(
            candidate.distance, candidate.valid, 0, d_max
        )
    else:
        hat, masked = compute_masked_distance(
            candidate.distance, candidate.valid, visibility, d_max
        )

    return ScoredCandidate(
        cid=candidate.cid,
        list_id=candidate.list_id,
        slot_id=candidate.slot_id,
        valid=candidate.valid,
        distance=candidate.distance,
        label=candidate.label,
        visibility=visibility,
        hat_distance=hat,
        masked_distance=masked,
    )


def _index_to_region(plan: ProofPlan) -> dict[int, ProofRegion]:
    mapping: dict[int, ProofRegion] = {}
    for region in plan.regions:
        for idx in region.candidate_indices:
            if idx in mapping:
                raise ValueError(
                    f"duplicate coverage: index {idx} in regions "
                    f"{mapping[idx].region_id} and {region.region_id}"
                )
            mapping[idx] = region
    return mapping


def run_authorized_reference_planned(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    plan: ProofPlan,
    top_k: int,
    *,
    d_max: int = DEFAULT_D_MAX,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
) -> PlannedReferenceResult:
    """
    Execute authorized top-k under proof plan semantics.

    pure_visible: valid slots use raw distance (region-level visibility proof).
    pure_invisible: valid slots assigned d_max without distance computation.
    impure: per-slot masked-distance fallback (same as baseline).
    """
    check_candidate_coverage(
        candidates, n_probe=n_probe, slots_per_list=slots_per_list
    )
    idx_region = _index_to_region(plan)
    if len(idx_region) != len(candidates):
        missing = set(range(len(candidates))) - set(idx_region)
        raise ValueError(f"plan missing candidate indices: {sorted(missing)}")

    scored = [
        _score_slot_in_region(
            candidates[idx], idx_region[idx], user, checkpoint, d_max
        )
        for idx in range(len(candidates))
    ]
    top_k_cids = authorized_topk(scored, top_k)
    return PlannedReferenceResult(
        top_k_cids=top_k_cids,
        scored=scored,
        plan=plan,
        checkpoint=checkpoint,
        user=user,
    )


def estimate_proof_plan_cost(
    plan: ProofPlan,
    cost_params: dict[str, int] | None = None,
) -> dict[str, int]:
    """
    Plaintext relative cost model for masked vs planned vs ideal compaction.

    Conservative plan cost counts per-slot vis+dist+mask on impure regions and
    per-slot dist on pure_visible; pure_invisible skips distance. Top-k cost
    uses N_valid candidates (conservative fixed-shape assumption).

    Ideal visible compaction: one global visibility pass + distance only on
    visible slots + compaction overhead.
    """
    p = {**DEFAULT_COST_PARAMS, **(cost_params or {})}
    c_dist = p["C_dist"]
    c_vis = p["C_vis"]
    c_mask = p["C_mask"]
    c_pure = p["C_region_pure"]
    c_impure = p["C_region_impure"]
    c_topk = p["C_topk_per_candidate"]
    c_compact = p["C_compact"]

    n_valid = plan.N_valid
    cost_masked = n_valid * (c_vis + c_dist + c_mask) + n_valid * c_topk

    cost_plan = 0
    for region in plan.regions:
        if region.region_type == "pure_visible":
            cost_plan += c_pure + region.valid_count * c_dist
        elif region.region_type == "pure_invisible":
            cost_plan += c_pure
        else:
            cost_plan += c_impure + region.valid_count * (c_vis + c_dist + c_mask)
    cost_plan += n_valid * c_topk

    cost_ideal = (
        n_valid * c_vis
        + plan.N_vis * c_dist
        + c_compact
        + plan.N_vis * c_topk
    )

    return {
        "estimated_cost_masked": cost_masked,
        "estimated_cost_plan": cost_plan,
        "estimated_cost_ideal_visible_compaction": cost_ideal,
        "N_dist_masked": n_valid,
        "N_dist_plan": sum(r.estimated_distance_count for r in plan.regions),
        "N_dist_ideal": plan.N_vis,
    }


def _expected_region_type(
    region: ProofRegion,
    candidates: list[CandidateRecord],
    vis_map: dict[int, int],
) -> RegionType:
    valid_indices = [i for i in region.candidate_indices if candidates[i].valid]
    visibilities = [vis_map[i] for i in valid_indices]
    return _classify_region_type(visibilities, valid_count=len(valid_indices))


def validate_proof_plan(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    plan: ProofPlan,
    *,
    require_topk_equivalence: bool = True,
    top_k: int = 1,
    d_max: int = DEFAULT_D_MAX,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
) -> PlanValidationResult:
    """
    Validate coverage, disjointness, purity correctness, and optional top-k eq.

    Region types must match committed auth visibility; prover cannot self-declare
    pure_invisible on a region containing visible valid slots.
    """
    errors: list[str] = []
    n = len(candidates)
    vis_map = _visibility_map(candidates, user, checkpoint)

    covered_valid: list[int] = []
    all_covered: set[int] = set()
    for region in plan.regions:
        for idx in region.candidate_indices:
            if idx in all_covered:
                errors.append(
                    f"duplicate coverage: index {idx} in region {region.region_id}"
                )
            all_covered.add(idx)
            if candidates[idx].valid:
                covered_valid.append(idx)

        expected = _expected_region_type(region, candidates, vis_map)
        if region.region_type != expected:
            errors.append(
                f"region {region.region_id} ({region.region_key}): "
                f"claimed {region.region_type}, expected {expected} from auth state"
            )

        if region.region_type == "pure_visible":
            for idx in region.candidate_indices:
                if candidates[idx].valid and vis_map[idx] != 1:
                    errors.append(
                        f"pure_visible region {region.region_id} contains "
                        f"invisible valid slot index={idx} cid={candidates[idx].cid}"
                    )
        elif region.region_type == "pure_invisible":
            for idx in region.candidate_indices:
                if candidates[idx].valid and vis_map[idx] != 0:
                    errors.append(
                        f"pure_invisible region {region.region_id} contains "
                        f"visible valid slot index={idx} cid={candidates[idx].cid}"
                    )

    if len(covered_valid) != len(set(covered_valid)):
        errors.append("valid candidate covered more than once")

    valid_indices = {i for i, c in enumerate(candidates) if c.valid}
    missing_valid = valid_indices - set(covered_valid)
    if missing_valid:
        errors.append(
            f"missing valid candidate coverage: indices {sorted(missing_valid)}"
        )

    missing_all = set(range(n)) - all_covered
    if missing_all:
        errors.append(f"missing slot coverage: indices {sorted(missing_all)}")

    if require_topk_equivalence and not errors:
        cmp = compare_planned_vs_masked_reference(
            candidates,
            user,
            checkpoint,
            plan,
            top_k,
            d_max=d_max,
            n_probe=n_probe,
            slots_per_list=slots_per_list,
        )
        if not cmp["equivalent"]:
            errors.append("planned top-k / distances not equivalent to masked baseline")

    return PlanValidationResult(valid=len(errors) == 0, errors=errors)


def compare_planned_vs_masked_reference(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    plan: ProofPlan,
    top_k: int,
    *,
    d_max: int = DEFAULT_D_MAX,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
) -> dict[str, object]:
    """Compare planned execution against masked-distance baseline."""
    masked = run_authorized_reference(
        candidates,
        user,
        checkpoint,
        top_k,
        d_max=d_max,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    planned = run_authorized_reference_planned(
        candidates,
        user,
        checkpoint,
        plan,
        top_k,
        d_max=d_max,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )

    top_k_match = masked.top_k_cids == planned.top_k_cids
    masked_distance_match = all(
        m.masked_distance == p.masked_distance
        for m, p in zip(masked.scored, planned.scored, strict=True)
    )
    visibility_match = all(
        m.visibility == p.visibility
        for m, p in zip(masked.scored, planned.scored, strict=True)
    )
    hat_distance_match = all(
        m.hat_distance == p.hat_distance
        for m, p in zip(masked.scored, planned.scored, strict=True)
    )

    return {
        "equivalent": (
            top_k_match and masked_distance_match and visibility_match and hat_distance_match
        ),
        "top_k_match": top_k_match,
        "masked_distance_match": masked_distance_match,
        "visibility_match": visibility_match,
        "hat_distance_match": hat_distance_match,
        "masked_top_k": masked.top_k_cids,
        "planned_top_k": planned.top_k_cids,
        "plan": plan,
        "metrics": {
            "N_slots": plan.N_slots,
            "N_valid": plan.N_valid,
            "N_vis": plan.N_vis,
            "N_invis": plan.N_invis,
            "N_dist_plan": plan.N_dist_plan,
            "N_dist_masked": plan.N_dist_masked,
            "estimated_cost_plan": plan.estimated_cost_plan,
            "estimated_cost_masked": plan.estimated_cost_masked,
        },
    }


def build_and_compare_proof_plan(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
    *,
    grouping_strategy: GroupingStrategy = "acl_class",
    block_size: int = 16,
    bindings: dict[int, ObjectClassBinding] | None = None,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
) -> dict[str, object]:
    """Convenience: build plan, validate, and compare to masked baseline."""
    plan = build_proof_plan(
        candidates,
        user,
        checkpoint,
        grouping_strategy=grouping_strategy,
        block_size=block_size,
        bindings=bindings,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    validation = validate_proof_plan(
        candidates,
        user,
        checkpoint,
        plan,
        top_k=top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    comparison = compare_planned_vs_masked_reference(
        candidates,
        user,
        checkpoint,
        plan,
        top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    return {
        "plan": plan,
        "validation": validation,
        "comparison": comparison,
    }
