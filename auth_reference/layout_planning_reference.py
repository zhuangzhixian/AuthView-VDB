"""Access-aware physical layout planning for proof-planning evaluation (Phase 6B-2.10).

Access-signature workload + layout-specific SA/PA cost-model units.
Plaintext only — not measured ZK gate counts.
"""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from auth_reference.attacks import DEFAULT_CHECKPOINT
from auth_reference.proof_planning_reference import (
    DEFAULT_COST_PARAMS,
    ProofPlan,
    ProofRegion,
    _make_region,
    _visibility_map,
    compare_planned_vs_masked_reference,
    estimate_proof_plan_cost,
    validate_proof_plan,
)
from auth_reference.records import AuthLabel, CandidateRecord, Checkpoint, UserContext

PhysicalLayout = Literal[
    "global",
    "acl_signature",
    "merged_k",
    "oracle_authorized_view",
]

# Legacy alias
PhysicalLayoutLegacy = Literal["acl_class"]

DEFAULT_SA_PARAMS: dict[str, float] = {
    "C_global_metadata": 0.02,
    "C_region_metadata": 24.0,
    "C_signature_table_entry": 4.0,
    "C_role_view_membership": 1.0,
    "C_role_view_header": 8.0,
}


@dataclass(frozen=True)
class AccessSignatureConfig:
    num_objects: int
    num_roles: int
    num_signatures: int
    seed: int = 0
    zipf_skew: float = 1.5
    min_sig_popcount: int = 1
    max_sig_popcount: int | None = None


@dataclass
class AccessSignatureWorkload:
    """Generated access-signature corpus + grid placement."""

    config: AccessSignatureConfig
    candidates: list[CandidateRecord]
    object_signatures: dict[int, int]
    signature_ids: list[int]
    signature_to_mask: dict[int, int]
    n_lists: int
    slot_per_list: int
    total_memberships: int
    effective_selectivity: float = 0.0

    def user_for_query_role(self, query_role: int) -> UserContext:
        return build_user_for_query_role(query_role)

    def effective_selectivity_for_role(self, query_role: int) -> float:
        n_vis = sum(
            1
            for c in self.candidates
            if c.valid and object_visible_for_role(self.object_signatures[c.cid], query_role)
        )
        n_valid = sum(1 for c in self.candidates if c.valid)
        return n_vis / n_valid if n_valid else 0.0


@dataclass
class LayoutEvalResult:
    physical_layout: PhysicalLayout
    plan: ProofPlan
    SA_commit: float
    PA_plan: float
    PA_ideal: float
    plan_vs_masked_cost: float
    ideal_vs_masked_cost: float
    dist_reduction_plan: float
    pure_visible_region_ratio: float
    pure_invisible_region_ratio: float
    impure_region_ratio: float
    pure_visible_valid_ratio: float
    pure_invisible_valid_ratio: float
    impure_valid_ratio: float
    estimated_region_cost: int
    estimated_visibility_cost: int
    estimated_distance_cost: int
    estimated_mask_topk_cost: int
    num_regions: int
    num_signatures: int
    merged_k: int
    query_role: int
    total_memberships: int
    stored_entries_norm: float
    effective_selectivity: float
    planned_equals_masked: bool
    validation_passed: bool


def object_visible_for_role(signature_mask: int, query_role: int) -> bool:
    return bool((signature_mask >> query_role) & 1)


def build_user_for_query_role(query_role: int) -> UserContext:
    """Query user holding exactly one role bit."""
    return UserContext(
        user_id=f"query-role-{query_role}",
        tenant="acme",
        projects=frozenset({"proj-a"}),
        clearance=100,
        roles=frozenset({f"sig-role-{query_role}"}),
        epoch=DEFAULT_CHECKPOINT.epoch,
    )


def _signature_to_label(signature_mask: int, num_roles: int) -> AuthLabel:
    if signature_mask == 0:
        return AuthLabel(
            tenant="acme",
            project="proj-a",
            level=999,
            state="active",
            epoch=DEFAULT_CHECKPOINT.epoch,
            roles=frozenset({"__never__"}),
        )
    role_tags = frozenset(
        f"sig-role-{i}"
        for i in range(num_roles)
        if object_visible_for_role(signature_mask, i)
    )
    return AuthLabel(
        tenant="acme",
        project="proj-a",
        level=1,
        state="active",
        epoch=DEFAULT_CHECKPOINT.epoch,
        roles=role_tags,
    )


def _random_signature_mask(
    rng: random.Random,
    num_roles: int,
    *,
    min_pop: int,
    max_pop: int,
    used: set[int],
) -> int:
    for _ in range(500):
        pop = rng.randint(min_pop, max_pop)
        bits = rng.sample(range(num_roles), pop)
        mask = sum(1 << b for b in bits)
        if mask not in used:
            used.add(mask)
            return mask
    raise RuntimeError("failed to generate distinct signature mask")


def build_access_signature_workload(
    config: AccessSignatureConfig,
    *,
    n_lists: int | None = None,
    slot_per_list: int | None = None,
) -> AccessSignatureWorkload:
    """
    Build synthetic corpus where each object has an access signature (role bitset).

    Objects sharing a signature are ACL-pure for any single-role query.
    """
    if config.num_roles <= 0 or config.num_signatures <= 0:
        raise ValueError("num_roles and num_signatures must be positive")
    if config.num_objects <= 0:
        raise ValueError("num_objects must be positive")

    max_pop = config.max_sig_popcount or max(1, config.num_roles // 2)
    max_pop = min(max_pop, config.num_roles)
    min_pop = min(config.min_sig_popcount, max_pop)

    rng = random.Random(config.seed)
    used_masks: set[int] = set()
    signature_to_mask: dict[int, int] = {}
    for sig_id in range(config.num_signatures):
        signature_to_mask[sig_id] = _random_signature_mask(
            rng,
            config.num_roles,
            min_pop=min_pop,
            max_pop=max_pop,
            used=used_masks,
        )

    if n_lists is None:
        n_lists = max(1, int(config.num_objects**0.5))
    while n_lists * (slot_per_list or 64) < config.num_objects:
        n_lists *= 2
    if slot_per_list is None:
        slot_per_list = (config.num_objects + n_lists - 1) // n_lists

    weights = [1.0 / ((i + 1) ** config.zipf_skew) for i in range(config.num_signatures)]
    sig_assign = rng.choices(
        list(range(config.num_signatures)), weights=weights, k=config.num_objects
    )

    candidates: list[CandidateRecord] = []
    object_signatures: dict[int, int] = {}
    valid_idx = 0
    for lid in range(n_lists):
        for sid in range(slot_per_list):
            flat = lid * slot_per_list + sid
            cid = 10_000 + flat
            is_valid = valid_idx < config.num_objects
            if is_valid:
                sig_id = sig_assign[valid_idx]
                mask = signature_to_mask[sig_id]
                object_signatures[cid] = mask
                label = _signature_to_label(mask, config.num_roles)
                valid_idx += 1
            else:
                label = AuthLabel(
                    tenant="other",
                    project="proj-a",
                    level=99,
                    state="active",
                    epoch=DEFAULT_CHECKPOINT.epoch,
                )
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

    total_memberships = sum(
        bin(mask).count("1")
        for mask in object_signatures.values()
    )

    return AccessSignatureWorkload(
        config=config,
        candidates=candidates,
        object_signatures=object_signatures,
        signature_ids=list(range(config.num_signatures)),
        signature_to_mask=signature_to_mask,
        n_lists=n_lists,
        slot_per_list=slot_per_list,
        total_memberships=total_memberships,
    )


def _cid_to_index(candidates: list[CandidateRecord]) -> dict[int, int]:
    return {c.cid: i for i, c in enumerate(candidates)}


def _group_by_signature(workload: AccessSignatureWorkload) -> dict[str, list[int]]:
    cid_to_idx = _cid_to_index(workload.candidates)
    sig_to_indices: dict[int, list[int]] = defaultdict(list)
    for c in workload.candidates:
        if not c.valid:
            continue
        mask = workload.object_signatures[c.cid]
        sig_to_indices[mask].append(cid_to_idx[c.cid])
    width = max(1, (workload.config.num_roles + 3) // 4)
    return {
        f"sig-{mask:0{width}x}": idxs
        for mask, idxs in sorted(sig_to_indices.items())
    }


def _group_global(candidates: list[CandidateRecord]) -> dict[str, list[int]]:
    return {"global": list(range(len(candidates)))}


def _group_merged_k(
    workload: AccessSignatureWorkload,
    merged_k: int,
) -> dict[str, list[int]]:
    """Merge k similar signatures (sorted by mask integer) into one region."""
    if merged_k <= 0:
        raise ValueError("merged_k must be positive")
    sig_groups = _group_by_signature(workload)
    keys = sorted(sig_groups.keys(), key=lambda k: int(k.split("-")[1], 16))
    groups: dict[str, list[int]] = {}
    for start in range(0, len(keys), merged_k):
        chunk = keys[start : start + merged_k]
        indices: list[int] = []
        for key in chunk:
            indices.extend(sig_groups[key])
        groups[f"merged-{start // merged_k}"] = indices
    invalid = [i for i, c in enumerate(workload.candidates) if not c.valid]
    if invalid:
        groups["invalid-padding"] = invalid
    return groups


def _group_oracle(
    candidates: list[CandidateRecord],
    vis_map: dict[int, int],
) -> dict[str, list[int]]:
    visible: list[int] = []
    invisible: list[int] = []
    invalid: list[int] = []
    for idx, c in enumerate(candidates):
        if not c.valid:
            invalid.append(idx)
        elif vis_map[idx] == 1:
            visible.append(idx)
        else:
            invisible.append(idx)
    groups: dict[str, list[int]] = {}
    if visible:
        groups["oracle-visible"] = visible
    if invisible:
        groups["oracle-invisible"] = invisible
    if invalid:
        groups["oracle-invalid"] = invalid
    return groups


def _build_plan_from_groups(
    candidates: list[CandidateRecord],
    groups: dict[str, list[int]],
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    grouping_strategy: str,
) -> ProofPlan:
    vis_map = _visibility_map(candidates, user, checkpoint)
    regions: list[ProofRegion] = []
    for region_id, (region_key, indices) in enumerate(sorted(groups.items())):
        if not indices:
            continue
        regions.append(
            _make_region(
                region_id,
                region_key,
                grouping_strategy,  # type: ignore[arg-type]
                indices,
                candidates,
                vis_map,
            )
        )

    n_slots = len(candidates)
    n_valid = sum(1 for c in candidates if c.valid)
    n_vis = sum(
        1 for i, c in enumerate(candidates) if c.valid and vis_map[i] == 1
    )
    n_invis = n_valid - n_vis
    n_pv = sum(1 for r in regions if r.region_type == "pure_visible")
    n_pi = sum(1 for r in regions if r.region_type == "pure_invisible")
    n_imp = sum(1 for r in regions if r.region_type == "impure")
    n_regions = len(regions)

    plan = ProofPlan(
        regions=regions,
        grouping_strategy=grouping_strategy,  # type: ignore[arg-type]
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
        N_dist_masked=0,
        N_dist_plan=0,
        N_dist_ideal=0,
    )
    costs = estimate_proof_plan_cost(plan)
    plan.estimated_cost_masked = costs["estimated_cost_masked"]
    plan.estimated_cost_plan = costs["estimated_cost_plan"]
    plan.estimated_cost_ideal_visible_compaction = costs[
        "estimated_cost_ideal_visible_compaction"
    ]
    plan.N_dist_masked = costs["N_dist_masked"]
    plan.N_dist_plan = costs["N_dist_plan"]
    plan.N_dist_ideal = costs["N_dist_ideal"]
    return plan


def build_layout_proof_plan(
    physical_layout: PhysicalLayout,
    workload: AccessSignatureWorkload,
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    merged_k: int = 1,
) -> ProofPlan:
    candidates = workload.candidates
    if physical_layout == "global":
        groups = _group_global(candidates)
        return _build_plan_from_groups(
            candidates, groups, user, checkpoint, grouping_strategy="fixed_block"
        )
    if physical_layout == "acl_signature":
        groups = _group_by_signature(workload)
        invalid = [i for i, c in enumerate(candidates) if not c.valid]
        if invalid:
            groups["invalid-padding"] = invalid
        return _build_plan_from_groups(
            candidates, groups, user, checkpoint, grouping_strategy="acl_class"
        )
    if physical_layout == "merged_k":
        groups = _group_merged_k(workload, merged_k)
        return _build_plan_from_groups(
            candidates, groups, user, checkpoint, grouping_strategy="ivf_list"
        )
    if physical_layout == "oracle_authorized_view":
        vis_map = _visibility_map(candidates, user, checkpoint)
        groups = _group_oracle(candidates, vis_map)
        return _build_plan_from_groups(
            candidates, groups, user, checkpoint, grouping_strategy="acl_class"
        )
    raise ValueError(f"unknown physical_layout: {physical_layout}")


def estimate_sa_commitment(
    physical_layout: PhysicalLayout,
    *,
    num_objects: int,
    num_regions: int,
    num_signatures: int,
    num_roles: int,
    total_memberships: int,
    sa_params: dict[str, float] | None = None,
) -> tuple[float, float]:
    """
    Storage / commitment amplification and normalized stored entries.

    Returns (SA_commit, stored_entries_norm).
    """
    p = {**DEFAULT_SA_PARAMS, **(sa_params or {})}
    n = max(1, num_objects)
    base = 1.0

    if physical_layout == "global":
        stored = 1.0
        sa = base + p["C_global_metadata"]
        return sa, stored

    if physical_layout == "acl_signature":
        stored = 1.0 + p["C_signature_table_entry"] * (num_signatures / n)
        region_term = p["C_region_metadata"] * num_regions / n
        return base + stored - 1.0 + region_term, stored

    if physical_layout == "merged_k":
        stored = 1.0
        region_term = p["C_region_metadata"] * num_regions / n
        return base + region_term, stored

    if physical_layout == "oracle_authorized_view":
        stored = total_memberships / n
        membership_term = p["C_role_view_membership"] * (total_memberships / n - 1.0)
        header_term = p["C_role_view_header"] * num_roles / n
        sa = base + max(0.0, membership_term) + header_term
        return sa, stored

    raise ValueError(f"unknown physical_layout: {physical_layout}")


def _plan_cost_breakdown(plan: ProofPlan, cost_params: dict[str, int]) -> dict[str, int]:
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


def _region_valid_counts(plan: ProofPlan) -> tuple[int, int, int]:
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


def _oracle_authorized_cost(n_vis: int, cost_params: dict[str, int]) -> int:
    c_dist = cost_params["C_dist"]
    c_topk = cost_params["C_topk_per_candidate"]
    return max(1, n_vis) * (c_dist + c_topk)


def evaluate_layout(
    physical_layout: PhysicalLayout,
    workload: AccessSignatureWorkload,
    query_role: int,
    checkpoint: Checkpoint = DEFAULT_CHECKPOINT,
    *,
    merged_k: int = 1,
    top_k: int = 5,
    cost_params: dict[str, int] | None = None,
    sa_params: dict[str, float] | None = None,
) -> LayoutEvalResult:
    """Evaluate one physical layout for a single-role query on signature workload."""
    params = dict(DEFAULT_COST_PARAMS)
    if cost_params:
        params.update(cost_params)

    user = workload.user_for_query_role(query_role)
    plan = build_layout_proof_plan(
        physical_layout,
        workload,
        user,
        checkpoint,
        merged_k=merged_k,
    )
    oracle_ref_plan = build_layout_proof_plan(
        "oracle_authorized_view",
        workload,
        user,
        checkpoint,
    )
    validation = validate_proof_plan(
        workload.candidates,
        user,
        checkpoint,
        plan,
        top_k=top_k,
        n_probe=workload.n_lists,
        slots_per_list=workload.slot_per_list,
    )
    comparison = compare_planned_vs_masked_reference(
        workload.candidates,
        user,
        checkpoint,
        plan,
        top_k,
        n_probe=workload.n_lists,
        slots_per_list=workload.slot_per_list,
    )

    n_regions = len(plan.regions)
    sa, stored_norm = estimate_sa_commitment(
        physical_layout,
        num_objects=plan.N_valid,
        num_regions=n_regions,
        num_signatures=workload.config.num_signatures,
        num_roles=workload.config.num_roles,
        total_memberships=workload.total_memberships,
        sa_params=sa_params,
    )

    pv_valid, pi_valid, imp_valid = _region_valid_counts(plan)
    breakdown = _plan_cost_breakdown(plan, params)
    oracle_denom = max(1, oracle_ref_plan.estimated_cost_plan)
    eff_sel = workload.effective_selectivity_for_role(query_role)

    dist_red = _safe_ratio(
        float(plan.N_dist_masked - plan.N_dist_plan), float(plan.N_dist_masked)
    )
    plan_vs_masked = _safe_ratio(
        float(plan.estimated_cost_plan), float(plan.estimated_cost_masked)
    )
    ideal_vs_masked = _safe_ratio(
        float(plan.estimated_cost_ideal_visible_compaction),
        float(plan.estimated_cost_masked),
    )
    pa_plan = _safe_ratio(float(plan.estimated_cost_plan), float(oracle_denom))
    pa_ideal = _safe_ratio(
        float(plan.estimated_cost_ideal_visible_compaction), float(oracle_denom)
    )

    return LayoutEvalResult(
        physical_layout=physical_layout,
        plan=plan,
        SA_commit=sa,
        PA_plan=pa_plan,
        PA_ideal=pa_ideal,
        plan_vs_masked_cost=plan_vs_masked,
        ideal_vs_masked_cost=ideal_vs_masked,
        dist_reduction_plan=dist_red,
        pure_visible_region_ratio=_safe_ratio(
            float(plan.N_pure_visible_regions), float(n_regions)
        ),
        pure_invisible_region_ratio=_safe_ratio(
            float(plan.N_pure_invisible_regions), float(n_regions)
        ),
        impure_region_ratio=plan.impure_region_ratio,
        pure_visible_valid_ratio=_safe_ratio(float(pv_valid), float(plan.N_valid)),
        pure_invisible_valid_ratio=_safe_ratio(float(pi_valid), float(plan.N_valid)),
        impure_valid_ratio=_safe_ratio(float(imp_valid), float(plan.N_valid)),
        estimated_region_cost=breakdown["estimated_region_cost"],
        estimated_visibility_cost=breakdown["estimated_visibility_cost"],
        estimated_distance_cost=breakdown["estimated_distance_cost"],
        estimated_mask_topk_cost=breakdown["estimated_mask_topk_cost"],
        num_regions=n_regions,
        num_signatures=workload.config.num_signatures,
        merged_k=merged_k if physical_layout == "merged_k" else 0,
        query_role=query_role,
        total_memberships=workload.total_memberships,
        stored_entries_norm=stored_norm,
        effective_selectivity=eff_sel,
        planned_equals_masked=bool(comparison["equivalent"]),
        validation_passed=validation.valid,
    )


# --- Legacy Phase 6B-2.9 API (deprecated) ---


@dataclass(frozen=True)
class RoleCombinationConfig:
    num_roles: int
    selectivity: float
    seed: int = 0


def build_role_combination_workload(*args, **kwargs):
    raise NotImplementedError(
        "Phase 6B-2.9 role-combination workload removed; use build_access_signature_workload"
    )
