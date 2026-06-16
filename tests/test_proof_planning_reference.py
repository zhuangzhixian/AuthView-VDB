"""Tests for access-aware proof planning plaintext reference (Phase 6B-1)."""

from __future__ import annotations

import copy

import pytest

from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    build_acl_fixtures_from_candidates,
)
from auth_reference.attacks import DEFAULT_CHECKPOINT, DEFAULT_USER, build_compliant_candidates
from auth_reference.proof_planning_reference import (
    ProofPlan,
    ProofRegion,
    build_and_compare_proof_plan,
    build_proof_plan,
    compare_planned_vs_masked_reference,
    estimate_proof_plan_cost,
    run_authorized_reference_planned,
    validate_proof_plan,
)
from auth_reference.records import AuthLabel, CandidateRecord
from auth_reference.reference import DEFAULT_D_MAX, run_authorized_reference


def _label(
    cid: int,
    *,
    tenant: str = "acme",
    project: str = "proj-a",
    level: int = 2,
    epoch: int = 1,
) -> AuthLabel:
    return AuthLabel(
        tenant=tenant,
        project=project,
        level=level,
        state="active",
        epoch=epoch,
    )


def _candidate(
    cid: int,
    list_id: int,
    slot_id: int,
    distance: int,
    *,
    valid: bool = True,
    label: AuthLabel | None = None,
) -> CandidateRecord:
    return CandidateRecord(
        cid=cid,
        list_id=list_id,
        slot_id=slot_id,
        valid=valid,
        distance=distance,
        label=label or _label(cid),
    )


def _class(class_id: int, *, tenant_id: int = 1, clearance: int = 2) -> ACLClassLabel:
    return ACLClassLabel(
        acl_class_id=class_id,
        tenant_id=tenant_id,
        project_id=10,
        required_clearance=clearance,
        epoch=DEFAULT_CHECKPOINT.epoch,
    )


def build_three_region_acl_fixture() -> tuple[list[CandidateRecord], dict[int, ObjectClassBinding], dict[int, ACLClassLabel]]:
    """
    Deterministic fixture with pure_visible, pure_invisible, and impure ACL classes.

    Class 1: all visible (tenant acme, level 2)
    Class 2: all invisible (tenant other)
    Class 3: mixed visibility (one visible + one invisible object)
    """
    candidates = [
        _candidate(1001, 0, 0, 10, label=_label(1001, level=2)),
        _candidate(1002, 0, 1, 20, label=_label(1002, level=2)),
        _candidate(1003, 0, 2, 30, label=_label(1003, tenant="other")),
        _candidate(1004, 1, 0, 5, label=_label(1004, tenant="other")),
        _candidate(1005, 1, 1, 15, label=_label(1005, level=2)),
        _candidate(1006, 1, 2, 25, label=_label(1006, tenant="other")),
    ]
    bindings = {
        1001: ObjectClassBinding(1001, acl_class_id=1),
        1002: ObjectClassBinding(1002, acl_class_id=1),
        1003: ObjectClassBinding(1003, acl_class_id=2),
        1004: ObjectClassBinding(1004, acl_class_id=2),
        1005: ObjectClassBinding(1005, acl_class_id=3),
        1006: ObjectClassBinding(1006, acl_class_id=3),
    }
    class_labels = {
        1: _class(1, tenant_id=1, clearance=2),
        2: _class(2, tenant_id=2, clearance=1),
        3: _class(3, tenant_id=1, clearance=2),
    }
    return candidates, bindings, class_labels


def build_all_visible_fixture() -> list[CandidateRecord]:
    return [
        _candidate(2001, 0, 0, 10),
        _candidate(2002, 0, 1, 20),
        _candidate(2003, 1, 0, 15),
        _candidate(2004, 1, 1, 25),
    ]


def build_all_invisible_fixture() -> list[CandidateRecord]:
    return [
        _candidate(3001, 0, 0, 5, label=_label(3001, tenant="other")),
        _candidate(3002, 0, 1, 8, label=_label(3002, tenant="other")),
        _candidate(3003, 1, 0, 12, label=_label(3003, tenant="other")),
        _candidate(3004, 1, 1, 18, label=_label(3004, tenant="other")),
    ]


def build_ivf_mixed_fixture() -> list[CandidateRecord]:
    """List 0 pure_visible; list 1 pure_invisible; list 2 impure."""
    return [
        _candidate(4001, 0, 0, 10, label=_label(4001, level=2)),
        _candidate(4002, 0, 1, 12, label=_label(4002, level=2)),
        _candidate(4003, 1, 0, 5, label=_label(4003, tenant="other")),
        _candidate(4004, 1, 1, 7, label=_label(4004, tenant="other")),
        _candidate(4005, 2, 0, 8, label=_label(4005, level=2)),
        _candidate(4006, 2, 1, 9, label=_label(4006, tenant="other")),
    ]


# --- PP-* grouping ---


def test_pp01_acl_class_grouping_produces_three_region_types():
    """PP-01: ACL-class grouping yields pure_visible, pure_invisible, impure."""
    candidates, bindings, class_labels = build_three_region_acl_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="acl_class",
        bindings=bindings,
        n_probe=2,
        slots_per_list=3,
    )
    types = {r.region_type for r in plan.regions}
    assert "pure_visible" in types
    assert "pure_invisible" in types
    assert "impure" in types
    assert plan.N_pure_visible_regions >= 1
    assert plan.N_pure_invisible_regions >= 1
    assert plan.N_impure_regions >= 1


def test_pp02_ivf_list_grouping_covers_all_valid_candidates():
    """PP-02: IVF-list grouping covers every valid candidate exactly once."""
    candidates = build_ivf_mixed_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=3,
        slots_per_list=2,
    )
    covered = set()
    for region in plan.regions:
        for idx in region.candidate_indices:
            assert idx not in covered
            covered.add(idx)
    assert covered == set(range(len(candidates)))
    validation = validate_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=2,
        n_probe=3,
        slots_per_list=2,
    )
    assert validation.valid is True


def test_pp03_fixed_block_grouping_covers_all_valid_candidates():
    """PP-03: fixed-block grouping covers all slots."""
    candidates = build_compliant_candidates()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="fixed_block",
        block_size=2,
        n_probe=2,
        slots_per_list=3,
    )
    covered = set()
    for region in plan.regions:
        covered.update(region.candidate_indices)
    assert covered == set(range(len(candidates)))
    validation = validate_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert validation.valid is True


# --- PV-* / PI-* / IM-* semantics ---


def test_pv01_pure_visible_region_topk_equals_masked():
    """PV-01: pure_visible region planned top-k matches masked baseline."""
    candidates = build_all_visible_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=2,
    )
    assert all(r.region_type == "pure_visible" for r in plan.regions)
    cmp = compare_planned_vs_masked_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=2,
        n_probe=2,
        slots_per_list=2,
    )
    assert cmp["equivalent"] is True


def test_pi01_pure_invisible_skips_distance_and_equivalent():
    """PI-01: pure_invisible regions assign d_max; top-k still equivalent."""
    candidates = build_all_invisible_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=2,
    )
    assert all(r.region_type == "pure_invisible" for r in plan.regions)
    assert plan.N_dist_plan == 0
    result = run_authorized_reference_planned(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=2,
        n_probe=2,
        slots_per_list=2,
    )
    for s in result.scored:
        if s.valid:
            assert s.hat_distance == DEFAULT_D_MAX
    cmp = compare_planned_vs_masked_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=2,
        n_probe=2,
        slots_per_list=2,
    )
    assert cmp["equivalent"] is True


def test_im01_impure_region_fallback_masked_semantics():
    """IM-01: impure region uses per-slot masked distance; top-k equivalent."""
    candidates, bindings, _ = build_three_region_acl_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="acl_class",
        bindings=bindings,
        n_probe=2,
        slots_per_list=3,
    )
    impure = [r for r in plan.regions if r.region_type == "impure"]
    assert len(impure) == 1
    cmp = compare_planned_vs_masked_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert cmp["equivalent"] is True


# --- COV-* coverage ---


def test_cov01_missing_candidate_coverage_validation_fails():
    """COV-01: dropping a valid candidate from plan fails validation."""
    candidates = build_compliant_candidates()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=3,
    )
    trimmed_regions = []
    for region in plan.regions:
        kept = tuple(i for i in region.candidate_indices if candidates[i].cid != 101)
        if kept:
            trimmed_regions.append(
                ProofRegion(
                    region_id=region.region_id,
                    region_type=region.region_type,
                    region_key=region.region_key,
                    grouping_strategy=region.grouping_strategy,
                    candidate_indices=kept,
                    valid_count=sum(1 for i in kept if candidates[i].valid),
                    visible_count=region.visible_count,
                    invisible_count=region.invisible_count,
                    estimated_distance_count=region.estimated_distance_count,
                    estimated_visibility_count=region.estimated_visibility_count,
                )
            )
    bad_plan = ProofPlan(
        regions=trimmed_regions,
        grouping_strategy=plan.grouping_strategy,
        N_slots=plan.N_slots,
        N_valid=plan.N_valid - 1,
        N_vis=plan.N_vis,
        N_invis=plan.N_invis,
        N_pure_visible_regions=plan.N_pure_visible_regions,
        N_pure_invisible_regions=plan.N_pure_invisible_regions,
        N_impure_regions=plan.N_impure_regions,
        pure_region_ratio=plan.pure_region_ratio,
        impure_region_ratio=plan.impure_region_ratio,
        visible_ratio=plan.visible_ratio,
        estimated_cost_masked=plan.estimated_cost_masked,
        estimated_cost_plan=plan.estimated_cost_plan,
        estimated_cost_ideal_visible_compaction=plan.estimated_cost_ideal_visible_compaction,
        N_dist_masked=plan.N_dist_masked,
        N_dist_plan=plan.N_dist_plan,
        N_dist_ideal=plan.N_dist_ideal,
    )
    result = validate_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        bad_plan,
        require_topk_equivalence=False,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert result.valid is False
    assert any("missing valid candidate coverage" in e for e in result.errors)


def test_cov02_duplicate_candidate_coverage_validation_fails():
    """COV-02: duplicate index in two regions fails validation."""
    candidates = build_compliant_candidates()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=3,
    )
    dup = copy.deepcopy(plan)
    dup.regions[0] = ProofRegion(
        region_id=99,
        region_type="impure",
        region_key="dup",
        grouping_strategy="ivf_list",
        candidate_indices=(0,) + dup.regions[0].candidate_indices,
        valid_count=1,
        visible_count=1,
        invisible_count=0,
        estimated_distance_count=1,
        estimated_visibility_count=1,
    )
    result = validate_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        dup,
        require_topk_equivalence=False,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert result.valid is False
    assert any("duplicate coverage" in e for e in result.errors)


# --- AT-* attack / purity tampering ---


def test_at01_false_pure_invisible_tamper_fails_validation():
    """AT-01: declaring visible region pure_invisible fails validation."""
    candidates, bindings, _ = build_three_region_acl_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="acl_class",
        bindings=bindings,
        n_probe=2,
        slots_per_list=3,
    )
    tampered = copy.deepcopy(plan)
    for i, region in enumerate(tampered.regions):
        if region.region_type == "impure":
            tampered.regions[i] = ProofRegion(
                region_id=region.region_id,
                region_type="pure_invisible",
                region_key=region.region_key,
                grouping_strategy=region.grouping_strategy,
                candidate_indices=region.candidate_indices,
                valid_count=region.valid_count,
                visible_count=region.visible_count,
                invisible_count=region.invisible_count,
                estimated_distance_count=0,
                estimated_visibility_count=0,
            )
            break
    else:
        pytest.fail("expected impure region in fixture")

    result = validate_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        tampered,
        require_topk_equivalence=False,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert result.valid is False
    assert any("pure_invisible" in e or "expected impure" in e for e in result.errors)


def test_at02_false_pure_visible_tamper_fails_validation():
    """AT-02: declaring invisible region pure_visible fails validation."""
    candidates, bindings, _ = build_three_region_acl_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="acl_class",
        bindings=bindings,
        n_probe=2,
        slots_per_list=3,
    )
    tampered = copy.deepcopy(plan)
    for i, region in enumerate(tampered.regions):
        if region.region_type == "pure_invisible":
            tampered.regions[i] = ProofRegion(
                region_id=region.region_id,
                region_type="pure_visible",
                region_key=region.region_key,
                grouping_strategy=region.grouping_strategy,
                candidate_indices=region.candidate_indices,
                valid_count=region.valid_count,
                visible_count=region.visible_count,
                invisible_count=region.invisible_count,
                estimated_distance_count=region.valid_count,
                estimated_visibility_count=0,
            )
            break
    else:
        pytest.fail("expected pure_invisible region in fixture")

    result = validate_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        tampered,
        require_topk_equivalence=False,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert result.valid is False


# --- CM-* cost model ---


def test_cm01_pure_invisible_increase_lowers_n_dist_plan():
    """CM-01: more pure_invisible area lowers N_dist_plan."""
    visible = build_all_visible_fixture()
    invisible = build_all_invisible_fixture()
    plan_vis = build_proof_plan(
        visible,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=2,
    )
    plan_invis = build_proof_plan(
        invisible,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=2,
    )
    assert plan_invis.N_dist_plan < plan_vis.N_dist_plan
    assert plan_invis.N_dist_plan == 0
    assert plan_vis.N_dist_plan == plan_vis.N_valid


def test_cm02_all_visible_plan_does_not_reduce_distance_count():
    """CM-02: all-visible workload still computes distance for all valid slots."""
    candidates = build_all_visible_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=2,
    )
    assert plan.N_dist_plan == plan.N_dist_masked == plan.N_valid


def test_cm03_all_invisible_plan_distance_count_zero():
    """CM-03: all-invisible workload has N_dist_plan = 0."""
    candidates = build_all_invisible_fixture()
    plan = build_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        grouping_strategy="ivf_list",
        n_probe=2,
        slots_per_list=2,
    )
    assert plan.N_dist_plan == 0
    costs = estimate_proof_plan_cost(plan)
    assert costs["N_dist_plan"] == 0


# --- EQ-* / DEG-* equivalence ---


def test_eq01_planned_topk_cids_match_masked_baseline():
    """EQ-01: planned top-k cids identical to masked baseline on mixed fixture."""
    candidates, bindings, _ = build_three_region_acl_fixture()
    out = build_and_compare_proof_plan(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        grouping_strategy="acl_class",
        bindings=bindings,
        n_probe=2,
        slots_per_list=3,
    )
    assert out["validation"].valid is True
    assert out["comparison"]["equivalent"] is True
    masked = run_authorized_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert out["comparison"]["planned_top_k"] == masked.top_k_cids


def test_deg01_all_impure_degenerates_to_masked_baseline():
    """DEG-01: per-slot impure regions match masked baseline."""
    candidates = build_compliant_candidates()
    vis_map = {
        i: 1
        for i, c in enumerate(candidates)
        if c.valid and c.label.tenant == "acme"
    }
    for i, c in enumerate(candidates):
        if c.valid and c.label.tenant != "acme":
            vis_map[i] = 0

    impure_regions = []
    for idx, c in enumerate(candidates):
        v = vis_map.get(idx, 0)
        impure_regions.append(
            ProofRegion(
                region_id=idx,
                region_type="impure",
                region_key=f"slot-{idx}",
                grouping_strategy="fixed_block",
                candidate_indices=(idx,),
                valid_count=1 if c.valid else 0,
                visible_count=1 if c.valid and v else 0,
                invisible_count=1 if c.valid and not v else 0,
                estimated_distance_count=1 if c.valid else 0,
                estimated_visibility_count=1 if c.valid else 0,
            )
        )
    n_valid = sum(1 for c in candidates if c.valid)
    n_vis = sum(
        1
        for i, c in enumerate(candidates)
        if c.valid and vis_map.get(i, 0) == 1
    )
    plan = ProofPlan(
        regions=impure_regions,
        grouping_strategy="fixed_block",
        N_slots=len(candidates),
        N_valid=n_valid,
        N_vis=n_vis,
        N_invis=n_valid - n_vis,
        N_pure_visible_regions=0,
        N_pure_invisible_regions=0,
        N_impure_regions=len(impure_regions),
        pure_region_ratio=0.0,
        impure_region_ratio=1.0,
        visible_ratio=n_vis / n_valid if n_valid else 0.0,
        estimated_cost_masked=0,
        estimated_cost_plan=0,
        estimated_cost_ideal_visible_compaction=0,
        N_dist_masked=n_valid,
        N_dist_plan=n_valid,
        N_dist_ideal=n_vis,
    )
    costs = estimate_proof_plan_cost(plan)
    plan.estimated_cost_masked = costs["estimated_cost_masked"]
    plan.estimated_cost_plan = costs["estimated_cost_plan"]
    plan.estimated_cost_ideal_visible_compaction = costs[
        "estimated_cost_ideal_visible_compaction"
    ]

    cmp = compare_planned_vs_masked_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        plan,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert cmp["equivalent"] is True
    assert plan.estimated_cost_plan >= plan.estimated_cost_masked


def test_compliant_fixture_all_grouping_strategies_equivalent():
    """Regression: compliant candidates equivalent under all grouping strategies."""
    candidates = build_compliant_candidates()
    bindings, _ = build_acl_fixtures_from_candidates(candidates)
    for strategy in ("acl_class", "ivf_list", "fixed_block"):
        out = build_and_compare_proof_plan(
            candidates,
            DEFAULT_USER,
            DEFAULT_CHECKPOINT,
            top_k=3,
            grouping_strategy=strategy,
            bindings=bindings,
            block_size=2,
            n_probe=2,
            slots_per_list=3,
        )
        assert out["validation"].valid is True, strategy
        assert out["comparison"]["equivalent"] is True, strategy
