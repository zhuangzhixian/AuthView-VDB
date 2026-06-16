"""Tests for ACL-class compression plaintext reference (Phase 5A)."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    acl_class_label_from_auth_label,
    authorized_topk_acl_compressed,
    build_acl_class_view,
    build_acl_fixtures_from_candidates,
    compare_object_level_vs_acl_class_reference,
    count_unique_acl_classes_in_candidates,
    estimate_acl_compression_cost,
    evaluate_acl_class_visibility,
    expand_auth_label_for_cid,
    object_binding_from_label,
    verify_object_class_bindings,
)
from auth_reference.attacks import (
    DEFAULT_CHECKPOINT,
    DEFAULT_USER,
    build_compliant_candidates,
    build_post_filter_contrast_candidates,
)
from auth_reference.policy import evaluate_policy
from auth_reference.records import AuthLabel, CandidateRecord
from auth_reference.reference import DEFAULT_D_MAX, run_authorized_reference


def _candidate(
    cid: int,
    list_id: int,
    slot_id: int,
    distance: int,
    *,
    valid: bool = True,
    tenant: str = "acme",
    project: str = "proj-a",
    level: int = 2,
    epoch: int = 1,
) -> CandidateRecord:
    return CandidateRecord(
        cid=cid,
        list_id=list_id,
        slot_id=slot_id,
        valid=valid,
        distance=distance,
        label=AuthLabel(
            tenant=tenant,
            project=project,
            level=level,
            state="active",
            epoch=epoch,
        ),
    )


def _class(
    class_id: int,
    *,
    tenant_id: int = 1,
    project_id: int = 10,
    clearance: int = 2,
    epoch: int = 1,
    state: str = "active",
) -> ACLClassLabel:
    return ACLClassLabel(
        acl_class_id=class_id,
        tenant_id=tenant_id,
        project_id=project_id,
        required_clearance=clearance,
        state=state,
        epoch=epoch,
    )


def test_acl_class_visibility_evaluation():
    """ACL-class visibility matches policy on expanded AuthLabel."""
    acl = _class(1, clearance=2, epoch=DEFAULT_CHECKPOINT.epoch)
    assert evaluate_acl_class_visibility(DEFAULT_USER, acl, DEFAULT_CHECKPOINT) == 1
    assert evaluate_policy(DEFAULT_USER, acl.to_auth_label(), DEFAULT_CHECKPOINT)

    invisible = _class(2, tenant_id=2, clearance=1, epoch=DEFAULT_CHECKPOINT.epoch)
    assert evaluate_acl_class_visibility(DEFAULT_USER, invisible, DEFAULT_CHECKPOINT) == 0


def test_acl_class_reference_equals_object_level():
    """ACL-class top-k matches object-level reference on compliant fixture."""
    candidates = build_compliant_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)

    cmp = compare_object_level_vs_acl_class_reference(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert cmp["equivalent"] is True
    assert cmp["object_top_k"] == [101, 104, 103]
    assert cmp["acl_top_k"] == [101, 104, 103]


def test_invisible_acl_class_masks_all_objects():
    """All objects bound to invisible class receive d_max."""
    candidates = [
        _candidate(701, 0, 0, 5, level=2),
        _candidate(702, 0, 1, 8, level=2),
        _candidate(703, 0, 2, 12, level=2),
    ]
    bindings = {
        701: ObjectClassBinding(701, acl_class_id=10, epoch=1),
        702: ObjectClassBinding(702, acl_class_id=10, epoch=1),
        703: ObjectClassBinding(703, acl_class_id=10, epoch=1),
    }
    class_labels = {
        10: _class(10, tenant_id=2, clearance=1, epoch=1),
    }

    result = authorized_topk_acl_compressed(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=2,
        n_probe=1,
        slots_per_list=3,
    )
    assert result.view.class_visibility[10] == 0
    assert all(s.visibility == 0 for s in result.scored)
    assert all(s.masked_distance == DEFAULT_D_MAX for s in result.scored)


def test_shared_acl_class_policy_counted_once():
    """Multiple objects share one class; policy evaluated once per class."""
    candidates = [
        _candidate(801, 0, 0, 10),
        _candidate(802, 0, 1, 15),
        _candidate(803, 0, 2, 20),
    ]
    bindings = {
        801: ObjectClassBinding(801, acl_class_id=1, epoch=1),
        802: ObjectClassBinding(802, acl_class_id=1, epoch=1),
        803: ObjectClassBinding(803, acl_class_id=1, epoch=1),
    }
    class_labels = {1: _class(1)}

    view = build_acl_class_view(
        candidates, bindings, class_labels, DEFAULT_USER, DEFAULT_CHECKPOINT
    )
    assert len(view.class_visibility) == 1
    assert count_unique_acl_classes_in_candidates(candidates, bindings) == 1
    assert all(v == 1 for v in view.cid_visibility.values())

    result = authorized_topk_acl_compressed(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=2,
        n_probe=1,
        slots_per_list=3,
    )
    assert result.cost.n_acl == 1
    assert result.cost.n_sel == 3
    assert result.cost.acl_class_policy_evals == 1
    assert result.cost.object_level_policy_evals == 3


def test_mixed_visible_invisible_acl_classes_topk():
    """Mixed classes produce correct authorized top-k."""
    candidates = build_post_filter_contrast_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)

    result = authorized_topk_acl_compressed(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=2,
        n_probe=2,
        slots_per_list=2,
    )
    cmp = compare_object_level_vs_acl_class_reference(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=2,
        n_probe=2,
        slots_per_list=2,
    )
    assert cmp["equivalent"] is True
    assert result.top_k_cids == [203, 204]


def test_forged_binding_detected():
    """Forged object-to-class binding rejected at plaintext validation."""
    candidates = build_compliant_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    committed = dict(bindings)

    forged = dict(bindings)
    first_cid = candidates[0].cid
    forged[first_cid] = ObjectClassBinding(
        first_cid, acl_class_id=999, epoch=1
    )

    with pytest.raises(ValueError, match="forged binding"):
        verify_object_class_bindings(candidates, forged, committed)


def test_stale_class_epoch_invisible():
    """Class epoch mismatch with checkpoint yields invisibility."""
    candidates = [_candidate(901, 0, 0, 10, epoch=1)]
    bindings = {901: ObjectClassBinding(901, acl_class_id=1, epoch=99)}
    class_labels = {1: _class(1, epoch=99)}

    assert evaluate_acl_class_visibility(DEFAULT_USER, class_labels[1], DEFAULT_CHECKPOINT) == 0

    result = authorized_topk_acl_compressed(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=1,
    )
    assert result.scored[0].visibility == 0
    assert result.scored[0].masked_distance == DEFAULT_D_MAX


def test_cost_model_sanity():
    """N_acl <= N_sel and ACL path cheaper when N_acl << N_sel."""
    cost = estimate_acl_compression_cost(n_sel=100, n_acl=10, n_vis=40)
    assert cost.n_acl <= cost.n_sel
    assert cost.estimated_cost_acl_class < cost.estimated_cost_object_level
    assert cost.estimated_policy_eval_saved == 90
    assert cost.acl_ratio == pytest.approx(0.1)
    assert cost.visible_ratio == pytest.approx(0.4)


def test_degenerate_n_acl_equals_n_sel():
    """N_acl = N_sel: no compression benefit, semantics still correct."""
    candidates = build_compliant_candidates()
    bindings = {
        c.cid: ObjectClassBinding(c.cid, acl_class_id=c.cid, epoch=c.label.epoch)
        for c in candidates
    }
    class_labels = {
        c.cid: acl_class_label_from_auth_label(c.cid, c.label) for c in candidates
    }

    cmp = compare_object_level_vs_acl_class_reference(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert cmp["equivalent"] is True
    cost = cmp["cost"]
    assert cost.n_acl == cost.n_sel
    assert cost.estimated_cost_acl_class > cost.estimated_cost_object_level


def test_all_candidates_same_acl_class():
    """N_acl = 1 yields maximum policy-eval savings."""
    candidates = build_compliant_candidates()
    bindings = {
        c.cid: ObjectClassBinding(c.cid, acl_class_id=1, epoch=1) for c in candidates
    }
    class_labels = {1: _class(1, clearance=2, epoch=1)}

    result = authorized_topk_acl_compressed(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    cmp = compare_object_level_vs_acl_class_reference(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert cmp["equivalent"] is True
    assert result.cost.n_acl == 1
    assert result.cost.n_sel == len([c for c in candidates if c.valid])
    assert result.cost.estimated_policy_eval_saved == result.cost.n_sel - 1


def test_expand_label_policy_equivalent_to_object_label():
    """Expanded label from binding is policy-equivalent to original object label."""
    from auth_reference.acl_class import TENANT_NAME_TO_ID

    candidates = build_compliant_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    for c in candidates:
        expanded = expand_auth_label_for_cid(bindings[c.cid], class_labels)
        assert TENANT_NAME_TO_ID.get(c.label.tenant) == TENANT_NAME_TO_ID.get(
            expanded.tenant
        )
        assert expanded.project == c.label.project
        assert expanded.level == c.label.level
        assert expanded.epoch == c.label.epoch
        assert evaluate_policy(DEFAULT_USER, expanded, DEFAULT_CHECKPOINT) == evaluate_policy(
            DEFAULT_USER, c.label, DEFAULT_CHECKPOINT
        )


def test_write_acl_class_plaintext_cases_csv(tmp_path):
    """Generate optional CSV artifact with equivalence cases."""
    cases = []

    def _record(case_id: str, candidates, bindings, class_labels, top_k, n_probe, slots):
        cmp = compare_object_level_vs_acl_class_reference(
            candidates,
            bindings,
            class_labels,
            DEFAULT_USER,
            DEFAULT_CHECKPOINT,
            top_k,
            n_probe=n_probe,
            slots_per_list=slots,
        )
        cost = cmp["cost"]
        cases.append(
            {
                "case_id": case_id,
                "N_sel": cost.n_sel,
                "N_acl": cost.n_acl,
                "N_vis": cost.n_vis,
                "acl_ratio": f"{cost.acl_ratio:.4f}",
                "visible_ratio": f"{cost.visible_ratio:.4f}",
                "object_level_policy_evals": cost.object_level_policy_evals,
                "acl_class_policy_evals": cost.acl_class_policy_evals,
                "estimated_cost_object_level": cost.estimated_cost_object_level,
                "estimated_cost_acl_class": cost.estimated_cost_acl_class,
                "expected_equivalent": "true",
                "observed_equivalent": str(cmp["equivalent"]).lower(),
            }
        )

    compliant = build_compliant_candidates()
    b1, c1 = build_acl_fixtures_from_candidates(compliant)
    _record("compliant_mixed", compliant, b1, c1, 3, 2, 3)

    post = build_post_filter_contrast_candidates()
    b2, c2 = build_acl_fixtures_from_candidates(post)
    _record("post_filter_contrast", post, b2, c2, 2, 2, 2)

    same_class = compliant
    b3 = {c.cid: ObjectClassBinding(c.cid, 1, 1) for c in same_class}
    c3 = {1: _class(1, clearance=2)}
    _record("all_same_class", same_class, b3, c3, 3, 2, 3)

    fields = [
        "case_id",
        "N_sel",
        "N_acl",
        "N_vis",
        "acl_ratio",
        "visible_ratio",
        "object_level_policy_evals",
        "acl_class_policy_evals",
        "estimated_cost_object_level",
        "estimated_cost_acl_class",
        "expected_equivalent",
        "observed_equivalent",
    ]
    out = tmp_path / "acl_class_plaintext_cases.csv"
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(cases)
    assert len(cases) == 3


def test_acl_class_csv_artifact_exists():
    """Repo artifact CSV is present and well-formed."""
    path = Path("artifacts/acl_class_plaintext_cases.csv")
    assert path.is_file()
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) >= 3
    assert all(r["observed_equivalent"] == "true" for r in rows)
