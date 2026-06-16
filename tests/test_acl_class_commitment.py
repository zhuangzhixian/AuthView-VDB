"""Tests for ACL-class commitment and ZK witness layout (Phase 5B-1)."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    acl_class_label_from_auth_label,
    build_acl_fixtures_from_candidates,
    count_unique_acl_classes_in_candidates,
)
from auth_reference.acl_class_commitment import (
    ACLClassLeaf,
    ObjectClassBindingLeaf,
    build_acl_class_tree,
    build_acl_class_zk_witness_for_candidates,
    build_object_class_binding_tree,
    compute_acl_class_leaf,
    compute_acl_class_leaf_record,
    compute_object_class_binding_leaf,
    compute_object_class_binding_leaf_record,
    estimate_acl_class_zk_cost,
    open_acl_class,
    open_object_class_binding,
    verify_acl_class_opening_plaintext,
    verify_acl_class_witness_plaintext,
    verify_object_class_binding_opening_plaintext,
)
from auth_reference.attacks import (
    DEFAULT_CHECKPOINT,
    DEFAULT_USER,
    build_compliant_candidates,
    build_post_filter_contrast_candidates,
)
from auth_reference.records import AuthLabel, CandidateRecord


def _class(
    class_id: int,
    *,
    tenant_id: int = 1,
    project_id: int = 10,
    clearance: int = 2,
    epoch: int = 1,
) -> ACLClassLabel:
    return ACLClassLabel(
        acl_class_id=class_id,
        tenant_id=tenant_id,
        project_id=project_id,
        required_clearance=clearance,
        state="active",
        epoch=epoch,
    )


def test_acl_class_leaf_hash_deterministic():
    label = _class(42, tenant_id=1, project_id=10, clearance=3, epoch=7)
    h1 = compute_acl_class_leaf(label)
    h2 = compute_acl_class_leaf_record(ACLClassLeaf.from_label(label))
    assert h1 == h2
    assert h1 == compute_acl_class_leaf(label)


def test_object_class_binding_leaf_hash_deterministic():
    binding = ObjectClassBinding(101, 42, 7)
    h1 = compute_object_class_binding_leaf(binding)
    h2 = compute_object_class_binding_leaf_record(
        ObjectClassBindingLeaf.from_binding(binding)
    )
    assert h1 == h2


def test_valid_acl_class_opening_succeeds():
    labels = {1: _class(1), 2: _class(2, tenant_id=2, clearance=1)}
    tree = build_acl_class_tree(labels)
    opening = open_acl_class(tree, 1)
    assert verify_acl_class_opening_plaintext(
        labels[1], opening.path, tree.root
    )


def test_valid_object_class_binding_opening_succeeds():
    bindings = [
        ObjectClassBinding(101, 1, 1),
        ObjectClassBinding(102, 1, 1),
        ObjectClassBinding(103, 2, 1),
        ObjectClassBinding(104, 2, 1),
    ]
    tree = build_object_class_binding_tree(bindings)
    opening = open_object_class_binding(tree, 0)
    assert verify_object_class_binding_opening_plaintext(
        bindings[0], opening.path, tree.root
    )


def test_forged_acl_class_label_fails():
    labels = {1: _class(1), 2: _class(2, tenant_id=2)}
    tree = build_acl_class_tree(labels)
    opening = open_acl_class(tree, 1)
    forged = _class(1, tenant_id=99)
    assert not verify_acl_class_opening_plaintext(forged, opening.path, tree.root)


def test_forged_object_class_binding_fails():
    bindings = [ObjectClassBinding(101, 1, 1), ObjectClassBinding(102, 2, 1)]
    tree = build_object_class_binding_tree(bindings)
    opening = open_object_class_binding(tree, 0)
    forged = ObjectClassBinding(101, 99, 1)
    assert not verify_object_class_binding_opening_plaintext(
        forged, opening.path, tree.root
    )


def test_witness_plaintext_verification_succeeds():
    candidates = build_compliant_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=4,
    )
    result = verify_acl_class_witness_plaintext(
        witness,
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert result["valid"] is True
    assert result["topk_equivalent"] is True


def test_witness_topk_equivalent_to_object_level():
    candidates = build_post_filter_contrast_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=4,
    )
    result = verify_acl_class_witness_plaintext(
        witness,
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=2,
        n_probe=2,
        slots_per_list=2,
    )
    assert result["acl_top_k"] == [203, 204]


def test_selected_class_table_padding():
    candidates = build_compliant_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=8,
    )
    assert len(witness.selected_class_labels) == 8
    assert sum(witness.selected_class_valids) == count_unique_acl_classes_in_candidates(
        candidates, bindings
    )
    assert witness.selected_class_valids.count(0) == 8 - sum(witness.selected_class_valids)


def test_per_slot_class_index_mismatch_fails():
    candidates = build_compliant_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=4,
    )
    witness.per_slot_class_index[0][0] = (witness.per_slot_class_index[0][0] + 1) % 4
    with pytest.raises(ValueError, match="selector/index mismatch|class index mismatch"):
        verify_acl_class_witness_plaintext(
            witness,
            candidates,
            bindings,
            class_labels,
            DEFAULT_USER,
            DEFAULT_CHECKPOINT,
            top_k=3,
            n_probe=2,
            slots_per_list=3,
        )


def test_object_cid_mismatch_fails():
    candidates = build_compliant_candidates()
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=4,
    )
    i, j = 0, 0
    old = witness.per_slot_bindings[i][j]
    witness.per_slot_bindings[i][j] = ObjectClassBinding(
        old.cid + 999, old.acl_class_id, old.epoch
    )
    with pytest.raises(ValueError, match="cid mismatch|binding mismatch|invalid binding"):
        verify_acl_class_witness_plaintext(
            witness,
            candidates,
            bindings,
            class_labels,
            DEFAULT_USER,
            DEFAULT_CHECKPOINT,
            top_k=3,
            n_probe=2,
            slots_per_list=3,
        )


def test_all_same_class_gives_n_acl_one():
    candidates = build_compliant_candidates()
    bindings = {
        c.cid: ObjectClassBinding(c.cid, 1, DEFAULT_CHECKPOINT.epoch)
        for c in candidates
    }
    class_labels = {1: _class(1, clearance=2)}
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=4,
    )
    assert sum(witness.selected_class_valids) == 1
    verify_acl_class_witness_plaintext(
        witness,
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )


def test_degenerate_one_class_per_object():
    candidates = build_compliant_candidates()
    bindings = {
        c.cid: ObjectClassBinding(c.cid, c.cid, c.label.epoch) for c in candidates
    }
    class_labels = {
        c.cid: acl_class_label_from_auth_label(c.cid, c.label) for c in candidates
    }
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=8,
    )
    n_sel = sum(1 for c in candidates if c.valid)
    assert sum(witness.selected_class_valids) == n_sel
    verify_acl_class_witness_plaintext(
        witness,
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )


def test_cost_model_benefit_when_compressed():
    cost = estimate_acl_class_zk_cost(n_sel=100, n_acl=10, n_acl_max=16, binding_openings=100)
    assert cost.estimated_acl_class_cost < cost.estimated_object_level_cost
    assert cost.acl_ratio == pytest.approx(0.1)


def test_cost_model_no_benefit_degenerate():
    cost = estimate_acl_class_zk_cost(n_sel=6, n_acl=6, n_acl_max=8, binding_openings=6)
    assert cost.estimated_acl_class_cost > cost.estimated_object_level_cost


def test_acl_class_commitment_csv_artifact_exists():
    path = Path("artifacts/acl_class_commitment_cases.csv")
    assert path.is_file()
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) >= 3
    assert all(r["witness_valid"] == "true" for r in rows)
    assert all(r["topk_equivalent"] == "true" for r in rows)
