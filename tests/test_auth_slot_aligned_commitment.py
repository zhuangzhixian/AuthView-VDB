"""Tests for slot-aligned auth Merkle commitment (Phase 3B-1)."""

from __future__ import annotations

import numpy as np
import pytest

from auth_reference.auth_commitment import AuthLabelLeaf, compute_auth_leaf
from auth_reference.slot_aligned_auth_commitment import (
    SlotAuthLabel,
    build_intra_list_auth_tree,
    build_slot_aligned_auth_tree,
    build_slot_aligned_auth_witness_for_buffers,
    estimate_global_opening_cost,
    estimate_slot_aligned_opening_cost,
    estimate_slot_aligned_opening_cost_naive,
    open_slot_aligned_auth_label,
    open_slot_in_list,
    verify_slot_aligned_opening_plaintext,
)
from auth_reference.v3db_adapter import V3DBSlotBuffers


def _leaf(cid, tenant=1, project=10, level=3, state=1, epoch=7):
    return AuthLabelLeaf(cid, tenant, project, level, state, epoch)


def _slot(list_id, slot_id, cid, tenant=1, project=10, level=3, state=1, epoch=7):
    return SlotAuthLabel(list_id, slot_id, cid, tenant, project, level, state, epoch)


def _small_tree():
    """n_list=4, slot_per_list=4 with distinct labels on list 1 slots 0-1."""
    labels = {
        (1, 0): _slot(1, 0, 101),
        (1, 1): _slot(1, 1, 102, level=2),
        (2, 0): _slot(2, 0, 201, tenant=2),
    }
    tree = build_slot_aligned_auth_tree(n_list=4, slot_per_list=4, slot_labels=labels)
    return tree, labels


def test_valid_slot_aligned_opening_succeeds():
    tree, _labels = _small_tree()
    label, slot_op, list_op = open_slot_aligned_auth_label(tree, list_id=1, slot_id=0)
    assert verify_slot_aligned_opening_plaintext(
        label,
        slot_op.intra_path,
        list_op.list_auth_root,
        list_op.top_path,
        tree.root_auth,
    )


def test_forged_tenant_fails():
    tree, _labels = _small_tree()
    label, slot_op, list_op = open_slot_aligned_auth_label(tree, list_id=1, slot_id=0)
    forged = AuthLabelLeaf(label.cid, 99, label.project, label.level, label.state, label.epoch)
    assert not verify_slot_aligned_opening_plaintext(
        forged,
        slot_op.intra_path,
        list_op.list_auth_root,
        list_op.top_path,
        tree.root_auth,
    )


def test_forged_cid_fails():
    tree, _labels = _small_tree()
    label, slot_op, list_op = open_slot_aligned_auth_label(tree, list_id=1, slot_id=0)
    forged = AuthLabelLeaf(999, label.tenant, label.project, label.level, label.state, label.epoch)
    assert not verify_slot_aligned_opening_plaintext(
        forged,
        slot_op.intra_path,
        list_op.list_auth_root,
        list_op.top_path,
        tree.root_auth,
    )


def test_wrong_intra_list_path_fails():
    tree, _labels = _small_tree()
    label, slot_op, list_op = open_slot_aligned_auth_label(tree, list_id=1, slot_id=0)
    bad_intra = [row[:] for row in slot_op.intra_path]
    bad_intra[0][1] ^= 1
    assert not verify_slot_aligned_opening_plaintext(
        label,
        bad_intra,
        list_op.list_auth_root,
        list_op.top_path,
        tree.root_auth,
    )


def test_wrong_top_level_path_fails():
    tree, _labels = _small_tree()
    label, slot_op, list_op = open_slot_aligned_auth_label(tree, list_id=1, slot_id=0)
    bad_top = [row[:] for row in list_op.top_path]
    bad_top[0][1] ^= 1
    assert not verify_slot_aligned_opening_plaintext(
        label,
        slot_op.intra_path,
        list_op.list_auth_root,
        bad_top,
        tree.root_auth,
    )


def test_cross_list_graft_fails():
    tree, _labels = _small_tree()
    _label_a, slot_a, _list_a = open_slot_aligned_auth_label(tree, list_id=1, slot_id=0)
    _label_b, _slot_b, list_b = open_slot_aligned_auth_label(tree, list_id=2, slot_id=0)
    assert not verify_slot_aligned_opening_plaintext(
        slot_a.label,
        slot_a.intra_path,
        tree.list_auth_root(1),
        list_b.top_path,
        tree.root_auth,
    )


def test_invalid_padding_slot_dummy_label_succeeds():
    from auth_reference.slot_aligned_auth_commitment import (
        dummy_auth_label_for_slot,
        open_list_auth_root,
    )

    tree = build_slot_aligned_auth_tree(
        n_list=2,
        slot_per_list=4,
        slot_labels={(0, 0): _slot(0, 0, 50)},
    )
    dummy = dummy_auth_label_for_slot(0)
    slot_op = open_slot_in_list(tree, list_id=0, slot_id=3)
    list_op = open_list_auth_root(tree, list_id=0)
    assert slot_op.label == dummy
    assert verify_slot_aligned_opening_plaintext(
        slot_op.label,
        slot_op.intra_path,
        list_op.list_auth_root,
        list_op.top_path,
        tree.root_auth,
    )


def test_shared_top_path_representation():
    tree, _labels = _small_tree()
    _l0, _s0, list_op_0 = open_slot_aligned_auth_label(tree, list_id=1, slot_id=0)
    _l1, _s1, list_op_1 = open_slot_aligned_auth_label(tree, list_id=1, slot_id=1)
    assert list_op_0.list_auth_root == list_op_1.list_auth_root
    assert list_op_0.top_path == list_op_1.top_path

    buffers = V3DBSlotBuffers(
        vpqss=np.zeros((1, 4, 8), dtype=np.int64),
        valids=np.array([[1, 1, 0, 0]], dtype=np.int64),
        itemss=np.array([[101, 102, 0, 0]], dtype=np.int64),
        cluster_idxes=np.array([1], dtype=np.int64),
        capacity=4,
        n_probe=1,
    )
    witness = build_slot_aligned_auth_witness_for_buffers(
        buffers,
        {
            (1, 0): _slot(1, 0, 101),
            (1, 1): _slot(1, 1, 102, level=2),
        },
        n_list=4,
    )
    shared = witness.shared_list_openings[1]
    assert witness.probe_list_ids == [1]
    assert witness.slot_openings[0][0].intra_path != witness.slot_openings[0][1].intra_path
    assert shared is witness.shared_list_openings[1]
    assert len(witness.shared_list_openings) == 1
    for j in range(4):
        slot_op = witness.slot_openings[0][j]
        assert verify_slot_aligned_opening_plaintext(
            slot_op.label,
            slot_op.intra_path,
            shared.list_auth_root,
            shared.top_path,
            witness.root_auth,
        )


def test_intra_list_leaf_matches_global_leaf():
    lbl = _leaf(101)
    intra = build_intra_list_auth_tree(0, [lbl])
    assert compute_auth_leaf(*lbl.as_list()) == compute_auth_leaf(101, 1, 10, 3, 1, 7)
    slot_op = open_slot_in_list(
        build_slot_aligned_auth_tree(1, 1, {(0, 0): lbl}),
        0,
        0,
    )
    assert slot_op.label == lbl


def test_cost_model_sanity():
    n_probe, slot_per_list, n_list = 4, 64, 8
    global_cost = estimate_global_opening_cost(n_probe, slot_per_list)
    aligned_cost = estimate_slot_aligned_opening_cost(n_probe, slot_per_list, n_list)
    naive_aligned = estimate_slot_aligned_opening_cost_naive(n_probe, slot_per_list, n_list)

    n_sel = n_probe * slot_per_list
    assert global_cost == n_sel * 8  # next_pow2(256) depth 8
    assert aligned_cost == n_probe * 3 + n_sel * 6  # depth_top=3, depth_slot=6
    assert aligned_cost < global_cost
    assert aligned_cost < naive_aligned


def test_cost_model_typical_phase2e_grid():
    cases = [
        (2, 32, 8),
        (2, 64, 8),
        (4, 32, 8),
        (4, 64, 8),
    ]
    for n_probe, slot, n_list in cases:
        g = estimate_global_opening_cost(n_probe, slot)
        a = estimate_slot_aligned_opening_cost(n_probe, slot, n_list)
        assert a < g, f"expected slot-aligned < global for {(n_probe, slot, n_list)}"
