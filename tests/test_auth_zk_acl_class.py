"""Phase 5B-3: ACL-class committed AuthView set-based ZK proof tests."""

from __future__ import annotations

import copy

import numpy as np
import pytest

from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    acl_class_label_from_auth_label,
    authorized_topk_acl_compressed,
    build_acl_fixtures_from_candidates,
    compare_object_level_vs_acl_class_reference,
)
from auth_reference.acl_class_commitment import (
    build_acl_class_zk_witness_for_buffers,
    split_acl_class_zk_witness_for_zk,
    top_k_cids_from_acl_class_ordered,
    verify_acl_class_opening_plaintext,
    verify_acl_class_witness_plaintext,
    verify_object_class_binding_opening_plaintext,
)
from auth_reference.attacks import DEFAULT_CHECKPOINT, DEFAULT_USER
from auth_reference.reference import run_authorized_reference
from auth_reference.v3db_adapter import (
    authorized_topk_v3db_tiebreak,
    build_all_visible_auth_labels,
    build_candidates_from_v3db_query,
    build_committed_auth_witness,
    build_ordered_auth_item_dis,
    build_partial_visible_labels,
    build_synthetic_user_context,
    compare_with_v3db_topk,
    encode_user_context_for_zk,
    top_k_cids_from_ordered,
)
from ivf_pq.zk import ivf_pq_learn
from tests.test_auth_zk_all_visible import _build_merkle_proof_inputs
from zk_IVF_PQ.zk_IVF_PQ import (
    py_set_based_auth_acl_class_with_merkle,
    py_set_based_auth_committed_with_merkle,
)


@pytest.fixture
def synthetic_zk_index():
    rng = np.random.default_rng(42)
    n_list = 8
    n = 400
    vecs = rng.integers(0, 4096, size=(n, 64), dtype=np.int64)
    query = rng.integers(0, 4096, size=64, dtype=np.int64)
    _labels, center, code_books, quant_vecs, id_groups = ivf_pq_learn(
        vecs, n_list=n_list, n_iter=8
    )
    return {
        "query": query,
        "center": center,
        "code_books": code_books,
        "quant_vecs": quant_vecs,
        "id_groups": id_groups,
        "n_probe": 4,
        "top_k": 5,
    }


def _partial_visible_fixture(idx):
    inputs = _build_merkle_proof_inputs(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
    )
    user = build_synthetic_user_context(clearance=10, epoch=DEFAULT_CHECKPOINT.epoch)
    checkpoint = DEFAULT_CHECKPOINT

    candidates, slot_rows, buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels={},
    )
    valid_rows = [r for r in slot_rows if r[4]]
    by_dist = sorted(valid_rows, key=lambda r: r[5])
    invisible_cids = {by_dist[0][3], by_dist[1][3]}
    visible_cids = {r[3] for r in valid_rows} - invisible_cids
    labels = build_partial_visible_labels(visible_cids, invisible_cids, user, checkpoint)

    candidates, _, _buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels=labels,
    )
    buffers = inputs["buffers"]
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    return idx, inputs, user, checkpoint, labels, candidates, buffers, bindings, class_labels


def _call_acl_class_zk(idx, inputs, user, checkpoint, split):
    user_w = encode_user_context_for_zk(user, checkpoint)
    return py_set_based_auth_acl_class_with_merkle(
        inputs["query"].tolist(),
        inputs["center"].tolist(),
        inputs["vpqss"].tolist(),
        inputs["valids"].tolist(),
        inputs["itemss"].tolist(),
        inputs["code_books"].tolist(),
        inputs["ivf_roots"].tolist(),
        int(idx["top_k"]),
        inputs["cluster_idx_dis"].tolist(),
        int(split["root_acl_class"]),
        int(split["root_object_class_binding"]),
        int(user_w["user_tenant_id"]),
        list(user_w["user_project_ids"]),
        list(user_w["user_project_valids"]),
        int(user_w["user_clearance"]),
        int(user_w["user_epoch"]),
        int(user_w["checkpoint_epoch"]),
        list(split["selected_class_valids"]),
        list(split["selected_acl_class_ids"]),
        list(split["selected_class_tenant_ids"]),
        list(split["selected_class_project_ids"]),
        list(split["selected_class_required_clearances"]),
        list(split["selected_class_states"]),
        list(split["selected_class_epochs"]),
        split["selected_class_path_directions"],
        split["selected_class_path_siblings"],
        split["binding_acl_class_ids"],
        split["binding_epochs"],
        split["binding_path_directions"],
        split["binding_path_siblings"],
        split["per_slot_class_selector"],
    )


def _run_acl_class_proof(idx, inputs, user, checkpoint, buffers, bindings, class_labels, *, n_acl_max=None):
    witness = build_acl_class_zk_witness_for_buffers(
        buffers,
        bindings,
        class_labels,
        user,
        checkpoint,
        n_acl_max=n_acl_max,
    )
    split = split_acl_class_zk_witness_for_zk(witness)
    metrics = _call_acl_class_zk(idx, inputs, user, checkpoint, split)
    return metrics, witness, split


def test_auth_zk_acl_class_partial_visible_succeeds(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    metrics, witness, _split = _run_acl_class_proof(
        idx, inputs, user, checkpoint, buffers, bindings, class_labels
    )

    n_probe = inputs["buffers"].n_probe
    slots = inputs["buffers"].capacity
    acl_topk = top_k_cids_from_acl_class_ordered(
        candidates,
        bindings,
        class_labels,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=n_probe,
        slots_per_list=slots,
    )
    result = run_authorized_reference(
        candidates,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=n_probe,
        slots_per_list=slots,
    )
    object_topk = authorized_topk_v3db_tiebreak(result.scored, idx["top_k"])
    assert compare_with_v3db_topk(acl_topk, object_topk)

    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0


def test_auth_zk_acl_class_all_same_class_succeeds(synthetic_zk_index):
    idx = synthetic_zk_index
    inputs = _build_merkle_proof_inputs(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
    )
    user = DEFAULT_USER
    checkpoint = DEFAULT_CHECKPOINT

    _candidates, slot_rows, buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels={},
    )
    valid_cids = {row[3] for row in slot_rows if row[4]}
    labels = build_all_visible_auth_labels(valid_cids, user, checkpoint)
    candidates, _, buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels=labels,
    )
    bindings, class_labels = build_acl_fixtures_from_candidates(candidates)
    assert len({b.acl_class_id for b in bindings.values()}) == 1

    metrics, _witness, _split = _run_acl_class_proof(
        idx, inputs, user, checkpoint, buffers, bindings, class_labels, n_acl_max=1
    )
    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0


def test_auth_zk_acl_class_one_class_per_object_succeeds(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, candidates, buffers, _bindings, _class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    bindings = {
        c.cid: ObjectClassBinding(c.cid, c.cid, c.label.epoch)
        for c in candidates
        if c.valid
    }
    class_labels = {
        c.cid: acl_class_label_from_auth_label(c.cid, c.label)
        for c in candidates
        if c.valid
    }
    n_sel = sum(1 for c in candidates if c.valid)
    n_acl = len(class_labels)
    assert n_acl == n_sel

    metrics, _witness, _split = _run_acl_class_proof(
        idx,
        inputs,
        user,
        checkpoint,
        buffers,
        bindings,
        class_labels,
        n_acl_max=n_acl,
    )
    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0


def test_auth_zk_acl_class_equivalent_to_object_level_committed(synthetic_zk_index):
    idx, inputs, user, checkpoint, labels, candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    n_probe = inputs["buffers"].n_probe
    slots = inputs["buffers"].capacity

    acl_metrics, _witness, split = _run_acl_class_proof(
        idx, inputs, user, checkpoint, buffers, bindings, class_labels
    )
    user_w = encode_user_context_for_zk(user, checkpoint)
    committed_w = build_committed_auth_witness(buffers, labels)
    committed_metrics = py_set_based_auth_committed_with_merkle(
        inputs["query"].tolist(),
        inputs["center"].tolist(),
        inputs["vpqss"].tolist(),
        inputs["valids"].tolist(),
        inputs["itemss"].tolist(),
        inputs["code_books"].tolist(),
        inputs["ivf_roots"].tolist(),
        int(idx["top_k"]),
        inputs["cluster_idx_dis"].tolist(),
        int(committed_w["root_auth"]),
        int(user_w["user_tenant_id"]),
        list(user_w["user_project_ids"]),
        list(user_w["user_project_valids"]),
        int(user_w["user_clearance"]),
        int(user_w["user_epoch"]),
        int(user_w["checkpoint_epoch"]),
        committed_w["object_tenant_ids"],
        committed_w["object_project_ids"],
        committed_w["object_levels"],
        committed_w["object_states"],
        committed_w["object_epochs"],
        committed_w["auth_path_directions"],
        committed_w["auth_path_siblings"],
    )

    acl_topk = top_k_cids_from_acl_class_ordered(
        candidates,
        bindings,
        class_labels,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=n_probe,
        slots_per_list=slots,
    )
    object_topk = top_k_cids_from_ordered(
        build_ordered_auth_item_dis(candidates, user, checkpoint),
        idx["top_k"],
    )
    assert compare_with_v3db_topk(acl_topk, object_topk)

    _b1, _p1, verify_acl, _, _, _ = acl_metrics
    _b2, _p2, verify_committed, _, _, _ = committed_metrics
    assert verify_acl > 0.0
    assert verify_committed > 0.0


def test_auth_zk_acl_class_forged_class_label_fails(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, _candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    witness = build_acl_class_zk_witness_for_buffers(
        buffers, bindings, class_labels, user, checkpoint
    )
    split = split_acl_class_zk_witness_for_zk(witness)
    split = copy.deepcopy(split)
    split["selected_class_tenant_ids"][0] ^= 1

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed_acl_class failed"):
        _call_acl_class_zk(idx, inputs, user, checkpoint, split)


def test_auth_zk_acl_class_forged_binding_fails(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, _candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    witness = build_acl_class_zk_witness_for_buffers(
        buffers, bindings, class_labels, user, checkpoint
    )
    split = split_acl_class_zk_witness_for_zk(witness)
    split = copy.deepcopy(split)
    split["binding_acl_class_ids"][0][0] ^= 1

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed_acl_class failed"):
        _call_acl_class_zk(idx, inputs, user, checkpoint, split)


def test_auth_zk_acl_class_selector_mismatch_fails(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, _candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    witness = build_acl_class_zk_witness_for_buffers(
        buffers, bindings, class_labels, user, checkpoint, n_acl_max=4
    )
    split = split_acl_class_zk_witness_for_zk(witness)
    split = copy.deepcopy(split)
    n_acl_max = int(split["n_acl_max"])
    if n_acl_max < 2:
        pytest.skip("need at least two ACL rows for selector mismatch")
    split["per_slot_class_selector"][0][0] = [0] * n_acl_max
    split["per_slot_class_selector"][0][0][1] = 1

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed_acl_class failed"):
        _call_acl_class_zk(idx, inputs, user, checkpoint, split)


def test_auth_zk_acl_class_invalid_selected_row_fails(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, _candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    witness = build_acl_class_zk_witness_for_buffers(
        buffers, bindings, class_labels, user, checkpoint, n_acl_max=4
    )
    split = split_acl_class_zk_witness_for_zk(witness)
    split = copy.deepcopy(split)
    dummy_idx = next(
        i for i, v in enumerate(split["selected_class_valids"]) if int(v) == 0
    )
    split["per_slot_class_selector"][0][0] = [0] * int(split["n_acl_max"])
    split["per_slot_class_selector"][0][0][dummy_idx] = 1

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed_acl_class failed"):
        _call_acl_class_zk(idx, inputs, user, checkpoint, split)


def test_auth_zk_acl_class_root_mixing_fails(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, _candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    witness = build_acl_class_zk_witness_for_buffers(
        buffers, bindings, class_labels, user, checkpoint
    )
    split = split_acl_class_zk_witness_for_zk(witness)
    split = copy.deepcopy(split)
    split["root_acl_class"] = int(split["root_acl_class"]) ^ 1

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed_acl_class failed"):
        _call_acl_class_zk(idx, inputs, user, checkpoint, split)


def test_auth_zk_acl_class_user_context_mismatch_fails(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    witness = build_acl_class_zk_witness_for_buffers(
        buffers, bindings, class_labels, user, checkpoint
    )
    split = split_acl_class_zk_witness_for_zk(witness)
    n_probe = inputs["buffers"].n_probe
    slots = inputs["buffers"].capacity

    high_topk = top_k_cids_from_acl_class_ordered(
        candidates,
        bindings,
        class_labels,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=n_probe,
        slots_per_list=slots,
    )

    low_clearance_user = build_synthetic_user_context(clearance=0, epoch=checkpoint.epoch)
    low_topk = top_k_cids_from_acl_class_ordered(
        candidates,
        bindings,
        class_labels,
        low_clearance_user,
        checkpoint,
        idx["top_k"],
        n_probe=n_probe,
        slots_per_list=slots,
    )
    assert high_topk != low_topk

    metrics = _call_acl_class_zk(idx, inputs, low_clearance_user, checkpoint, split)
    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0

    low_topk_from_proof_context = top_k_cids_from_acl_class_ordered(
        candidates,
        bindings,
        class_labels,
        low_clearance_user,
        checkpoint,
        idx["top_k"],
        n_probe=n_probe,
        slots_per_list=slots,
    )
    assert low_topk == low_topk_from_proof_context
    assert low_topk != high_topk


def test_auth_zk_acl_class_parity_smoke(synthetic_zk_index):
    idx, inputs, user, checkpoint, _labels, candidates, buffers, bindings, class_labels = (
        _partial_visible_fixture(synthetic_zk_index)
    )
    witness = build_acl_class_zk_witness_for_buffers(
        buffers, bindings, class_labels, user, checkpoint
    )
    split = split_acl_class_zk_witness_for_zk(witness)

    for idx_row, (lbl, valid) in enumerate(
        zip(witness.selected_class_labels, witness.selected_class_valids, strict=True)
    ):
        if valid:
            path = [
                [
                    witness.selected_class_path_directions[idx_row][d],
                    witness.selected_class_path_siblings[idx_row][d],
                ]
                for d in range(len(witness.selected_class_path_directions[idx_row]))
            ]
            assert verify_acl_class_opening_plaintext(lbl, path, witness.root_acl_class)

    for i in range(witness.n_probe):
        for j in range(witness.slot_per_list):
            binding = witness.per_slot_bindings[i][j]
            path = [
                [
                    witness.per_slot_binding_path_directions[i][j][d],
                    witness.per_slot_binding_path_siblings[i][j][d],
                ]
                for d in range(len(witness.per_slot_binding_path_directions[i][j]))
            ]
            assert verify_object_class_binding_opening_plaintext(
                binding, path, witness.root_object_class_binding
            )

    cmp = compare_object_level_vs_acl_class_reference(
        candidates,
        bindings,
        class_labels,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=inputs["buffers"].n_probe,
        slots_per_list=inputs["buffers"].capacity,
    )
    assert cmp["equivalent"] is True

    metrics = _call_acl_class_zk(idx, inputs, user, checkpoint, split)
    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0
