"""Phase 3B-3: slot-aligned committed-auth AuthView set-based ZK proof tests."""

from __future__ import annotations

import numpy as np
import pytest

from auth_reference.attacks import DEFAULT_CHECKPOINT, DEFAULT_USER
from auth_reference.reference import run_authorized_reference
from auth_reference.slot_aligned_auth_commitment import build_slot_aligned_auth_tree
from auth_reference.v3db_adapter import (
    authorized_topk_v3db_tiebreak,
    build_all_visible_auth_labels,
    build_candidates_from_v3db_query,
    build_committed_auth_witness,
    build_ordered_auth_item_dis,
    build_partial_visible_labels,
    build_slot_aligned_zk_witness_for_buffers,
    build_synthetic_user_context,
    compare_with_v3db_topk,
    encode_user_context_for_zk,
    top_k_cids_from_ordered,
    top_k_cids_from_slot_aligned_ordered,
)
from ivf_pq.zk import ivf_pq_learn
from tests.test_auth_zk_all_visible import _build_merkle_proof_inputs
from zk_IVF_PQ.zk_IVF_PQ import (
    py_set_based_auth_committed_with_merkle,
    py_set_based_auth_slot_aligned_with_merkle,
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
        "n_list": n_list,
        "n_probe": 4,
        "top_k": 5,
    }


def _run_slot_aligned_proof(idx, inputs, user, checkpoint, labels):
    candidates, _slot_rows, buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels,
    )
    ordered = build_ordered_auth_item_dis(candidates, user, checkpoint)
    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )

    metrics = py_set_based_auth_slot_aligned_with_merkle(
        inputs["query"].tolist(),
        inputs["center"].tolist(),
        inputs["vpqss"].tolist(),
        inputs["valids"].tolist(),
        inputs["itemss"].tolist(),
        inputs["code_books"].tolist(),
        inputs["ivf_roots"].tolist(),
        int(idx["top_k"]),
        inputs["cluster_idx_dis"].tolist(),
        int(slot_w["root_auth"]),
        int(user_w["user_tenant_id"]),
        list(user_w["user_project_ids"]),
        list(user_w["user_project_valids"]),
        int(user_w["user_clearance"]),
        int(user_w["user_epoch"]),
        int(user_w["checkpoint_epoch"]),
        slot_w["object_tenant_ids"],
        slot_w["object_project_ids"],
        slot_w["object_levels"],
        slot_w["object_states"],
        slot_w["object_epochs"],
        slot_w["list_ids"],
        slot_w["list_auth_roots"],
        slot_w["top_path_directions"],
        slot_w["top_path_siblings"],
        slot_w["intra_path_directions"],
        slot_w["intra_path_siblings"],
    )
    return metrics, ordered, candidates, slot_w


def test_auth_zk_slot_aligned_partial_visible_succeeds(synthetic_zk_index):
    idx = synthetic_zk_index
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

    _candidates, slot_rows, _buffers = build_candidates_from_v3db_query(
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

    metrics, ordered, candidates, _slot_w = _run_slot_aligned_proof(
        idx, inputs, user, checkpoint, labels
    )

    result = run_authorized_reference(
        candidates,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=inputs["buffers"].n_probe,
        slots_per_list=inputs["buffers"].capacity,
    )
    oracle_topk = authorized_topk_v3db_tiebreak(result.scored, idx["top_k"])
    witness_topk = top_k_cids_from_slot_aligned_ordered(ordered, idx["top_k"])
    assert compare_with_v3db_topk(witness_topk, oracle_topk)

    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0


def test_auth_zk_slot_aligned_all_visible_regression(synthetic_zk_index):
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

    _candidates, slot_rows, _buffers = build_candidates_from_v3db_query(
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

    metrics, ordered, candidates, _slot_w = _run_slot_aligned_proof(
        idx, inputs, user, checkpoint, labels
    )
    oracle_topk = top_k_cids_from_slot_aligned_ordered(
        build_ordered_auth_item_dis(candidates, user, checkpoint),
        idx["top_k"],
    )
    witness_topk = top_k_cids_from_slot_aligned_ordered(ordered, idx["top_k"])
    assert compare_with_v3db_topk(witness_topk, oracle_topk)

    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0


def test_auth_zk_global_vs_slot_aligned_equivalence(synthetic_zk_index):
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

    user_w = encode_user_context_for_zk(user, checkpoint)
    committed_w = build_committed_auth_witness(buffers, labels)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )

    slot_metrics = py_set_based_auth_slot_aligned_with_merkle(
        inputs["query"].tolist(),
        inputs["center"].tolist(),
        inputs["vpqss"].tolist(),
        inputs["valids"].tolist(),
        inputs["itemss"].tolist(),
        inputs["code_books"].tolist(),
        inputs["ivf_roots"].tolist(),
        int(idx["top_k"]),
        inputs["cluster_idx_dis"].tolist(),
        int(slot_w["root_auth"]),
        int(user_w["user_tenant_id"]),
        list(user_w["user_project_ids"]),
        list(user_w["user_project_valids"]),
        int(user_w["user_clearance"]),
        int(user_w["user_epoch"]),
        int(user_w["checkpoint_epoch"]),
        slot_w["object_tenant_ids"],
        slot_w["object_project_ids"],
        slot_w["object_levels"],
        slot_w["object_states"],
        slot_w["object_epochs"],
        slot_w["list_ids"],
        slot_w["list_auth_roots"],
        slot_w["top_path_directions"],
        slot_w["top_path_siblings"],
        slot_w["intra_path_directions"],
        slot_w["intra_path_siblings"],
    )

    global_metrics = py_set_based_auth_committed_with_merkle(
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

    _b1, _p1, verify_slot, _, _, _ = slot_metrics
    _b2, _p2, verify_global, _, _, _ = global_metrics
    assert verify_slot > 0.0
    assert verify_global > 0.0

    candidates, _, _ = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels,
    )
    ordered = build_ordered_auth_item_dis(candidates, user, checkpoint)
    topk = top_k_cids_from_ordered(ordered, idx["top_k"])
    assert len(topk) == idx["top_k"]


def test_auth_zk_slot_aligned_forged_tenant_fails(synthetic_zk_index):
    idx = synthetic_zk_index
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

    _candidates, slot_rows, buffers = build_candidates_from_v3db_query(
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

    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )

    forged_tenant = int(user_w["user_tenant_id"])
    target_i, target_j = None, None
    n_probe, capacity = buffers.valids.shape
    for i in range(n_probe):
        for j in range(capacity):
            cid = int(buffers.itemss[i, j])
            if cid in invisible_cids:
                slot_w["object_tenant_ids"][i][j] = forged_tenant
                target_i, target_j = i, j
                break
        if target_i is not None:
            break
    assert target_i is not None

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        py_set_based_auth_slot_aligned_with_merkle(
            inputs["query"].tolist(),
            inputs["center"].tolist(),
            inputs["vpqss"].tolist(),
            inputs["valids"].tolist(),
            inputs["itemss"].tolist(),
            inputs["code_books"].tolist(),
            inputs["ivf_roots"].tolist(),
            int(idx["top_k"]),
            inputs["cluster_idx_dis"].tolist(),
            int(slot_w["root_auth"]),
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            slot_w["object_tenant_ids"],
            slot_w["object_project_ids"],
            slot_w["object_levels"],
            slot_w["object_states"],
            slot_w["object_epochs"],
            slot_w["list_ids"],
            slot_w["list_auth_roots"],
            slot_w["top_path_directions"],
            slot_w["top_path_siblings"],
            slot_w["intra_path_directions"],
            slot_w["intra_path_siblings"],
        )


def test_auth_zk_slot_aligned_wrong_intra_path_fails(synthetic_zk_index):
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

    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )
    slot_w["intra_path_siblings"][0][0][0] ^= 1

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        py_set_based_auth_slot_aligned_with_merkle(
            inputs["query"].tolist(),
            inputs["center"].tolist(),
            inputs["vpqss"].tolist(),
            inputs["valids"].tolist(),
            inputs["itemss"].tolist(),
            inputs["code_books"].tolist(),
            inputs["ivf_roots"].tolist(),
            int(idx["top_k"]),
            inputs["cluster_idx_dis"].tolist(),
            int(slot_w["root_auth"]),
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            slot_w["object_tenant_ids"],
            slot_w["object_project_ids"],
            slot_w["object_levels"],
            slot_w["object_states"],
            slot_w["object_epochs"],
            slot_w["list_ids"],
            slot_w["list_auth_roots"],
            slot_w["top_path_directions"],
            slot_w["top_path_siblings"],
            slot_w["intra_path_directions"],
            slot_w["intra_path_siblings"],
        )


def test_auth_zk_slot_aligned_wrong_top_path_fails(synthetic_zk_index):
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

    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )
    slot_w["top_path_siblings"][0][0] ^= 1

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        py_set_based_auth_slot_aligned_with_merkle(
            inputs["query"].tolist(),
            inputs["center"].tolist(),
            inputs["vpqss"].tolist(),
            inputs["valids"].tolist(),
            inputs["itemss"].tolist(),
            inputs["code_books"].tolist(),
            inputs["ivf_roots"].tolist(),
            int(idx["top_k"]),
            inputs["cluster_idx_dis"].tolist(),
            int(slot_w["root_auth"]),
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            slot_w["object_tenant_ids"],
            slot_w["object_project_ids"],
            slot_w["object_levels"],
            slot_w["object_states"],
            slot_w["object_epochs"],
            slot_w["list_ids"],
            slot_w["list_auth_roots"],
            slot_w["top_path_directions"],
            slot_w["top_path_siblings"],
            slot_w["intra_path_directions"],
            slot_w["intra_path_siblings"],
        )


def test_auth_zk_slot_aligned_list_id_graft_fails(synthetic_zk_index):
    """Cross-list top path graft must fail via list_id binding."""
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

    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )

    probe0_list = int(slot_w["list_ids"][0])
    other_list = (probe0_list + 1) % idx["n_list"]
    dummy_tree = build_slot_aligned_auth_tree(
        n_list=idx["n_list"],
        slot_per_list=int(buffers.capacity),
        slot_labels={},
    )
    from auth_reference.slot_aligned_auth_commitment import open_list_auth_root

    graft = open_list_auth_root(dummy_tree, other_list)
    slot_w["list_auth_roots"][0] = int(graft.list_auth_root)
    slot_w["top_path_directions"][0] = list(graft.top_path_directions)
    slot_w["top_path_siblings"][0] = list(graft.top_path_siblings)

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        py_set_based_auth_slot_aligned_with_merkle(
            inputs["query"].tolist(),
            inputs["center"].tolist(),
            inputs["vpqss"].tolist(),
            inputs["valids"].tolist(),
            inputs["itemss"].tolist(),
            inputs["code_books"].tolist(),
            inputs["ivf_roots"].tolist(),
            int(idx["top_k"]),
            inputs["cluster_idx_dis"].tolist(),
            int(slot_w["root_auth"]),
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            slot_w["object_tenant_ids"],
            slot_w["object_project_ids"],
            slot_w["object_levels"],
            slot_w["object_states"],
            slot_w["object_epochs"],
            slot_w["list_ids"],
            slot_w["list_auth_roots"],
            slot_w["top_path_directions"],
            slot_w["top_path_siblings"],
            slot_w["intra_path_directions"],
            slot_w["intra_path_siblings"],
        )
