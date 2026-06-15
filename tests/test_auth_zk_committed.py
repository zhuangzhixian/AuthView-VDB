"""Phase 2C-2: committed-auth AuthView set-based ZK proof tests."""

from __future__ import annotations

import numpy as np
import pytest

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
    py_set_based_auth_committed_with_merkle,
    py_set_based_auth_with_merkle,
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


def _run_committed_proof(idx, inputs, user, checkpoint, labels):
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
    committed_w = build_committed_auth_witness(buffers, labels)

    metrics = py_set_based_auth_committed_with_merkle(
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
    return metrics, ordered, candidates, committed_w


def test_auth_zk_committed_partial_visible_succeeds(synthetic_zk_index):
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
    metrics, ordered, candidates, _committed_w = _run_committed_proof(
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
    witness_topk = top_k_cids_from_ordered(ordered, idx["top_k"])
    assert compare_with_v3db_topk(witness_topk, oracle_topk)

    _build, _prove, verify_time, _size, _mem, _gates = metrics
    assert verify_time > 0.0


def test_auth_zk_committed_forged_tenant_fails(synthetic_zk_index):
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
    committed_w = build_committed_auth_witness(buffers, labels)

    forged_tenant = int(user_w["user_tenant_id"])
    target_i, target_j = None, None
    n_probe, capacity = buffers.valids.shape
    for i in range(n_probe):
        for j in range(capacity):
            cid = int(buffers.itemss[i, j])
            if cid in invisible_cids:
                committed_w["object_tenant_ids"][i][j] = forged_tenant
                target_i, target_j = i, j
                break
        if target_i is not None:
            break
    assert target_i is not None

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed failed"):
        py_set_based_auth_committed_with_merkle(
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


def test_auth_zk_committed_wrong_auth_path_fails(synthetic_zk_index):
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
    committed_w["auth_path_siblings"][0][0][0] ^= 1

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed failed"):
        py_set_based_auth_committed_with_merkle(
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


def test_auth_zk_committed_all_visible_regression(synthetic_zk_index):
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

    committed_metrics, ordered, candidates, _committed_w = _run_committed_proof(
        idx, inputs, user, checkpoint, labels
    )
    oracle_topk = top_k_cids_from_ordered(
        build_ordered_auth_item_dis(candidates, user, checkpoint),
        idx["top_k"],
    )
    committed_topk = top_k_cids_from_ordered(ordered, idx["top_k"])
    assert compare_with_v3db_topk(committed_topk, oracle_topk)

    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = build_committed_auth_witness(inputs["buffers"], labels)
    policy_metrics = py_set_based_auth_with_merkle(
        inputs["query"].tolist(),
        inputs["center"].tolist(),
        inputs["vpqss"].tolist(),
        inputs["valids"].tolist(),
        inputs["itemss"].tolist(),
        inputs["code_books"].tolist(),
        inputs["ivf_roots"].tolist(),
        int(idx["top_k"]),
        inputs["cluster_idx_dis"].tolist(),
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
    )

    _b1, _p1, verify_committed, _, _, gates_committed = committed_metrics
    _b2, _p2, verify_policy, _, _, gates_policy = policy_metrics
    assert verify_committed > 0.0
    assert verify_policy > 0.0
    assert gates_committed >= gates_policy
