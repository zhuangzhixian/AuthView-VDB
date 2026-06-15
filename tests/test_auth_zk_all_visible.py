"""Phase 2B-3a: all-visible AuthView set-based ZK proof smoke + baseline equivalence."""

from __future__ import annotations

import numpy as np
import pytest

from auth_reference.attacks import DEFAULT_CHECKPOINT, DEFAULT_USER
from auth_reference.v3db_adapter import (
    build_all_visible_auth_labels,
    build_candidates_from_v3db_query,
    build_fixed_shape_slot_buffers,
    compare_with_v3db_topk,
    compute_v3db_slot_distances,
    run_all_visible_authorized_reference,
    v3db_baseline_topk,
)
from ivf_pq.zk import ivf_pq_learn
from zk_IVF_PQ.zk_IVF_PQ import (
    py_set_based_auth_all_visible_with_merkle,
    py_set_based_with_merkle,
    single_hash,
)


def _compute_cluster_root(cluster_index, vpqs, valids, items):
    capacity, _ = vpqs.shape
    hash_list = []
    for j in range(capacity):
        left = np.array(
            [cluster_index, j, int(valids[j]), int(items[j])],
            dtype=np.int64,
        )
        leaf = np.concatenate([left, vpqs[j].astype(np.int64)])
        hash_list.append(single_hash(leaf))
    while len(hash_list) > 1:
        hash_list = [
            single_hash([hash_list[2 * i], hash_list[2 * i + 1]])
            for i in range(len(hash_list) // 2)
        ]
    return np.uint64(hash_list[0])


def _build_merkle_proof_inputs(
    query,
    center,
    code_books,
    quant_vecs,
    id_groups,
    n_probe,
):
    """Mirror ivf_pq/merkle_zk.py proof=True buffer + root construction."""
    query = np.asarray(query, dtype=np.int64)
    center = np.asarray(center, dtype=np.int64)
    code_books = np.rint(code_books).astype(np.int64)
    quant_vecs = np.asarray(quant_vecs, dtype=np.int64)

    diff = center - query
    dist2 = (diff * diff).sum(axis=1, dtype=np.int64)
    sorted_idx = np.argsort(dist2, kind="stable")
    cluster_idx_dis = np.stack([sorted_idx, dist2[sorted_idx]], axis=1).astype(np.int64)
    cluster_idxes = sorted_idx[:n_probe]

    buffers = build_fixed_shape_slot_buffers(
        query, center, quant_vecs, id_groups, n_probe
    )
    n_list, m = center.shape[0], int(quant_vecs.shape[1])
    ivf_roots = np.zeros((n_list,), dtype=np.uint64)
    visited = np.zeros((n_list,), dtype=bool)

    for probe_pos, cluster_index in enumerate(cluster_idxes):
        ci = int(cluster_index)
        vpqs = buffers.vpqss[probe_pos]
        valids = buffers.valids[probe_pos]
        items = buffers.itemss[probe_pos]
        ivf_roots[ci] = _compute_cluster_root(ci, vpqs, valids, items)
        visited[ci] = True

    for ci in range(n_list):
        if visited[ci]:
            continue
        vector_ids = id_groups[ci]
        vpqs = np.zeros((buffers.capacity, m), dtype=np.int64)
        valids = np.zeros((buffers.capacity,), dtype=np.int64)
        items = np.zeros((buffers.capacity,), dtype=np.int64)
        for local_pos, vec_id in enumerate(vector_ids):
            if local_pos >= buffers.capacity:
                break
            items[local_pos] = int(vec_id)
            valids[local_pos] = 1
            vpqs[local_pos, :] = quant_vecs[int(vec_id)]
        ivf_roots[ci] = _compute_cluster_root(ci, vpqs, valids, items)

    return {
        "query": query,
        "center": center,
        "code_books": code_books,
        "vpqss": buffers.vpqss,
        "valids": buffers.valids,
        "itemss": buffers.itemss,
        "ivf_roots": ivf_roots,
        "cluster_idx_dis": cluster_idx_dis,
        "buffers": buffers,
    }


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


def test_auth_zk_all_visible_prove_verify_and_matches_baseline(synthetic_zk_index):
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
    candidates, slot_rows, buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels,
    )

    baseline_topk = v3db_baseline_topk(slot_rows, idx["top_k"])
    _result, auth_topk, v3db_topk = run_all_visible_authorized_reference(
        candidates,
        user,
        checkpoint,
        idx["top_k"],
        slot_rows,
        n_probe=buffers.n_probe,
        slots_per_list=buffers.capacity,
    )
    assert compare_with_v3db_topk(auth_topk, v3db_topk)
    assert compare_with_v3db_topk(baseline_topk, v3db_topk)

    common_args = (
        inputs["query"].tolist(),
        inputs["center"].tolist(),
        inputs["vpqss"].tolist(),
        inputs["valids"].tolist(),
        inputs["itemss"].tolist(),
        inputs["code_books"].tolist(),
        inputs["ivf_roots"].tolist(),
        int(idx["top_k"]),
        inputs["cluster_idx_dis"].tolist(),
        [],
    )

    baseline_metrics = py_set_based_with_merkle(*common_args)
    auth_metrics = py_set_based_auth_all_visible_with_merkle(*common_args)

    _build_b, _prove_b, verify_b, _size_b, _mem_b, gates_b = baseline_metrics
    _build_a, _prove_a, verify_a, _size_a, _mem_a, gates_a = auth_metrics

    assert verify_b > 0.0, "baseline proof verify should succeed"
    assert verify_a > 0.0, "auth all-visible proof verify should succeed"
    assert gates_a >= gates_b, "auth path adds mask gadget overhead"

    slot_rows_check = compute_v3db_slot_distances(
        idx["query"], idx["center"], idx["code_books"], inputs["buffers"]
    )
    expected_topk = v3db_baseline_topk(slot_rows_check, idx["top_k"])
    assert compare_with_v3db_topk(expected_topk, baseline_topk)
