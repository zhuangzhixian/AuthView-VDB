"""Phase 4C: systematic attack matrix tests for RQ1."""

from __future__ import annotations

import numpy as np
import pytest

from auth_reference.attacks import (
    DEFAULT_CHECKPOINT,
    DEFAULT_USER,
    build_post_filter_contrast_candidates,
)
from auth_reference.post_filter import run_post_filter_baseline
from auth_reference.reference import run_authorized_reference
from auth_reference.slot_aligned_auth_commitment import (
    build_slot_aligned_auth_tree,
    open_list_auth_root,
)
from auth_reference.v3db_adapter import (
    authorized_topk_v3db_tiebreak,
    build_all_visible_auth_labels,
    build_candidates_from_v3db_query,
    build_committed_auth_witness,
    build_partial_visible_labels,
    build_slot_aligned_zk_witness_for_buffers,
    build_synthetic_user_context,
    encode_user_context_for_zk,
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


def _zk_inputs(idx):
    return _build_merkle_proof_inputs(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
    )


def _partial_visible_setup(idx):
    inputs = _zk_inputs(idx)
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
    return idx, inputs, user, checkpoint, buffers, labels, invisible_cids, visible_cids


def _all_visible_setup(idx):
    inputs = _zk_inputs(idx)
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
    return idx, inputs, user, checkpoint, buffers, labels


def _call_committed(idx, inputs, user, checkpoint, committed_w):
    user_w = encode_user_context_for_zk(user, checkpoint)
    return py_set_based_auth_committed_with_merkle(
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


def _call_slot_aligned(idx, inputs, user, checkpoint, slot_w):
    user_w = encode_user_context_for_zk(user, checkpoint)
    return py_set_based_auth_slot_aligned_with_merkle(
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


# --- A1 plaintext ---


def test_a1_post_filter_insufficiency():
    """A1: post-filter may miss authorized top-k."""
    candidates = build_post_filter_contrast_candidates()
    user = DEFAULT_USER
    checkpoint = DEFAULT_CHECKPOINT
    top_k = 2

    post = run_post_filter_baseline(candidates, user, checkpoint, top_k)
    result = run_authorized_reference(candidates, user, checkpoint, top_k)
    auth_topk = authorized_topk_v3db_tiebreak(result.scored, top_k)

    assert post == []
    assert auth_topk == [203, 204]


# --- A2–A5 global committed ZK ---


def test_a2_committed_forged_tenant_zk_fails(synthetic_zk_index):
    """A2: unauthorized tenant forgery fails under committed root_auth."""
    idx, inputs, user, checkpoint, buffers, labels, invisible_cids, _visible = (
        _partial_visible_setup(synthetic_zk_index)
    )
    user_w = encode_user_context_for_zk(user, checkpoint)
    committed_w = build_committed_auth_witness(buffers, labels)

    forged_tenant = int(user_w["user_tenant_id"])
    n_probe, capacity = buffers.valids.shape
    tampered = False
    for i in range(n_probe):
        for j in range(capacity):
            if int(buffers.itemss[i, j]) in invisible_cids:
                committed_w["object_tenant_ids"][i][j] = forged_tenant
                tampered = True
                break
        if tampered:
            break
    assert tampered

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed failed"):
        _call_committed(idx, inputs, user, checkpoint, committed_w)


def test_a3_committed_wrong_auth_path_zk_fails(synthetic_zk_index):
    """A3: wrong Merkle auth path sibling fails."""
    idx, inputs, user, checkpoint, buffers, labels = _all_visible_setup(synthetic_zk_index)
    committed_w = build_committed_auth_witness(buffers, labels)
    committed_w["auth_path_siblings"][0][0][0] ^= 1

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed failed"):
        _call_committed(idx, inputs, user, checkpoint, committed_w)


def test_a4_committed_forged_level_zk_fails(synthetic_zk_index):
    """A4: visibility field (level) forgery inconsistent with Merkle leaf."""
    idx, inputs, user, checkpoint, buffers, labels, _invisible, visible_cids = (
        _partial_visible_setup(synthetic_zk_index)
    )
    committed_w = build_committed_auth_witness(buffers, labels)

    target_cid = next(iter(visible_cids))
    n_probe, capacity = buffers.valids.shape
    tampered = False
    for i in range(n_probe):
        for j in range(capacity):
            if int(buffers.itemss[i, j]) == target_cid:
                committed_w["object_levels"][i][j] = 1
                tampered = True
                break
        if tampered:
            break
    assert tampered

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed failed"):
        _call_committed(idx, inputs, user, checkpoint, committed_w)


def test_a5_committed_root_label_mixing_zk_fails(synthetic_zk_index):
    """A5: root_auth from one label set, paths/witness from another."""
    idx, inputs, user, checkpoint, buffers, labels = _all_visible_setup(synthetic_zk_index)
    committed_w = build_committed_auth_witness(buffers, labels)

    alt_labels = dict(labels)
    first_cid = next(iter(alt_labels))
    base = alt_labels[first_cid]
    alt_labels[first_cid] = base.__class__(
        tenant="other-tenant",
        project=base.project,
        level=base.level,
        state=base.state,
        epoch=base.epoch,
        roles=base.roles,
    )
    alt_w = build_committed_auth_witness(buffers, alt_labels)
    committed_w["root_auth"] = alt_w["root_auth"]

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed failed"):
        _call_committed(idx, inputs, user, checkpoint, committed_w)


def test_a12_committed_user_clearance_mismatch_zk_fails(synthetic_zk_index):
    """A12: witness label level tampered under verifier-pinned low clearance."""
    idx, inputs, user, checkpoint, buffers, labels, _invisible, visible_cids = (
        _partial_visible_setup(synthetic_zk_index)
    )
    committed_w = build_committed_auth_witness(buffers, labels)

    low_clearance_user = build_synthetic_user_context(clearance=1, epoch=checkpoint.epoch)
    n_probe, capacity = buffers.valids.shape
    target_cid = next(iter(visible_cids))
    tampered = False
    for i in range(n_probe):
        for j in range(capacity):
            if int(buffers.itemss[i, j]) == target_cid:
                committed_w["object_levels"][i][j] = 1
                tampered = True
                break
        if tampered:
            break
    assert tampered

    with pytest.raises(RuntimeError, match="set_based_auth_ivf_pq_proof_committed failed"):
        _call_committed(idx, inputs, low_clearance_user, checkpoint, committed_w)


# --- A2b, A6–A8 slot-aligned ZK ---


def test_a2b_slot_aligned_forged_tenant_zk_fails(synthetic_zk_index):
    """A2b: slot-aligned tenant forgery fails."""
    idx, inputs, user, checkpoint, buffers, labels, invisible_cids, _visible = (
        _partial_visible_setup(synthetic_zk_index)
    )
    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )

    forged_tenant = int(user_w["user_tenant_id"])
    n_probe, capacity = buffers.valids.shape
    tampered = False
    for i in range(n_probe):
        for j in range(capacity):
            if int(buffers.itemss[i, j]) in invisible_cids:
                slot_w["object_tenant_ids"][i][j] = forged_tenant
                tampered = True
                break
        if tampered:
            break
    assert tampered

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        _call_slot_aligned(idx, inputs, user, checkpoint, slot_w)


def test_a6_slot_aligned_cross_list_graft_zk_fails(synthetic_zk_index):
    """A6: cross-list graft of top path / list root fails."""
    idx, inputs, user, checkpoint, buffers, labels = _all_visible_setup(synthetic_zk_index)
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
    graft = open_list_auth_root(dummy_tree, other_list)
    slot_w["list_auth_roots"][0] = int(graft.list_auth_root)
    slot_w["top_path_directions"][0] = list(graft.top_path_directions)
    slot_w["top_path_siblings"][0] = list(graft.top_path_siblings)

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        _call_slot_aligned(idx, inputs, user, checkpoint, slot_w)


def test_a7_slot_aligned_wrong_intra_path_zk_fails(synthetic_zk_index):
    """A7: corrupted intra-list Merkle path fails."""
    idx, inputs, user, checkpoint, buffers, labels = _all_visible_setup(synthetic_zk_index)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )
    slot_w["intra_path_siblings"][0][0][0] ^= 1

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        _call_slot_aligned(idx, inputs, user, checkpoint, slot_w)


def test_a8_slot_aligned_wrong_top_path_zk_fails(synthetic_zk_index):
    """A8: corrupted top-level Merkle path fails."""
    idx, inputs, user, checkpoint, buffers, labels = _all_visible_setup(synthetic_zk_index)
    slot_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=idx["n_list"]
    )
    slot_w["top_path_siblings"][0][0] ^= 1

    with pytest.raises(
        RuntimeError,
        match="set_based_auth_ivf_pq_proof_committed_slot_aligned failed",
    ):
        _call_slot_aligned(idx, inputs, user, checkpoint, slot_w)


def test_attack_matrix_registry_row_count():
    """Ensure registry documents all matrix rows for CSV export."""
    from auth_reference.attack_matrix import ATTACK_MATRIX

    assert len(ATTACK_MATRIX) >= 12
    statuses = {row.status for row in ATTACK_MATRIX}
    assert statuses >= {"passed", "plaintext_only", "partially_covered", "out_of_scope"}
