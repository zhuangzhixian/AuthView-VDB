"""Tests for V3DB candidate-buffer adapter (Phase 1C)."""

from __future__ import annotations

import numpy as np
import pytest

from auth_reference.attacks import DEFAULT_CHECKPOINT, DEFAULT_USER
from auth_reference.policy import compute_visibility
from auth_reference.reference import DEFAULT_D_MAX, authorized_topk
from auth_reference.v3db_adapter import (
    build_all_visible_auth_labels,
    build_candidates_from_v3db_query,
    build_partial_visible_labels,
    build_synthetic_user_context,
    compare_with_v3db_topk,
    run_all_visible_authorized_reference,
    v3db_baseline_topk,
)
from ivf_pq.zk import ivf_pq_learn


@pytest.fixture
def synthetic_index():
    """Small IVF-PQ index for adapter tests (no Rust required)."""
    rng = np.random.default_rng(123)
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


def test_all_visible_regression_matches_v3db_baseline(synthetic_index):
    idx = synthetic_index
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

    result, auth_topk, baseline = run_all_visible_authorized_reference(
        candidates,
        user,
        checkpoint,
        idx["top_k"],
        slot_rows,
        n_probe=buffers.n_probe,
        slots_per_list=buffers.capacity,
    )

    assert compare_with_v3db_topk(auth_topk, baseline)
    for sc in result.scored:
        if sc.valid:
            assert sc.visibility == 1
            assert sc.masked_distance == sc.distance
            assert sc.hat_distance == sc.distance


def test_all_visible_matches_merkle_zk_scoring_path(synthetic_index):
    """Adapter baseline top-k matches merkle_zk fixed-shape scoring (no Rust proof)."""
    idx = synthetic_index
    candidates, slot_rows, _buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels={},
    )
    baseline = v3db_baseline_topk(slot_rows, idx["top_k"])

    # Recompute like merkle_zk.py: only valid slots contribute non-max distances
    max_dis = DEFAULT_D_MAX
    pairs = []
    for row in slot_rows:
        cid, dist, valid = row[3], row[5], row[4]
        pairs.append((cid, dist if valid else max_dis))
    order = sorted(range(len(pairs)), key=lambda i: pairs[i][1])
    expected = [pairs[i][0] for i in order[: idx["top_k"]]]
    assert baseline == expected


def test_partial_visible_smoke(synthetic_index):
    idx = synthetic_index
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
    valid_cids = [r[3] for r in valid_rows]
    assert len(valid_cids) >= 4

    by_dist = sorted(valid_rows, key=lambda r: r[5])
    invisible_cids = {by_dist[0][3], by_dist[1][3]}
    visible_cids = set(valid_cids) - invisible_cids

    labels = build_partial_visible_labels(visible_cids, invisible_cids, user, checkpoint)
    candidates, slot_rows, buffers = build_candidates_from_v3db_query(
        idx["query"],
        idx["center"],
        idx["code_books"],
        idx["quant_vecs"],
        idx["id_groups"],
        idx["n_probe"],
        labels,
    )

    from auth_reference.reference import run_authorized_reference

    result = run_authorized_reference(
        candidates,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=buffers.n_probe,
        slots_per_list=buffers.capacity,
    )
    topk = authorized_topk(result.scored, idx["top_k"])

    for sc in result.scored:
        if sc.cid in invisible_cids and sc.valid:
            assert sc.visibility == 0
            assert sc.masked_distance == DEFAULT_D_MAX
            assert sc.hat_distance == DEFAULT_D_MAX

    for cid in topk:
        if cid in invisible_cids:
            pytest.fail("invisible candidate in authorized top-k")

    for cid in topk:
        c = next(x for x in candidates if x.cid == cid)
        if c.valid:
            assert compute_visibility(user, c.label, checkpoint) == 1


def test_invalid_padding_slots_demoted(synthetic_index):
    idx = synthetic_index
    user = DEFAULT_USER
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
    valid_cids = {r[3] for r in slot_rows if r[4]}
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

    from auth_reference.reference import run_authorized_reference

    result = run_authorized_reference(
        candidates,
        user,
        checkpoint,
        idx["top_k"],
        n_probe=buffers.n_probe,
        slots_per_list=buffers.capacity,
    )
    for sc in result.scored:
        if not sc.valid:
            assert sc.distance == DEFAULT_D_MAX
            assert sc.masked_distance == DEFAULT_D_MAX
