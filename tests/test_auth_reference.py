"""Tests for plaintext authorized IVF-PQ reference (Phase 1B)."""

from __future__ import annotations

import pytest

from auth_reference.attacks import (
    DEFAULT_CHECKPOINT,
    DEFAULT_USER,
    all_items_authorized,
    build_checkpoint_mismatch_label,
    build_compliant_candidates,
    build_forged_label_case,
    build_post_filter_contrast_candidates,
    build_skipped_candidate_subset,
    build_visibility_manipulation_case,
)
from auth_reference.policy import evaluate_policy
from auth_reference.post_filter import run_post_filter_baseline
from auth_reference.reference import (
    DEFAULT_D_MAX,
    check_candidate_coverage,
    run_authorized_reference,
    verify_label_commitment,
    verify_visibility_consistency,
)


def test_compliant_case():
    candidates = build_compliant_candidates()
    result = run_authorized_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert result.top_k_cids == [101, 104, 103]
    for cid in result.top_k_cids:
        c = next(x for x in candidates if x.cid == cid)
        assert evaluate_policy(DEFAULT_USER, c.label, DEFAULT_CHECKPOINT)


def test_skipped_candidate_fails_coverage():
    full, skipped = build_skipped_candidate_subset()
    check_candidate_coverage(full, n_probe=1, slots_per_list=3)
    with pytest.raises(ValueError, match="candidate count"):
        check_candidate_coverage(skipped, n_probe=1, slots_per_list=3)


def test_forged_label_rejected():
    forged, committed = build_forged_label_case()
    with pytest.raises(ValueError, match="forged label"):
        verify_label_commitment(forged, committed)


def test_visibility_manipulation_detected():
    _, manipulated = build_visibility_manipulation_case()
    with pytest.raises(ValueError, match="visibility manipulation"):
        verify_visibility_consistency(
            [manipulated], DEFAULT_USER, DEFAULT_CHECKPOINT
        )


def test_checkpoint_mismatch_invisible():
    cand = build_checkpoint_mismatch_label()
    assert evaluate_policy(DEFAULT_USER, cand.label, DEFAULT_CHECKPOINT) is False
    result = run_authorized_reference(
        [cand],
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=1,
    )
    assert result.top_k_cids == [601]
    assert result.scored[0].visibility == 0
    assert result.scored[0].masked_distance == DEFAULT_D_MAX


def test_post_filter_missing_authorized_neighbor():
    candidates = build_post_filter_contrast_candidates()
    k = 2
    auth = run_authorized_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=k,
        n_probe=2,
        slots_per_list=2,
    )
    post = run_post_filter_baseline(
        candidates, DEFAULT_USER, DEFAULT_CHECKPOINT, top_k=k
    )
    assert auth.top_k_cids == [203, 204]
    assert post == []
    assert auth.top_k_cids != post
    assert all_items_authorized(post, candidates)


def test_per_item_authorized_insufficient():
    """Returned post-filter set can be authorized yet semantically wrong."""
    candidates = build_post_filter_contrast_candidates()
    post = run_post_filter_baseline(
        candidates, DEFAULT_USER, DEFAULT_CHECKPOINT, top_k=2
    )
    assert post == []
    assert all_items_authorized(post, candidates)
    auth = run_authorized_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=2,
        n_probe=2,
        slots_per_list=2,
    )
    assert 203 in auth.top_k_cids


def test_invalid_slot_demoted():
    candidates = build_compliant_candidates()
    invalid = candidates[0]
    candidates = [
        type(invalid)(
            cid=invalid.cid,
            list_id=invalid.list_id,
            slot_id=invalid.slot_id,
            valid=False,
            distance=1,
            label=invalid.label,
        ),
        *candidates[1:],
    ]
    result = run_authorized_reference(
        candidates,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k=3,
        n_probe=2,
        slots_per_list=3,
    )
    assert result.scored[0].masked_distance == DEFAULT_D_MAX
    assert 101 not in result.top_k_cids
