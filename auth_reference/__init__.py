"""Plaintext authorized IVF-PQ reference (Phase 1B)."""

from auth_reference.policy import compute_visibility, evaluate_policy
from auth_reference.post_filter import run_post_filter_baseline
from auth_reference.records import (
    AuthLabel,
    AuthorizedReferenceResult,
    CandidateRecord,
    Checkpoint,
    ContentSlotRecord,
    ScoredCandidate,
    UserContext,
)
from auth_reference.reference import (
    DEFAULT_D_MAX,
    authorized_topk,
    check_candidate_coverage,
    compute_masked_distance,
    run_authorized_reference,
    score_candidate,
    verify_label_commitment,
    verify_visibility_consistency,
)

__all__ = [
    "AuthLabel",
    "AuthorizedReferenceResult",
    "CandidateRecord",
    "Checkpoint",
    "ContentSlotRecord",
    "DEFAULT_D_MAX",
    "ScoredCandidate",
    "UserContext",
    "authorized_topk",
    "check_candidate_coverage",
    "compute_masked_distance",
    "compute_visibility",
    "evaluate_policy",
    "run_authorized_reference",
    "run_post_filter_baseline",
    "score_candidate",
    "verify_label_commitment",
    "verify_visibility_consistency",
]
