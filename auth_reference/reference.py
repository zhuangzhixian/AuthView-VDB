"""Plaintext authorized IVF-PQ retrieval reference."""

from __future__ import annotations

from auth_reference.policy import compute_visibility
from auth_reference.records import (
    AuthLabel,
    AuthorizedReferenceResult,
    CandidateRecord,
    Checkpoint,
    ScoredCandidate,
    UserContext,
)

# Match V3DB Merkle/set-based sentinel (2^62 - 1).
DEFAULT_D_MAX = (1 << 62) - 1


def compute_masked_distance(
    distance: int,
    valid: bool,
    visibility: int,
    d_max: int = DEFAULT_D_MAX,
) -> tuple[int, int]:
    """
    Compute hat_d and tilde_d (masked_distance).

    hat_d = v * d + (1 - v) * d_max
    tilde_d = f * hat_d + (1 - f) * d_max
    """
    hat = visibility * distance + (1 - visibility) * d_max
    valid_bit = 1 if valid else 0
    masked = valid_bit * hat + (1 - valid_bit) * d_max
    return hat, masked


def score_candidate(
    candidate: CandidateRecord,
    user: UserContext,
    checkpoint: Checkpoint,
    d_max: int = DEFAULT_D_MAX,
) -> ScoredCandidate:
    visibility = compute_visibility(user, candidate.label, checkpoint)
    hat, masked = compute_masked_distance(
        candidate.distance, candidate.valid, visibility, d_max
    )
    return ScoredCandidate(
        cid=candidate.cid,
        list_id=candidate.list_id,
        slot_id=candidate.slot_id,
        valid=candidate.valid,
        distance=candidate.distance,
        label=candidate.label,
        visibility=visibility,
        hat_distance=hat,
        masked_distance=masked,
    )


def authorized_topk(scored: list[ScoredCandidate], k: int) -> list[int]:
    """
    Top-k over masked distances with deterministic tie-break (masked_distance, cid).
    """
    ranked = sorted(scored, key=lambda c: (c.masked_distance, c.cid))
    return [c.cid for c in ranked[:k]]


def check_candidate_coverage(
    candidates: list[CandidateRecord],
    *,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
) -> None:
    """
    Verify fixed-shape candidate coverage Cand(q, S, theta).

    Raises ValueError if slots are missing, duplicated, or count mismatches.
    """
    if not candidates:
        raise ValueError("empty candidate set")

    keys = [(c.list_id, c.slot_id) for c in candidates]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate (list_id, slot_id) in candidate set")

    if n_probe is not None and slots_per_list is not None:
        expected = n_probe * slots_per_list
        if len(candidates) != expected:
            raise ValueError(
                f"candidate count {len(candidates)} != expected {expected}"
            )
        list_ids = {c.list_id for c in candidates}
        if len(list_ids) != n_probe:
            raise ValueError(
                f"distinct list_id count {len(list_ids)} != n_probe {n_probe}"
            )
        for lid in list_ids:
            slots = [c.slot_id for c in candidates if c.list_id == lid]
            if len(slots) != slots_per_list:
                raise ValueError(
                    f"list {lid}: slot count {len(slots)} != {slots_per_list}"
                )


def verify_visibility_consistency(
    scored: list[ScoredCandidate],
    user: UserContext,
    checkpoint: Checkpoint,
) -> None:
    """Reject visibility bits that do not match P(gamma_U, lambda_x, sigma)."""
    for c in scored:
        expected = compute_visibility(user, c.label, checkpoint)
        if c.visibility != expected:
            raise ValueError(
                f"visibility manipulation on cid={c.cid}: "
                f"claimed {c.visibility}, expected {expected}"
            )


def verify_label_commitment(
    candidates: list[CandidateRecord],
    committed_labels: dict[int, AuthLabel],
) -> None:
    """Reject forged labels not matching committed auth state."""
    for c in candidates:
        committed = committed_labels.get(c.cid)
        if committed is None:
            raise ValueError(f"missing committed label for cid={c.cid}")
        if c.label != committed:
            raise ValueError(f"forged label for cid={c.cid}")


def run_authorized_reference(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
    *,
    d_max: int = DEFAULT_D_MAX,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
    committed_labels: dict[int, AuthLabel] | None = None,
    verify_visibility: bool = True,
) -> AuthorizedReferenceResult:
    """
    Full authorized reference: coverage check, score, top-k.

    R = TopK_k({(x, tilde_d_x) | x in Cand})
    """
    check_candidate_coverage(
        candidates, n_probe=n_probe, slots_per_list=slots_per_list
    )
    if committed_labels is not None:
        verify_label_commitment(candidates, committed_labels)

    scored = [score_candidate(c, user, checkpoint, d_max) for c in candidates]
    if verify_visibility:
        verify_visibility_consistency(scored, user, checkpoint)

    top_k_cids = authorized_topk(scored, top_k)
    return AuthorizedReferenceResult(
        top_k_cids=top_k_cids,
        scored=scored,
        checkpoint=checkpoint,
        user=user,
    )
