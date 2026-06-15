"""Post-filter baseline for semantic comparison."""

from __future__ import annotations

from auth_reference.policy import compute_visibility
from auth_reference.records import CandidateRecord, Checkpoint, UserContext


def run_post_filter_baseline(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
) -> list[int]:
    """
    Weak semantics: TopK_k by raw distance, then filter to visible objects.

    R_post = Filter(TopK_k({(x, d_x)}), V(U, sigma))

    Only valid candidates participate in raw ranking. Result may contain
    fewer than top_k items when invisible objects occupy raw top-k slots.
    """
    valid = [c for c in candidates if c.valid]
    ranked = sorted(valid, key=lambda c: (c.distance, c.cid))
    raw_top = ranked[:top_k]
    visible = [
        c
        for c in raw_top
        if compute_visibility(user, c.label, checkpoint) == 1
    ]
    return [c.cid for c in visible]
