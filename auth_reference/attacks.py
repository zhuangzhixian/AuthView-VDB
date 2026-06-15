"""Synthetic attack scenarios for plaintext reference tests."""

from __future__ import annotations

from auth_reference.policy import evaluate_policy
from auth_reference.records import (
    AuthLabel,
    CandidateRecord,
    Checkpoint,
    ScoredCandidate,
    UserContext,
)
from auth_reference.reference import (
    DEFAULT_D_MAX,
    compute_masked_distance,
    score_candidate,
)

DEFAULT_CHECKPOINT = Checkpoint(checkpoint_id="sigma-1", epoch=1)
DEFAULT_USER = UserContext(
    user_id="alice",
    tenant="acme",
    projects=frozenset({"proj-a"}),
    clearance=3,
    roles=frozenset({"analyst"}),
    epoch=1,
)


def _label(
    cid: int,
    *,
    tenant: str = "acme",
    project: str = "proj-a",
    level: int = 2,
    state: str = "active",
    epoch: int = 1,
    roles: frozenset[str] | None = None,
) -> AuthLabel:
    return AuthLabel(
        tenant=tenant,
        project=project,
        level=level,
        state=state,
        epoch=epoch,
        roles=roles or frozenset(),
    )


def _candidate(
    cid: int,
    list_id: int,
    slot_id: int,
    distance: int,
    *,
    valid: bool = True,
    label: AuthLabel | None = None,
) -> CandidateRecord:
    return CandidateRecord(
        cid=cid,
        list_id=list_id,
        slot_id=slot_id,
        valid=valid,
        distance=distance,
        label=label or _label(cid),
    )


def build_compliant_candidates() -> list[CandidateRecord]:
    """Mixed visibility; authorized top-k should rank visible objects correctly."""
    return [
        _candidate(101, 0, 0, 10, label=_label(101, level=2)),
        _candidate(102, 0, 1, 12, label=_label(102, tenant="other")),
        _candidate(103, 0, 2, 15, label=_label(103, level=2)),
        _candidate(104, 1, 0, 11, label=_label(104, level=2)),
        _candidate(105, 1, 1, 20, label=_label(105, level=2)),
        _candidate(106, 1, 2, 8, label=_label(106, tenant="other")),
    ]


def build_post_filter_contrast_candidates() -> list[CandidateRecord]:
    """
    Invisible objects occupy raw top-k; post-filter drops them and misses
    closer visible neighbors outside raw top-k.
    """
    return [
        _candidate(201, 0, 0, 5, label=_label(201, tenant="other")),
        _candidate(202, 0, 1, 7, label=_label(202, tenant="other")),
        _candidate(203, 1, 0, 18, label=_label(203, level=2)),
        _candidate(204, 1, 1, 20, label=_label(204, level=2)),
    ]


def build_skipped_candidate_subset() -> tuple[list[CandidateRecord], list[CandidateRecord]]:
    """Full Cand vs adversarial subset omitting closer visible slot."""
    full = [
        _candidate(301, 0, 0, 50, label=_label(301, level=2)),
        _candidate(302, 0, 1, 10, label=_label(302, level=2)),
        _candidate(303, 0, 2, 30, label=_label(303, level=2)),
    ]
    skipped = [full[0], full[2]]
    return full, skipped


def build_forged_label_case() -> tuple[list[CandidateRecord], dict[int, AuthLabel]]:
    """Candidate carries label that differs from committed auth state."""
    committed = {
        401: _label(401, tenant="other", level=2),
    }
    forged = [
        CandidateRecord(
            cid=401,
            list_id=0,
            slot_id=0,
            valid=True,
            distance=10,
            label=_label(401, level=2),
        )
    ]
    return forged, committed


def build_visibility_manipulation_case() -> tuple[CandidateRecord, ScoredCandidate]:
    """Visible object with adversarial v_x = 0."""
    cand = _candidate(501, 0, 0, 10, label=_label(501, level=2))
    scored = score_candidate(cand, DEFAULT_USER, DEFAULT_CHECKPOINT)
    manipulated = ScoredCandidate(
        cid=scored.cid,
        list_id=scored.list_id,
        slot_id=scored.slot_id,
        valid=scored.valid,
        distance=scored.distance,
        label=scored.label,
        visibility=0,
        hat_distance=DEFAULT_D_MAX,
        masked_distance=DEFAULT_D_MAX,
    )
    return cand, manipulated


def build_checkpoint_mismatch_label() -> CandidateRecord:
    """Label epoch inconsistent with checkpoint sigma."""
    return _candidate(
        601,
        0,
        0,
        10,
        label=_label(601, level=2, epoch=99),
    )


def all_items_authorized(cids: list[int], candidates: list[CandidateRecord]) -> bool:
    """Weaker check: every returned cid is visible (insufficient guarantee)."""
    by_cid = {c.cid: c for c in candidates}
    for cid in cids:
        c = by_cid[cid]
        if not evaluate_policy(DEFAULT_USER, c.label, DEFAULT_CHECKPOINT):
            return False
    return True
