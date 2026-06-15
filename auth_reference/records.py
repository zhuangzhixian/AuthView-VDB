"""Data structures for plaintext authorized retrieval reference."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Set


@dataclass(frozen=True)
class AuthLabel:
    """Access label lambda_x at a checkpoint."""

    tenant: str
    project: str
    level: int
    state: str = "active"
    epoch: int = 0
    roles: FrozenSet[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class UserContext:
    """User authorization context gamma_U."""

    user_id: str
    tenant: str
    projects: FrozenSet[str]
    clearance: int
    roles: FrozenSet[str] = field(default_factory=frozenset)
    epoch: int = 0


@dataclass(frozen=True)
class Checkpoint:
    """Authorization state checkpoint sigma."""

    checkpoint_id: str
    epoch: int
    policy_id: str = "default-v1"


@dataclass(frozen=True)
class ContentSlotRecord:
    """Content-side slot record from committed snapshot S."""

    cid: int
    list_id: int
    slot_id: int
    valid: bool
    distance: int


@dataclass(frozen=True)
class CandidateRecord:
    """Candidate slot with content distance and auth label."""

    cid: int
    list_id: int
    slot_id: int
    valid: bool
    distance: int
    label: AuthLabel


@dataclass
class ScoredCandidate:
    """Candidate after visibility and masking."""

    cid: int
    list_id: int
    slot_id: int
    valid: bool
    distance: int
    label: AuthLabel
    visibility: int
    hat_distance: int
    masked_distance: int


@dataclass
class AuthorizedReferenceResult:
    """Output of run_authorized_reference."""

    top_k_cids: list[int]
    scored: list[ScoredCandidate]
    checkpoint: Checkpoint
    user: UserContext
