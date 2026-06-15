"""
Adapter between V3DB Python slot buffers and auth_reference.CandidateRecord.

V3DB fixed-shape structures (proof=True path in ivf_pq/merkle_zk.py):
  vpqss   : (n_probe, capacity, M)  PQ code indices per slot
  valids  : (n_probe, capacity)     1 if real vector, 0 if padding
  itemss  : (n_probe, capacity)     vector / item id (cid)
  cluster_idxes : (n_probe,)        selected inverted-list ids

Distances are NOT stored in buffers; they are computed via ADC/PQ lookup
(code_books + residual query). The closest safe conversion point is after
V3DB step-4 scoring (same loop as merkle_zk.py lines 185-196).

Limitation: proof=False fast path uses variable-length clusters without padding
slots; this adapter targets the fixed-shape proof path only.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from auth_reference.policy import compute_visibility
from auth_reference.records import AuthLabel, CandidateRecord, Checkpoint, UserContext
from auth_reference.reference import (
    DEFAULT_D_MAX,
    AuthorizedReferenceResult,
    run_authorized_reference,
    score_candidate,
)

V3DB_MAX_DIS = DEFAULT_D_MAX


@dataclass
class V3DBSlotBuffers:
    """Fixed-shape slot buffers for probed lists."""

    vpqss: np.ndarray  # (n_probe, capacity, M)
    valids: np.ndarray  # (n_probe, capacity)
    itemss: np.ndarray  # (n_probe, capacity)
    cluster_idxes: np.ndarray  # (n_probe,)
    capacity: int
    n_probe: int


def cluster_capacity(id_groups: dict) -> int:
    """Power-of-two capacity >= max cluster size (mirrors merkle_zk._build_cluster_capacity)."""
    sizes = [group.shape[0] for group in id_groups.values()]
    if not sizes:
        return 1
    max_size = max(sizes)
    cap = 1
    while cap < max_size:
        cap *= 2
    return cap


def build_fixed_shape_slot_buffers(
    query: np.ndarray,
    center: np.ndarray,
    quant_vecs: np.ndarray,
    id_groups: dict,
    n_probe: int,
) -> V3DBSlotBuffers:
    """
    Build vpqss / valids / itemss for probed lists without Merkle or Rust calls.

    Mirrors ivf_pq/merkle_zk.py proof=True slot construction (steps 1-2.1).
    """
    query = np.asarray(query, dtype=np.int64)
    center = np.asarray(center, dtype=np.int64)
    quant_vecs = np.asarray(quant_vecs, dtype=np.int64)

    diff = center - query
    dist2 = (diff * diff).sum(axis=1, dtype=np.int64)
    sorted_idx = np.argsort(dist2, kind="stable")
    cluster_idxes = sorted_idx[:n_probe]

    capacity = cluster_capacity(id_groups)
    m = int(quant_vecs.shape[1])
    vpqss_list = []
    valids_list = []
    itemss_list = []

    for cluster_index in cluster_idxes:
        ci = int(cluster_index)
        vector_ids = id_groups[ci]
        vpqs = np.zeros((capacity, m), dtype=np.int64)
        valids = np.zeros((capacity,), dtype=np.int64)
        items = np.zeros((capacity,), dtype=np.int64)

        for local_pos, vec_id in enumerate(vector_ids):
            if local_pos >= capacity:
                break
            vid = int(vec_id)
            items[local_pos] = vid
            valids[local_pos] = 1
            vpqs[local_pos, :] = quant_vecs[vid]

        vpqss_list.append(vpqs)
        valids_list.append(valids)
        itemss_list.append(items)

    return V3DBSlotBuffers(
        vpqss=np.stack(vpqss_list, axis=0),
        valids=np.stack(valids_list, axis=0),
        itemss=np.stack(itemss_list, axis=0),
        cluster_idxes=cluster_idxes.astype(np.int64),
        capacity=capacity,
        n_probe=int(n_probe),
    )


def compute_v3db_slot_distances(
    query: np.ndarray,
    center: np.ndarray,
    code_books: np.ndarray,
    buffers: V3DBSlotBuffers,
) -> list[tuple[int, int, int, int, bool, int]]:
    """
    ADC/PQ distances per slot (mirrors merkle_zk.py step 3).

    Returns list of (probe_pos, list_id, slot_id, cid, distance, valid) in
    slot iteration order.
    """
    query = np.asarray(query, dtype=np.int64)
    center = np.asarray(center, dtype=np.int64)
    code_books = np.rint(code_books).astype(np.int64)
    m, _, d = code_books.shape

    rows: list[tuple[int, int, int, int, bool]] = []
    for probe_pos, cluster_index in enumerate(buffers.cluster_idxes):
        ci = int(cluster_index)
        delta = query - center[ci]
        for slot_id in range(buffers.capacity):
            valid = bool(buffers.valids[probe_pos, slot_id])
            cid = int(buffers.itemss[probe_pos, slot_id])
            codes = buffers.vpqss[probe_pos, slot_id]
            selected = code_books[np.arange(m), codes]
            code_vec = selected.reshape(m * d)
            curr_diff = delta - code_vec
            dist = int(np.dot(curr_diff, curr_diff))
            if not valid:
                dist = V3DB_MAX_DIS
            rows.append((probe_pos, ci, slot_id, cid, valid, dist))
    return rows


def candidate_records_from_slot_buffers(
    slot_rows: list[tuple[int, int, int, int, bool, int]],
    labels: dict[int, AuthLabel],
    *,
    default_label: AuthLabel | None = None,
) -> list[CandidateRecord]:
    """Convert scored slot rows to CandidateRecord list (slot iteration order)."""
    default = default_label or AuthLabel(
        tenant="acme",
        project="proj-a",
        level=1,
        state="active",
        epoch=1,
    )
    out: list[CandidateRecord] = []
    for _probe_pos, list_id, slot_id, cid, valid, distance in slot_rows:
        label = labels.get(cid, default)
        out.append(
            CandidateRecord(
                cid=cid,
                list_id=list_id,
                slot_id=slot_id,
                valid=valid,
                distance=int(distance),
                label=label,
            )
        )
    return out


def build_synthetic_user_context(
    *,
    user_id: str = "alice",
    tenant: str = "acme",
    projects: frozenset[str] | None = None,
    clearance: int = 10,
    roles: frozenset[str] | None = None,
    epoch: int = 1,
) -> UserContext:
    return UserContext(
        user_id=user_id,
        tenant=tenant,
        projects=projects or frozenset({"proj-a"}),
        clearance=clearance,
        roles=roles or frozenset({"analyst"}),
        epoch=epoch,
    )


def build_all_visible_auth_labels(
    cids: list[int] | set[int],
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    project: str | None = None,
) -> dict[int, AuthLabel]:
    """Labels that satisfy P(gamma_U, lambda_x, sigma)=1 for every cid."""
    proj = project or next(iter(user.projects))
    return {
        int(cid): AuthLabel(
            tenant=user.tenant,
            project=proj,
            level=user.clearance,
            state="active",
            epoch=checkpoint.epoch,
            roles=user.roles,
        )
        for cid in cids
    }


def build_partial_visible_labels(
    visible_cids: set[int],
    invisible_cids: set[int],
    user: UserContext,
    checkpoint: Checkpoint,
) -> dict[int, AuthLabel]:
    """Visible cids match user; invisible use wrong tenant."""
    labels = build_all_visible_auth_labels(visible_cids, user, checkpoint)
    for cid in invisible_cids:
        labels[int(cid)] = AuthLabel(
            tenant="other-tenant",
            project="proj-a",
            level=1,
            state="active",
            epoch=checkpoint.epoch,
        )
    return labels


def v3db_baseline_topk(
    slot_rows: list[tuple[int, int, int, int, bool, int]],
    top_k: int,
) -> list[int]:
    """
    V3DB top-k: stable sort by effective distance, preserve slot iteration order on ties.

    Matches merkle_zk.py lines 198-201.
    """
    pairs = [(row[3], row[5]) for row in slot_rows]  # (cid, distance)
    order = sorted(range(len(pairs)), key=lambda i: pairs[i][1])
    return [pairs[i][0] for i in order[:top_k]]


def authorized_topk_v3db_tiebreak(
    scored_in_slot_order: list,
    top_k: int,
) -> list[int]:
    """
    Authorized top-k with V3DB-compatible tie-breaking (distance only, stable order).

    Use for all-visible regression where masked_distance equals V3DB effective distance.
    """
    order = sorted(range(len(scored_in_slot_order)), key=lambda i: scored_in_slot_order[i].masked_distance)
    return [scored_in_slot_order[i].cid for i in order[:top_k]]


def compare_with_v3db_topk(auth_topk: list[int], v3db_topk: list[int]) -> bool:
    return list(auth_topk) == list(v3db_topk)


def run_all_visible_authorized_reference(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
    slot_rows: list[tuple[int, int, int, int, bool, int]],
    *,
    n_probe: int,
    slots_per_list: int,
) -> tuple[AuthorizedReferenceResult, list[int], list[int]]:
    """
    Run authorized reference under all-visible labels and compare with V3DB baseline.

    Returns (reference result, auth_topk_v3db_tiebreak, v3db_baseline_topk).
    """
    result = run_authorized_reference(
        candidates,
        user,
        checkpoint,
        top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    auth_topk = authorized_topk_v3db_tiebreak(result.scored, top_k)
    baseline = v3db_baseline_topk(slot_rows, top_k)
    return result, auth_topk, baseline


def build_candidates_from_v3db_query(
    query: np.ndarray,
    center: np.ndarray,
    code_books: np.ndarray,
    quant_vecs: np.ndarray,
    id_groups: dict,
    n_probe: int,
    labels: dict[int, AuthLabel],
) -> tuple[list[CandidateRecord], list[tuple[int, int, int, int, bool, int]], V3DBSlotBuffers]:
    """End-to-end: slot buffers -> distances -> CandidateRecords."""
    buffers = build_fixed_shape_slot_buffers(
        query, center, quant_vecs, id_groups, n_probe
    )
    slot_rows = compute_v3db_slot_distances(query, center, code_books, buffers)
    candidates = candidate_records_from_slot_buffers(slot_rows, labels)
    return candidates, slot_rows, buffers
