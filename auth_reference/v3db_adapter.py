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

from auth_reference.auth_commitment import (
    AuthLabelLeaf,
    build_auth_tree_for_slot_labels,
    dummy_auth_label_for_slot,
    open_auth_label,
    split_auth_path,
)
from auth_reference.policy import compute_visibility
from auth_reference.records import AuthLabel, CandidateRecord, Checkpoint, UserContext
from auth_reference.reference import (
    DEFAULT_D_MAX,
    AuthorizedReferenceResult,
    compute_masked_distance,
    run_authorized_reference,
    score_candidate,
)

V3DB_MAX_DIS = DEFAULT_D_MAX

# Integer tag registries for ZK policy gadget (Phase 2B-3b sidecar witness).
ZK_MAX_PROJECTS = 4
ZK_TENANT_ID: dict[str, int] = {"acme": 1, "other-tenant": 2}
ZK_PROJECT_ID: dict[str, int] = {"proj-a": 10, "proj-b": 11}
ZK_STATE_ID: dict[str, int] = {"active": 1, "inactive": 0}
ZK_ACTIVE_STATE = 1


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


def encode_user_context_for_zk(
    user: UserContext,
    checkpoint: Checkpoint,
) -> dict[str, int | list[int]]:
    """Map plaintext user context to integer ZK policy witness fields."""
    projects = sorted(user.projects)
    project_ids = [ZK_PROJECT_ID[p] for p in projects[:ZK_MAX_PROJECTS]]
    project_valids = [1] * len(project_ids)
    while len(project_ids) < ZK_MAX_PROJECTS:
        project_ids.append(0)
        project_valids.append(0)
    return {
        "user_tenant_id": ZK_TENANT_ID[user.tenant],
        "user_project_ids": project_ids,
        "user_project_valids": project_valids,
        "user_clearance": int(user.clearance),
        "user_epoch": int(user.epoch),
        "checkpoint_epoch": int(checkpoint.epoch),
    }


def _encode_auth_label_for_zk(label: AuthLabel) -> tuple[int, int, int, int, int]:
    state = ZK_STATE_ID.get(label.state, 0)
    return (
        ZK_TENANT_ID[label.tenant],
        ZK_PROJECT_ID[label.project],
        int(label.level),
        state,
        int(label.epoch),
    )


def encode_slot_auth_labels_for_zk(
    buffers: V3DBSlotBuffers,
    labels: dict[int, AuthLabel],
    *,
    default_label: AuthLabel | None = None,
) -> dict[str, list[list[int]]]:
    """
    Per-slot integer auth label arrays shaped [n_probe][capacity].

    Sidecar witness for policy gadget; not Merkle-bound in Phase 2B-3b.
    """
    default = default_label or AuthLabel(
        tenant="acme",
        project="proj-a",
        level=1,
        state="active",
        epoch=1,
    )
    n_probe, capacity = buffers.valids.shape
    tenants: list[list[int]] = []
    projects: list[list[int]] = []
    levels: list[list[int]] = []
    states: list[list[int]] = []
    epochs: list[list[int]] = []

    for i in range(n_probe):
        row_t, row_p, row_l, row_s, row_e = [], [], [], [], []
        for j in range(capacity):
            cid = int(buffers.itemss[i, j])
            label = labels.get(cid, default)
            t, p, lv, st, ep = _encode_auth_label_for_zk(label)
            row_t.append(t)
            row_p.append(p)
            row_l.append(lv)
            row_s.append(st)
            row_e.append(ep)
        tenants.append(row_t)
        projects.append(row_p)
        levels.append(row_l)
        states.append(row_s)
        epochs.append(row_e)

    return {
        "object_tenant_ids": tenants,
        "object_project_ids": projects,
        "object_levels": levels,
        "object_states": states,
        "object_epochs": epochs,
    }


def build_ordered_auth_item_dis(
    candidates: list[CandidateRecord],
    user: UserContext,
    checkpoint: Checkpoint,
) -> list[list[int]]:
    """
    Build sorted (cid, hat_d) witness using plaintext oracle masking.

    Sort key matches circuit non-decreasing distance constraint (V3DB tie-break).
    """
    pairs: list[list[int]] = []
    for c in candidates:
        visibility = compute_visibility(user, c.label, checkpoint)
        _, masked = compute_masked_distance(c.distance, c.valid, visibility)
        pairs.append([c.cid, int(masked)])
    pairs.sort(key=lambda row: row[1])
    return pairs


def top_k_cids_from_ordered(ordered: list[list[int]], top_k: int) -> list[int]:
    """First k cids from sorted auth-masked (cid, distance) witness."""
    return [int(row[0]) for row in ordered[:top_k]]


def _slot_label_leaf_for_zk(
    cid: int,
    valid: bool,
    labels: dict[int, AuthLabel],
    default_label: AuthLabel,
) -> AuthLabelLeaf:
    """Auth label leaf for one slot; invalid slots use deterministic dummy fields."""
    if not valid:
        return dummy_auth_label_for_slot(cid)
    label = labels.get(cid, default_label)
    t, p, lv, st, ep = _encode_auth_label_for_zk(label)
    return AuthLabelLeaf(int(cid), t, p, lv, st, ep)


def build_committed_auth_witness(
    buffers: V3DBSlotBuffers,
    labels: dict[int, AuthLabel],
    *,
    default_label: AuthLabel | None = None,
) -> dict[str, int | list[list[int]] | list[list[list[int]]]]:
    """
    Build committed-auth ZK witness: root_auth + per-slot Merkle openings + label arrays.

    Leaf field order matches Rust `auth_label_leaf_fields`. Invalid padding slots
    use `(cid, 0, 0, 0, 0, 0)` with a valid opening under the same global tree.
    """
    default = default_label or AuthLabel(
        tenant="acme",
        project="proj-a",
        level=1,
        state="active",
        epoch=1,
    )
    n_probe, capacity = buffers.valids.shape

    flat_labels: list[AuthLabelLeaf] = []
    for i in range(n_probe):
        for j in range(capacity):
            cid = int(buffers.itemss[i, j])
            valid = bool(buffers.valids[i, j])
            flat_labels.append(
                _slot_label_leaf_for_zk(cid, valid, labels, default)
            )

    root_auth, hash_tree, _padded = build_auth_tree_for_slot_labels(flat_labels)
    depth = len(open_auth_label(0, hash_tree))

    tenants: list[list[int]] = []
    projects: list[list[int]] = []
    levels: list[list[int]] = []
    states: list[list[int]] = []
    epochs: list[list[int]] = []
    directions: list[list[list[int]]] = []
    siblings: list[list[list[int]]] = []

    leaf_idx = 0
    for i in range(n_probe):
        row_t, row_p, row_l, row_s, row_e = [], [], [], [], []
        row_d, row_sib = [], []
        for j in range(capacity):
            lbl = flat_labels[leaf_idx]
            row_t.append(lbl.tenant)
            row_p.append(lbl.project)
            row_l.append(lbl.level)
            row_s.append(lbl.state)
            row_e.append(lbl.epoch)
            path = open_auth_label(leaf_idx, hash_tree)
            d_row, s_row = split_auth_path(path)
            assert len(d_row) == depth
            row_d.append(d_row)
            row_sib.append(s_row)
            leaf_idx += 1
        tenants.append(row_t)
        projects.append(row_p)
        levels.append(row_l)
        states.append(row_s)
        epochs.append(row_e)
        directions.append(row_d)
        siblings.append(row_sib)

    return {
        "root_auth": int(root_auth),
        "auth_path_directions": directions,
        "auth_path_siblings": siblings,
        "object_tenant_ids": tenants,
        "object_project_ids": projects,
        "object_levels": levels,
        "object_states": states,
        "object_epochs": epochs,
    }
