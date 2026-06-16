"""Plaintext slot-aligned auth Merkle commitment (Phase 3B-1).

Two-level layout (Phase 3A design):
  intra-list: authLeaf_{list,slot} -> root^auth_list
  top-level:  root^auth_list -> root_auth

Leaf field order matches `auth_commitment` / Rust `auth_commitment_gadget`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from auth_reference.auth_commitment import (
    AuthLabelLeaf,
    build_auth_merkle_tree,
    compute_auth_leaf,
    compute_auth_leaf_record,
    dummy_auth_label_for_slot,
    next_pow2,
    open_auth_label,
    split_auth_path,
)
from auth_reference.v3db_adapter import V3DBSlotBuffers
from zk_IVF_PQ.zk_IVF_PQ import single_hash

DUMMY_PADDING_LEAF = AuthLabelLeaf(0, 0, 0, 0, 0, 0)


def tree_depth_padded(count: int) -> int:
    """Merkle path depth for `count` leaves padded to next power of two."""
    if count <= 0:
        return 0
    padded = next_pow2(count)
    depth = 0
    n = padded
    while n > 1:
        n //= 2
        depth += 1
    return depth


def _padded_leaf_hashes(labels: list[AuthLabelLeaf]) -> list[int]:
    hashes = [compute_auth_leaf_record(lbl) for lbl in labels]
    padded = next_pow2(len(hashes))
    while len(hashes) < padded:
        hashes.append(compute_auth_leaf(0, 0, 0, 0, 0, 0))
    return hashes


@dataclass(frozen=True)
class SlotAuthLabel:
    """Auth label keyed by IVF list / slot index (not cid alone)."""

    list_id: int
    slot_id: int
    cid: int
    tenant: int
    project: int
    level: int
    state: int
    epoch: int

    def as_leaf(self) -> AuthLabelLeaf:
        return AuthLabelLeaf(
            self.cid,
            self.tenant,
            self.project,
            self.level,
            self.state,
            self.epoch,
        )

    @property
    def key(self) -> tuple[int, int]:
        return (self.list_id, self.slot_id)


@dataclass
class IntraListAuthTree:
    list_id: int
    root: int
    hash_tree: list[int]
    labels: list[AuthLabelLeaf]
    padded_slot_count: int

    @property
    def depth(self) -> int:
        return tree_depth_padded(len(self.labels))


@dataclass
class SlotAlignedAuthTree:
    """Full index slot-aligned auth commitment."""

    root_auth: int
    top_hash_tree: list[int]
    intra_trees: dict[int, IntraListAuthTree]
    n_list: int
    slot_per_list: int

    @property
    def depth_top(self) -> int:
        return tree_depth_padded(self.n_list)

    @property
    def depth_slot(self) -> int:
        return tree_depth_padded(self.slot_per_list)

    def list_auth_root(self, list_id: int) -> int:
        return int(self.intra_trees[list_id].root)


@dataclass
class ListAuthOpening:
    """Shared top-level opening for one probed IVF list."""

    list_id: int
    list_auth_root: int
    top_path: list[list[int]]

    @property
    def top_path_directions(self) -> list[int]:
        d, _ = split_auth_path(self.top_path)
        return d

    @property
    def top_path_siblings(self) -> list[int]:
        _, s = split_auth_path(self.top_path)
        return s


@dataclass
class SlotAuthOpening:
    """Intra-list opening for one slot."""

    list_id: int
    slot_id: int
    label: AuthLabelLeaf
    intra_path: list[list[int]]

    @property
    def intra_path_directions(self) -> list[int]:
        d, _ = split_auth_path(self.intra_path)
        return d

    @property
    def intra_path_siblings(self) -> list[int]:
        _, s = split_auth_path(self.intra_path)
        return s


@dataclass
class SlotAlignedAuthWitness:
    """
    Prover witness with **shared** top-level openings per probed list.

    `shared_list_openings[list_id]` holds one top path reused by all slots in
    that list. This is the canonical Phase 3B layout (not per-slot top paths).
    """

    root_auth: int
    n_list: int
    slot_per_list: int
    probe_list_ids: list[int]
    shared_list_openings: dict[int, ListAuthOpening]
    slot_openings: list[list[SlotAuthOpening]]
    object_tenant_ids: list[list[int]] = field(default_factory=list)
    object_project_ids: list[list[int]] = field(default_factory=list)
    object_levels: list[list[int]] = field(default_factory=list)
    object_states: list[list[int]] = field(default_factory=list)
    object_epochs: list[list[int]] = field(default_factory=list)


def build_intra_list_auth_tree(
    list_id: int,
    slot_labels: list[AuthLabelLeaf],
) -> IntraListAuthTree:
    """Build Merkle tree over slots `0..len(slot_labels)-1` for one IVF list."""
    if not slot_labels:
        raise ValueError("empty slot_labels")
    leaf_hashes = _padded_leaf_hashes(slot_labels)
    root, tree = build_auth_merkle_tree(leaf_hashes)
    return IntraListAuthTree(
        list_id=int(list_id),
        root=int(root),
        hash_tree=tree,
        labels=list(slot_labels),
        padded_slot_count=len(leaf_hashes),
    )


def build_top_auth_tree(list_roots: list[int]) -> tuple[int, list[int]]:
    """Build top-level tree over per-list auth roots (padded to power of two)."""
    if not list_roots:
        raise ValueError("empty list_roots")
    roots = [int(r) for r in list_roots]
    padded = next_pow2(len(roots))
    while len(roots) < padded:
        roots.append(compute_auth_leaf(0, 0, 0, 0, 0, 0))
    return build_auth_merkle_tree(roots)


def _labels_grid(
    n_list: int,
    slot_per_list: int,
    slot_labels: dict[tuple[int, int], AuthLabelLeaf | SlotAuthLabel],
) -> dict[int, list[AuthLabelLeaf]]:
    """Normalize `(list_id, slot_id)` map into per-list label rows."""
    grid: dict[int, list[AuthLabelLeaf]] = {}
    for list_id in range(n_list):
        row: list[AuthLabelLeaf] = []
        for slot_id in range(slot_per_list):
            key = (list_id, slot_id)
            if key not in slot_labels:
                row.append(DUMMY_PADDING_LEAF)
                continue
            entry = slot_labels[key]
            if isinstance(entry, SlotAuthLabel):
                row.append(entry.as_leaf())
            else:
                row.append(entry)
        grid[list_id] = row
    return grid


def build_slot_aligned_auth_tree(
    n_list: int,
    slot_per_list: int,
    slot_labels: dict[tuple[int, int], AuthLabelLeaf | SlotAuthLabel],
) -> SlotAlignedAuthTree:
    """
    Build full two-level slot-aligned auth tree over all lists and slots.

    `slot_labels` is keyed by `(list_id, slot_id)`. Missing entries use
    `DUMMY_PADDING_LEAF` (cid=0, all fields zero).
    """
    if n_list <= 0 or slot_per_list <= 0:
        raise ValueError("n_list and slot_per_list must be positive")

    grid = _labels_grid(n_list, slot_per_list, slot_labels)
    intra_trees: dict[int, IntraListAuthTree] = {}
    list_roots: list[int] = []
    for list_id in range(n_list):
        intra = build_intra_list_auth_tree(list_id, grid[list_id])
        intra_trees[list_id] = intra
        list_roots.append(intra.root)

    root_auth, top_tree = build_top_auth_tree(list_roots)
    return SlotAlignedAuthTree(
        root_auth=int(root_auth),
        top_hash_tree=top_tree,
        intra_trees=intra_trees,
        n_list=n_list,
        slot_per_list=slot_per_list,
    )


def open_list_auth_root(
    tree: SlotAlignedAuthTree,
    list_id: int,
) -> ListAuthOpening:
    """Top-level opening for one list root under `root_auth`."""
    if list_id < 0 or list_id >= tree.n_list:
        raise ValueError(f"list_id {list_id} out of range")
    list_root = tree.list_auth_root(list_id)
    top_path = open_auth_label(list_id, tree.top_hash_tree)
    return ListAuthOpening(
        list_id=int(list_id),
        list_auth_root=int(list_root),
        top_path=top_path,
    )


def open_slot_in_list(
    tree: SlotAlignedAuthTree,
    list_id: int,
    slot_id: int,
) -> SlotAuthOpening:
    """Intra-list opening for one slot leaf under `root^auth_list`."""
    intra = tree.intra_trees[list_id]
    if slot_id < 0 or slot_id >= len(intra.labels):
        raise ValueError(f"slot_id {slot_id} out of range for list {list_id}")
    label = intra.labels[slot_id]
    intra_path = open_auth_label(slot_id, intra.hash_tree)
    return SlotAuthOpening(
        list_id=int(list_id),
        slot_id=int(slot_id),
        label=label,
        intra_path=intra_path,
    )


def open_slot_aligned_auth_label(
    tree: SlotAlignedAuthTree,
    list_id: int,
    slot_id: int,
) -> tuple[AuthLabelLeaf, SlotAuthOpening, ListAuthOpening]:
    """
    Return `(label, intra opening, shared list opening)` for one slot.

    The list opening is the same object for every slot in `list_id`.
    """
    list_opening = open_list_auth_root(tree, list_id)
    slot_opening = open_slot_in_list(tree, list_id, slot_id)
    return slot_opening.label, slot_opening, list_opening


def verify_slot_aligned_opening_plaintext(
    label: AuthLabelLeaf,
    intra_path: list[list[int]],
    list_auth_root: int,
    top_path: list[list[int]],
    expected_root_auth: int,
) -> bool:
    """Verify leaf -> list root -> top root_auth."""
    curr = compute_auth_leaf_record(label)
    for direction, sibling in intra_path:
        d = int(direction)
        sib = int(sibling)
        if d == 0:
            curr = int(single_hash([curr, sib]))
        else:
            curr = int(single_hash([sib, curr]))
    if curr != int(list_auth_root):
        return False

    curr = int(list_auth_root)
    for direction, sibling in top_path:
        d = int(direction)
        sib = int(sibling)
        if d == 0:
            curr = int(single_hash([curr, sib]))
        else:
            curr = int(single_hash([sib, curr]))
    return curr == int(expected_root_auth)


def estimate_global_opening_cost(n_probe: int, slot_per_list: int) -> int:
    """
    Phase 2C-2 style: each selected slot carries one global path.

    Returns total hash steps ≈ N_sel * depth_global.
    """
    n_sel = n_probe * slot_per_list
    depth_global = tree_depth_padded(n_sel)
    return n_sel * depth_global


def estimate_slot_aligned_opening_cost(
    n_probe: int,
    slot_per_list: int,
    n_list: int,
) -> int:
    """
    Ideal shared top path: n_probe top openings + N_sel intra openings.

    Returns n_probe * depth_top + N_sel * depth_slot.
    """
    n_sel = n_probe * slot_per_list
    depth_top = tree_depth_padded(n_list)
    depth_slot = tree_depth_padded(slot_per_list)
    return n_probe * depth_top + n_sel * depth_slot


def estimate_slot_aligned_opening_cost_naive(
    n_probe: int,
    slot_per_list: int,
    n_list: int,
) -> int:
    """Naive per-slot top+intra (no sharing): N_sel * (depth_top + depth_slot)."""
    n_sel = n_probe * slot_per_list
    depth_top = tree_depth_padded(n_list)
    depth_slot = tree_depth_padded(slot_per_list)
    return n_sel * (depth_top + depth_slot)


def build_slot_aligned_auth_witness_for_buffers(
    buffers: V3DBSlotBuffers,
    slot_labels: dict[tuple[int, int], AuthLabelLeaf | SlotAuthLabel],
    *,
    n_list: int,
) -> SlotAlignedAuthWitness:
    """
    Build slot-aligned witness for probed fixed-shape buffers.

    Full `n_list` × `slot_per_list` tree is built; probed rows reference
    `buffers.cluster_idxes[i]` as `list_id`. Invalid padding slots in probed
    rows use `(cid=itemss[i][j], 0,0,0,0,0)` matching Phase 2C-2.

    Non-probed lists use `DUMMY_PADDING_LEAF` for every slot.
    """
    n_probe, capacity = buffers.valids.shape
    slot_per_list = int(buffers.capacity)

    full_labels: dict[tuple[int, int], AuthLabelLeaf] = {}
    for list_id in range(n_list):
        for slot_id in range(slot_per_list):
            full_labels[(list_id, slot_id)] = DUMMY_PADDING_LEAF

    for key, entry in slot_labels.items():
        if isinstance(entry, SlotAuthLabel):
            full_labels[key] = entry.as_leaf()
        else:
            full_labels[key] = entry

    for i in range(n_probe):
        list_id = int(buffers.cluster_idxes[i])
        for j in range(capacity):
            cid = int(buffers.itemss[i, j])
            valid = bool(buffers.valids[i, j])
            key = (list_id, j)
            if key in slot_labels:
                continue
            if valid:
                raise KeyError(
                    f"missing slot label for probed slot (list_id={list_id}, slot_id={j})"
                )
            full_labels[key] = dummy_auth_label_for_slot(cid)

    tree = build_slot_aligned_auth_tree(n_list, slot_per_list, full_labels)

    shared: dict[int, ListAuthOpening] = {}
    probe_list_ids: list[int] = []
    slot_openings: list[list[SlotAuthOpening]] = []
    tenants: list[list[int]] = []
    projects: list[list[int]] = []
    levels: list[list[int]] = []
    states: list[list[int]] = []
    epochs: list[list[int]] = []

    for i in range(n_probe):
        list_id = int(buffers.cluster_idxes[i])
        probe_list_ids.append(list_id)
        if list_id not in shared:
            shared[list_id] = open_list_auth_root(tree, list_id)

        row_slots: list[SlotAuthOpening] = []
        row_t, row_p, row_l, row_s, row_e = [], [], [], [], []
        for j in range(capacity):
            slot_op = open_slot_in_list(tree, list_id, j)
            row_slots.append(slot_op)
            lbl = slot_op.label
            row_t.append(lbl.tenant)
            row_p.append(lbl.project)
            row_l.append(lbl.level)
            row_s.append(lbl.state)
            row_e.append(lbl.epoch)
        slot_openings.append(row_slots)
        tenants.append(row_t)
        projects.append(row_p)
        levels.append(row_l)
        states.append(row_s)
        epochs.append(row_e)

    return SlotAlignedAuthWitness(
        root_auth=int(tree.root_auth),
        n_list=n_list,
        slot_per_list=slot_per_list,
        probe_list_ids=probe_list_ids,
        shared_list_openings=shared,
        slot_openings=slot_openings,
        object_tenant_ids=tenants,
        object_project_ids=projects,
        object_levels=levels,
        object_states=states,
        object_epochs=epochs,
    )
