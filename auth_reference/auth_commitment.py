"""Plaintext auth label Merkle commitment helpers (Phase 2C-1).

Leaf format matches Rust `auth_commitment_gadget`:
  H(cid, tenant, project, level, state, epoch)
using Poseidon hash_no_pad via `single_hash` (same as V3DB `hash_u64`).
"""

from __future__ import annotations

from dataclasses import dataclass

from zk_IVF_PQ.zk_IVF_PQ import single_hash

# Field order must match Rust `auth_label_leaf_fields`.
AUTH_LABEL_FIELD_ORDER = ("cid", "tenant", "project", "level", "state", "epoch")


@dataclass(frozen=True)
class AuthLabelLeaf:
    cid: int
    tenant: int
    project: int
    level: int
    state: int
    epoch: int

    def as_list(self) -> list[int]:
        return [self.cid, self.tenant, self.project, self.level, self.state, self.epoch]


def compute_auth_leaf(
    cid: int,
    tenant: int,
    project: int,
    level: int,
    state: int,
    epoch: int,
) -> int:
    """Poseidon leaf hash; matches `auth_label_leaf_hash_u64` in Rust."""
    return int(
        single_hash([int(cid), int(tenant), int(project), int(level), int(state), int(epoch)])
    )


def compute_auth_leaf_record(label: AuthLabelLeaf) -> int:
    return compute_auth_leaf(*label.as_list())


def _tree_depth(leaf_count: int) -> int:
    depth = 0
    n = leaf_count
    while n > 1:
        n //= 2
        depth += 1
    return depth


def build_auth_merkle_tree(leaves: list[int]) -> tuple[int, list[int]]:
    """
    Build binary Merkle tree over leaf hashes.

    Returns `(root, hash_tree)` where `hash_tree` layout matches
    `hash_gadgets::hash_tree_gen`.
    """
    if not leaves:
        raise ValueError("empty leaf list")
    n = len(leaves)
    if n & (n - 1) != 0:
        raise ValueError("leaf count must be a power of two")

    hash_list = [int(x) for x in leaves]
    hash_tree: list[int] = list(hash_list)
    hash_len = n
    while hash_len > 1:
        hash_len //= 2
        curr: list[int] = []
        for i in range(hash_len):
            curr.append(single_hash([hash_list[2 * i], hash_list[2 * i + 1]]))
        hash_list = curr
        hash_tree = curr + hash_tree
    return hash_list[0], hash_tree


def open_auth_label(leaf_idx: int, hash_tree: list[int]) -> list[list[int]]:
    """
    Merkle opening path for `leaf_idx`.

    Each row is `[direction, sibling_hash]` matching `hash_tree_path` /
    `merkle_back_gadget`.
    """
    leaf_count = (len(hash_tree) + 1) // 2
    depth = _tree_depth(leaf_count)
    idx = int(leaf_idx)
    idx_bits: list[int] = []
    for _ in range(depth):
        idx_bits.append(idx % 2)
        idx //= 2
    idx_bits.reverse()

    other_part: list[int] = []
    curr_idx = 0
    for bit in idx_bits:
        curr_idx = curr_idx * 2 + bit + 1
        if curr_idx % 2 == 0:
            other_part.append(hash_tree[curr_idx - 1])
        else:
            other_part.append(hash_tree[curr_idx + 1])

    idx_bits.reverse()
    other_part.reverse()
    return [[idx_bits[i], other_part[i]] for i in range(depth)]


def verify_auth_opening_plaintext(
    label: AuthLabelLeaf,
    path: list[list[int]],
    expected_root: int,
) -> bool:
    """Recompute root from label + path; return True iff equals `expected_root`."""
    curr = compute_auth_leaf_record(label)
    for direction, sibling in path:
        d = int(direction)
        sib = int(sibling)
        if d == 0:
            curr = int(single_hash([curr, sib]))
        else:
            curr = int(single_hash([sib, curr]))
    return curr == int(expected_root)


def next_pow2(n: int) -> int:
    """Smallest power of two >= n (matches Rust auth tree padding)."""
    if n <= 0:
        return 1
    p = 1
    while p < n:
        p *= 2
    return p


def dummy_auth_label_for_slot(cid: int) -> AuthLabelLeaf:
    """Deterministic auth label for invalid padding slots: (cid, 0, 0, 0, 0, 0)."""
    return AuthLabelLeaf(int(cid), 0, 0, 0, 0, 0)


def build_auth_tree_for_slot_labels(
    slot_labels: list[AuthLabelLeaf],
) -> tuple[int, list[int], int]:
    """
    Build global auth Merkle tree over row-major slot labels.

    Pads with H(0,0,0,0,0,0) leaves to the next power of two. Returns
    `(root_auth, hash_tree, padded_leaf_count)`.
    """
    if not slot_labels:
        raise ValueError("empty slot label list")
    padded = next_pow2(len(slot_labels))
    leaf_hashes = [compute_auth_leaf_record(lbl) for lbl in slot_labels]
    while len(leaf_hashes) < padded:
        leaf_hashes.append(compute_auth_leaf(0, 0, 0, 0, 0, 0))
    root, tree = build_auth_merkle_tree(leaf_hashes)
    return int(root), tree, padded


def split_auth_path(path: list[list[int]]) -> tuple[list[int], list[int]]:
    """Split `open_auth_label` rows into parallel direction / sibling arrays."""
    directions = [int(row[0]) for row in path]
    siblings = [int(row[1]) for row in path]
    return directions, siblings
