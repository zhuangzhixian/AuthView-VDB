"""ACL-class Merkle commitment and ZK-ready witness layout (Phase 5B-1).

Plaintext commitment helpers only — no Rust proof path in this phase.

Leaf formats (field order fixed for future Rust gadgets):
  aclClassLeaf      = H(acl_class_id, tenant_id, project_id, required_clearance, state, epoch)
  objClassLeaf      = H(cid, acl_class_id, epoch)
"""

from __future__ import annotations

from dataclasses import dataclass

from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    compare_object_level_vs_acl_class_reference,
    evaluate_acl_class_visibility,
    expand_auth_label_for_cid,
)
from auth_reference.auth_commitment import (
    build_auth_merkle_tree,
    next_pow2,
    open_auth_label,
    split_auth_path,
)
from auth_reference.policy import ACTIVE_STATE
from auth_reference.records import CandidateRecord, Checkpoint, UserContext
from auth_reference.v3db_adapter import V3DBSlotBuffers, ZK_STATE_ID
from zk_IVF_PQ.zk_IVF_PQ import single_hash

# Fixed leaf field order (must match future Rust).
ACL_CLASS_LEAF_FIELD_ORDER = (
    "acl_class_id",
    "tenant_id",
    "project_id",
    "required_clearance",
    "state",
    "epoch",
)
OBJECT_CLASS_BINDING_LEAF_FIELD_ORDER = ("cid", "acl_class_id", "epoch")

DUMMY_ACL_CLASS_ID = 0
DUMMY_BINDING_CID = 0


@dataclass(frozen=True)
class ACLClassLeaf:
    acl_class_id: int
    tenant_id: int
    project_id: int
    required_clearance: int
    state: int
    epoch: int

    @classmethod
    def from_label(cls, label: ACLClassLabel) -> ACLClassLeaf:
        return cls(
            acl_class_id=int(label.acl_class_id),
            tenant_id=int(label.tenant_id),
            project_id=int(label.project_id),
            required_clearance=int(label.required_clearance),
            state=int(ZK_STATE_ID.get(label.state, 0)),
            epoch=int(label.epoch),
        )

    def as_list(self) -> list[int]:
        return [
            self.acl_class_id,
            self.tenant_id,
            self.project_id,
            self.required_clearance,
            self.state,
            self.epoch,
        ]

    def to_class_label(self) -> ACLClassLabel:
        state_name = ACTIVE_STATE if self.state == ZK_STATE_ID.get(ACTIVE_STATE, 1) else "inactive"
        return ACLClassLabel(
            acl_class_id=self.acl_class_id,
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            required_clearance=self.required_clearance,
            state=state_name,
            epoch=self.epoch,
        )


@dataclass(frozen=True)
class ObjectClassBindingLeaf:
    cid: int
    acl_class_id: int
    epoch: int

    @classmethod
    def from_binding(cls, binding: ObjectClassBinding) -> ObjectClassBindingLeaf:
        return cls(
            cid=int(binding.cid),
            acl_class_id=int(binding.acl_class_id),
            epoch=int(binding.epoch),
        )

    def as_list(self) -> list[int]:
        return [self.cid, self.acl_class_id, self.epoch]

    def to_binding(self) -> ObjectClassBinding:
        return ObjectClassBinding(
            cid=self.cid,
            acl_class_id=self.acl_class_id,
            epoch=self.epoch,
        )


@dataclass
class ACLClassTree:
    root: int
    hash_tree: list[int]
    labels: list[ACLClassLeaf]
    padded_leaf_count: int

    @property
    def depth(self) -> int:
        return _tree_depth(self.padded_leaf_count)


@dataclass
class ObjectClassBindingTree:
    root: int
    hash_tree: list[int]
    bindings: list[ObjectClassBindingLeaf]
    padded_leaf_count: int

    @property
    def depth(self) -> int:
        return _tree_depth(self.padded_leaf_count)


@dataclass
class ACLClassOpening:
    label: ACLClassLeaf
    path: list[list[int]]
    leaf_idx: int


@dataclass
class ObjectClassBindingOpening:
    binding: ObjectClassBindingLeaf
    path: list[list[int]]
    leaf_idx: int


@dataclass
class ACLClassZkWitness:
    """Fixed-shape ZK-ready witness for ACL-class authorized retrieval."""

    root_acl_class: int
    root_object_class_binding: int
    n_acl_max: int
    n_probe: int
    slot_per_list: int

    selected_class_labels: list[ACLClassLabel]
    selected_class_valids: list[int]
    selected_class_path_directions: list[list[int]]
    selected_class_path_siblings: list[list[int]]

    per_slot_bindings: list[list[ObjectClassBinding]]
    per_slot_binding_path_directions: list[list[list[int]]]
    per_slot_binding_path_siblings: list[list[list[int]]]

    per_slot_class_index: list[list[int]]
    per_slot_class_selector: list[list[list[int]]]

    class_visibility_plaintext: list[int]
    expected_slot_visibility: list[list[int]]

    acl_class_tree: ACLClassTree
    binding_tree: ObjectClassBindingTree


@dataclass
class ACLClassZkCost:
    n_sel: int
    n_acl: int
    n_acl_max: int
    binding_openings: int
    class_openings: int
    policy_evals_object_level: int
    policy_evals_acl_class: int
    estimated_object_level_cost: int
    estimated_acl_class_cost: int
    acl_ratio: float


def _tree_depth(padded_leaf_count: int) -> int:
    depth = 0
    n = padded_leaf_count
    while n > 1:
        n //= 2
        depth += 1
    return depth


def _encode_state(state: str) -> int:
    return int(ZK_STATE_ID.get(state, 0))


def compute_acl_class_leaf(class_label: ACLClassLabel) -> int:
    """H(acl_class_id, tenant_id, project_id, required_clearance, state, epoch)."""
    leaf = ACLClassLeaf.from_label(class_label)
    return compute_acl_class_leaf_record(leaf)


def compute_acl_class_leaf_record(leaf: ACLClassLeaf) -> int:
    return int(single_hash(leaf.as_list()))


def compute_object_class_binding_leaf(binding: ObjectClassBinding) -> int:
    """H(cid, acl_class_id, epoch)."""
    leaf = ObjectClassBindingLeaf.from_binding(binding)
    return compute_object_class_binding_leaf_record(leaf)


def compute_object_class_binding_leaf_record(leaf: ObjectClassBindingLeaf) -> int:
    return int(single_hash(leaf.as_list()))


def dummy_acl_class_label() -> ACLClassLabel:
    """Padding row in selected class table; matches dummy_acl_class_leaf hash."""
    return ACLClassLabel(
        acl_class_id=DUMMY_ACL_CLASS_ID,
        tenant_id=0,
        project_id=0,
        required_clearance=0,
        state="inactive",
        epoch=0,
    )


def dummy_acl_class_leaf() -> ACLClassLeaf:
    """Deterministic padding class: all-zero fields, inactive state."""
    return ACLClassLeaf.from_label(dummy_acl_class_label())


def dummy_object_class_binding_leaf() -> ObjectClassBindingLeaf:
    return ObjectClassBindingLeaf(DUMMY_BINDING_CID, DUMMY_ACL_CLASS_ID, 0)


def build_acl_class_tree(class_labels: dict[int, ACLClassLabel]) -> ACLClassTree:
    """Build Merkle tree over ACL class leaves (sorted by acl_class_id)."""
    if not class_labels:
        raise ValueError("empty class_labels")

    labels_dict = dict(class_labels)
    if DUMMY_ACL_CLASS_ID not in labels_dict:
        labels_dict[DUMMY_ACL_CLASS_ID] = dummy_acl_class_label()

    ordered_ids = sorted(labels_dict.keys())
    labels = [ACLClassLeaf.from_label(labels_dict[cid]) for cid in ordered_ids]
    leaf_hashes = [compute_acl_class_leaf_record(lbl) for lbl in labels]

    padded = next_pow2(len(leaf_hashes))
    while len(leaf_hashes) < padded:
        leaf_hashes.append(compute_acl_class_leaf_record(dummy_acl_class_leaf()))
        labels.append(dummy_acl_class_leaf())

    root, tree = build_auth_merkle_tree(leaf_hashes)
    return ACLClassTree(int(root), tree, labels, padded)


def build_object_class_binding_tree(
    bindings: list[ObjectClassBinding],
) -> ObjectClassBindingTree:
    """Build Merkle tree over row-major binding leaves."""
    if not bindings:
        raise ValueError("empty bindings list")

    binding_leaves = [ObjectClassBindingLeaf.from_binding(b) for b in bindings]
    leaf_hashes = [compute_object_class_binding_leaf_record(b) for b in binding_leaves]

    padded = next_pow2(len(leaf_hashes))
    while len(leaf_hashes) < padded:
        leaf_hashes.append(
            compute_object_class_binding_leaf_record(dummy_object_class_binding_leaf())
        )
        binding_leaves.append(dummy_object_class_binding_leaf())

    root, tree = build_auth_merkle_tree(leaf_hashes)
    return ObjectClassBindingTree(int(root), tree, binding_leaves, padded)


def open_acl_class(
    acl_class_tree: ACLClassTree,
    acl_class_id: int,
) -> ACLClassOpening:
    """Open ACL class leaf by acl_class_id."""
    leaf_idx = None
    for i, lbl in enumerate(acl_class_tree.labels):
        if lbl.acl_class_id == acl_class_id:
            leaf_idx = i
            break
    if leaf_idx is None:
        raise ValueError(f"acl_class_id {acl_class_id} not in tree")
    path = open_auth_label(leaf_idx, acl_class_tree.hash_tree)
    return ACLClassOpening(acl_class_tree.labels[leaf_idx], path, leaf_idx)


def open_object_class_binding(
    binding_tree: ObjectClassBindingTree,
    leaf_idx: int,
) -> ObjectClassBindingOpening:
    if leaf_idx < 0 or leaf_idx >= len(binding_tree.bindings):
        raise ValueError(f"leaf_idx {leaf_idx} out of range")
    path = open_auth_label(leaf_idx, binding_tree.hash_tree)
    return ObjectClassBindingOpening(binding_tree.bindings[leaf_idx], path, leaf_idx)


def verify_acl_class_opening_plaintext(
    class_label: ACLClassLabel,
    path: list[list[int]],
    expected_root: int,
) -> bool:
    leaf = ACLClassLeaf.from_label(class_label)
    curr = compute_acl_class_leaf_record(leaf)
    for direction, sibling in path:
        d = int(direction)
        sib = int(sibling)
        if d == 0:
            curr = int(single_hash([curr, sib]))
        else:
            curr = int(single_hash([sib, curr]))
    return curr == int(expected_root)


def verify_object_class_binding_opening_plaintext(
    binding: ObjectClassBinding,
    path: list[list[int]],
    expected_root: int,
) -> bool:
    leaf = ObjectClassBindingLeaf.from_binding(binding)
    curr = compute_object_class_binding_leaf_record(leaf)
    for direction, sibling in path:
        d = int(direction)
        sib = int(sibling)
        if d == 0:
            curr = int(single_hash([curr, sib]))
        else:
            curr = int(single_hash([sib, curr]))
    return curr == int(expected_root)


def _candidate_grid(
    candidates: list[CandidateRecord],
) -> tuple[list[list[CandidateRecord | None]], int, int]:
    """Organize candidates into [n_probe][slot] grid by list_id / slot_id."""
    if not candidates:
        raise ValueError("empty candidates")

    list_ids = sorted({c.list_id for c in candidates})
    n_probe = len(list_ids)
    slots_per_list = max(c.slot_id for c in candidates) + 1
    grid: list[list[CandidateRecord | None]] = [
        [None] * slots_per_list for _ in range(n_probe)
    ]
    list_id_to_row = {lid: i for i, lid in enumerate(list_ids)}

    for c in candidates:
        row = list_id_to_row[c.list_id]
        if c.slot_id >= slots_per_list:
            raise ValueError(f"slot_id {c.slot_id} exceeds grid width")
        if grid[row][c.slot_id] is not None:
            raise ValueError(f"duplicate slot ({c.list_id}, {c.slot_id})")
        grid[row][c.slot_id] = c

    return grid, n_probe, slots_per_list


def _bindings_row_major_from_grid(
    grid: list[list[CandidateRecord | None]],
    bindings: dict[int, ObjectClassBinding],
    *,
    dummy_class_id: int = DUMMY_ACL_CLASS_ID,
) -> list[ObjectClassBinding]:
    """Row-major bindings for commitment tree (includes invalid slots)."""
    flat: list[ObjectClassBinding] = []
    for row in grid:
        for cell in row:
            if cell is None:
                flat.append(ObjectClassBinding(0, dummy_class_id, 0))
            elif not cell.valid:
                flat.append(ObjectClassBinding(int(cell.cid), dummy_class_id, 0))
            else:
                b = bindings.get(cell.cid)
                if b is None:
                    raise ValueError(f"missing binding for cid={cell.cid}")
                flat.append(b)
    return flat


def _build_selected_class_table(
    class_labels: dict[int, ACLClassLabel],
    used_class_ids: set[int],
    n_acl_max: int,
) -> tuple[list[ACLClassLabel], list[int], dict[int, int]]:
    """Fixed-length selected class table with deterministic dummy padding."""
    if n_acl_max <= 0:
        raise ValueError("n_acl_max must be positive")

    ordered_used = sorted(used_class_ids)
    if len(ordered_used) > n_acl_max:
        raise ValueError(
            f"unique classes {len(ordered_used)} exceed n_acl_max={n_acl_max}"
        )

    selected: list[ACLClassLabel] = []
    valids: list[int] = []
    id_to_index: dict[int, int] = {}

    for class_id in ordered_used:
        idx = len(selected)
        selected.append(class_labels[class_id])
        valids.append(1)
        id_to_index[class_id] = idx

    dummy = dummy_acl_class_label()
    while len(selected) < n_acl_max:
        selected.append(dummy)
        valids.append(0)

    return selected, valids, id_to_index


def _one_hot(index: int, size: int) -> list[int]:
    row = [0] * size
    if 0 <= index < size:
        row[index] = 1
    return row


def estimate_acl_class_zk_cost(
    n_sel: int,
    n_acl: int,
    n_acl_max: int,
    *,
    binding_openings: int | None = None,
) -> ACLClassZkCost:
    """
    Relative ZK cost model for ACL-class witness layout.

    Object-level: N_sel policy evals + N_sel label openings.
    ACL-class: N_acl policy evals + N_acl class openings + binding_openings.
    """
    if n_sel <= 0:
        raise ValueError("n_sel must be positive")
    if n_acl <= 0 or n_acl > n_sel:
        raise ValueError("n_acl must satisfy 1 <= n_acl <= n_sel")
    if n_acl_max < n_acl:
        raise ValueError("n_acl_max must be >= n_acl")

    openings = binding_openings if binding_openings is not None else n_sel
    policy_object = n_sel
    policy_acl = n_acl
    cost_object = policy_object + n_sel
    cost_acl = policy_acl + n_acl + openings

    return ACLClassZkCost(
        n_sel=n_sel,
        n_acl=n_acl,
        n_acl_max=n_acl_max,
        binding_openings=openings,
        class_openings=n_acl,
        policy_evals_object_level=policy_object,
        policy_evals_acl_class=policy_acl,
        estimated_object_level_cost=cost_object,
        estimated_acl_class_cost=cost_acl,
        acl_ratio=n_acl / n_sel,
    )


def _candidate_grid_from_v3db_buffers(
    buffers: V3DBSlotBuffers,
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
) -> list[list[CandidateRecord]]:
    """Probe-major candidate grid aligned with V3DB slot buffers (row i = probe i)."""
    from auth_reference.records import AuthLabel

    n_probe, capacity = buffers.valids.shape
    default = AuthLabel(
        tenant="acme",
        project="proj-a",
        level=0,
        state="active",
        epoch=0,
    )
    grid: list[list[CandidateRecord]] = []
    for i in range(n_probe):
        list_id = int(buffers.cluster_idxes[i])
        row: list[CandidateRecord] = []
        for j in range(capacity):
            cid = int(buffers.itemss[i, j])
            valid = bool(buffers.valids[i, j])
            if valid and cid in bindings:
                label = expand_auth_label_for_cid(bindings[cid], class_labels)
            else:
                label = default
            row.append(
                CandidateRecord(
                    cid=cid,
                    list_id=list_id,
                    slot_id=j,
                    valid=valid,
                    distance=0,
                    label=label,
                )
            )
        grid.append(row)
    return grid


def _build_acl_class_zk_witness_from_grid(
    grid: list[list[CandidateRecord | None]],
    n_probe: int,
    slot_per_list: int,
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    n_acl_max: int | None = None,
    acl_class_tree: ACLClassTree | None = None,
    binding_tree: ObjectClassBindingTree | None = None,
) -> ACLClassZkWitness:
    """Shared witness builder for probe-major or list-id-organized candidate grids."""
    used_class_ids: set[int] = set()
    for row in grid:
        for cell in row:
            if cell is not None and cell.valid:
                b = bindings[cell.cid]
                used_class_ids.add(b.acl_class_id)

    n_acl = len(used_class_ids)
    if n_acl_max is None:
        n_acl_max = max(next_pow2(n_acl), 1)
    if n_acl_max < n_acl:
        raise ValueError(f"n_acl_max={n_acl_max} < unique classes {n_acl}")

    selected_labels, selected_valids, id_to_index = _build_selected_class_table(
        class_labels, used_class_ids, n_acl_max
    )

    flat_bindings = _bindings_row_major_from_grid(grid, bindings)
    if binding_tree is None:
        binding_tree = build_object_class_binding_tree(flat_bindings)
    if acl_class_tree is None:
        acl_class_tree = build_acl_class_tree(class_labels)

    class_vis = [
        evaluate_acl_class_visibility(user, lbl, checkpoint) if valid else 0
        for lbl, valid in zip(selected_labels, selected_valids, strict=True)
    ]

    per_slot_bindings: list[list[ObjectClassBinding]] = []
    per_slot_binding_dirs: list[list[list[int]]] = []
    per_slot_binding_sibs: list[list[list[int]]] = []
    per_slot_class_index: list[list[int]] = []
    per_slot_class_selector: list[list[list[int]]] = []
    expected_slot_visibility: list[list[int]] = []

    flat_idx = 0
    for row in grid:
        row_bindings: list[ObjectClassBinding] = []
        row_dirs: list[list[int]] = []
        row_sibs: list[list[int]] = []
        row_class_idx: list[int] = []
        row_selector: list[list[int]] = []
        row_vis: list[int] = []

        for cell in row:
            binding = flat_bindings[flat_idx]
            opening = open_object_class_binding(binding_tree, flat_idx)
            dirs, sibs = split_auth_path(opening.path)

            if cell is not None and cell.valid:
                class_idx = id_to_index[binding.acl_class_id]
                row_selector.append(_one_hot(class_idx, n_acl_max))
                row_vis.append(class_vis[class_idx])
            else:
                class_idx = 0
                row_selector.append([0] * n_acl_max)
                row_vis.append(0)

            row_bindings.append(binding)
            row_dirs.append(dirs)
            row_sibs.append(sibs)
            row_class_idx.append(class_idx)
            flat_idx += 1

        per_slot_bindings.append(row_bindings)
        per_slot_binding_dirs.append(row_dirs)
        per_slot_binding_sibs.append(row_sibs)
        per_slot_class_index.append(row_class_idx)
        per_slot_class_selector.append(row_selector)
        expected_slot_visibility.append(row_vis)

    selected_class_dirs: list[list[int]] = []
    selected_class_sibs: list[list[int]] = []
    for idx, (lbl, valid) in enumerate(zip(selected_labels, selected_valids, strict=True)):
        if valid:
            opening = open_acl_class(acl_class_tree, lbl.acl_class_id)
        else:
            opening = open_acl_class(acl_class_tree, DUMMY_ACL_CLASS_ID)
        dirs, sibs = split_auth_path(opening.path)
        selected_class_dirs.append(dirs)
        selected_class_sibs.append(sibs)

    return ACLClassZkWitness(
        root_acl_class=int(acl_class_tree.root),
        root_object_class_binding=int(binding_tree.root),
        n_acl_max=n_acl_max,
        n_probe=n_probe,
        slot_per_list=slot_per_list,
        selected_class_labels=selected_labels,
        selected_class_valids=selected_valids,
        selected_class_path_directions=selected_class_dirs,
        selected_class_path_siblings=selected_class_sibs,
        per_slot_bindings=per_slot_bindings,
        per_slot_binding_path_directions=per_slot_binding_dirs,
        per_slot_binding_path_siblings=per_slot_binding_sibs,
        per_slot_class_index=per_slot_class_index,
        per_slot_class_selector=per_slot_class_selector,
        class_visibility_plaintext=class_vis,
        expected_slot_visibility=expected_slot_visibility,
        acl_class_tree=acl_class_tree,
        binding_tree=binding_tree,
    )


def build_acl_class_zk_witness_for_candidates(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    n_acl_max: int | None = None,
    acl_class_tree: ACLClassTree | None = None,
    binding_tree: ObjectClassBindingTree | None = None,
) -> ACLClassZkWitness:
    """
    Build fixed-shape ACL-class ZK witness from candidate grid.

    Invalid slots use all-zero class selectors (no dummy row required).
    """
    grid, n_probe, slot_per_list = _candidate_grid(candidates)
    return _build_acl_class_zk_witness_from_grid(
        grid,
        n_probe,
        slot_per_list,
        bindings,
        class_labels,
        user,
        checkpoint,
        n_acl_max=n_acl_max,
        acl_class_tree=acl_class_tree,
        binding_tree=binding_tree,
    )


def build_acl_class_zk_witness_for_buffers(
    buffers: V3DBSlotBuffers,
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    n_acl_max: int | None = None,
) -> ACLClassZkWitness:
    """Build witness from V3DB fixed-shape slot buffers (probe-major row order)."""
    grid = _candidate_grid_from_v3db_buffers(buffers, bindings, class_labels)
    n_probe, slot_per_list = buffers.valids.shape
    return _build_acl_class_zk_witness_from_grid(
        grid,
        n_probe,
        slot_per_list,
        bindings,
        class_labels,
        user,
        checkpoint,
        n_acl_max=n_acl_max,
    )


def verify_acl_class_witness_plaintext(
    witness: ACLClassZkWitness,
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
    *,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
    buffers: V3DBSlotBuffers | None = None,
) -> dict[str, object]:
    """
    Plaintext validation of ACL-class ZK witness layout.

    Checks Merkle openings, binding/cid consistency, class table matching,
    visibility inheritance, and top-k equivalence with object-level reference.
    """
    grid, grid_n_probe, grid_slots = _candidate_grid(candidates)
    if buffers is not None:
        grid = _candidate_grid_from_v3db_buffers(buffers, bindings, class_labels)
        grid_n_probe, grid_slots = buffers.valids.shape
    if n_probe is not None and n_probe != grid_n_probe:
        raise ValueError("n_probe mismatch")
    if slots_per_list is not None and slots_per_list != grid_slots:
        raise ValueError("slots_per_list mismatch")

    # 1. Class openings to root_acl_class
    for idx, (lbl, valid) in enumerate(
        zip(witness.selected_class_labels, witness.selected_class_valids, strict=True)
    ):
        path = [
            [witness.selected_class_path_directions[idx][d], witness.selected_class_path_siblings[idx][d]]
            for d in range(len(witness.selected_class_path_directions[idx]))
        ]
        if not verify_acl_class_opening_plaintext(lbl, path, witness.root_acl_class):
            raise ValueError(f"invalid ACL class opening at table index {idx}")

    # 2. Binding openings to root_object_class_binding
    flat_idx = 0
    for i in range(witness.n_probe):
        for j in range(witness.slot_per_list):
            binding = witness.per_slot_bindings[i][j]
            path = [
                [
                    witness.per_slot_binding_path_directions[i][j][d],
                    witness.per_slot_binding_path_siblings[i][j][d],
                ]
                for d in range(len(witness.per_slot_binding_path_directions[i][j]))
            ]
            if not verify_object_class_binding_opening_plaintext(
                binding, path, witness.root_object_class_binding
            ):
                raise ValueError(f"invalid binding opening at slot ({i},{j})")
            flat_idx += 1

    # 3–4. Per-slot cid and class index consistency
    for i, row in enumerate(grid):
        for j, cell in enumerate(row):
            binding = witness.per_slot_bindings[i][j]
            class_idx = witness.per_slot_class_index[i][j]
            selected = witness.selected_class_labels[class_idx]
            selector = witness.per_slot_class_selector[i][j]

            if cell is not None and cell.valid:
                if binding.cid != cell.cid:
                    raise ValueError(
                        f"cid mismatch at ({i},{j}): binding {binding.cid} != candidate {cell.cid}"
                    )
                committed = bindings.get(cell.cid)
                if committed is None or binding != committed:
                    raise ValueError(f"binding mismatch at ({i},{j}) for cid={cell.cid}")
                if binding.acl_class_id != selected.acl_class_id:
                    raise ValueError(
                        f"class index mismatch at ({i},{j}): "
                        f"binding class {binding.acl_class_id} != selected {selected.acl_class_id}"
                    )
                if sum(selector) != 1:
                    raise ValueError(f"selector not one-hot at ({i},{j})")
                if selector[class_idx] != 1:
                    raise ValueError(f"selector/index mismatch at ({i},{j})")
            elif sum(selector) != 0:
                raise ValueError(f"invalid slot selector must be zero at ({i},{j})")

            # 5–6. Visibility inheritance
            if cell is not None and cell.valid:
                expected_vis = witness.class_visibility_plaintext[class_idx]
                policy_vis = evaluate_acl_class_visibility(user, selected, checkpoint)
                if witness.class_visibility_plaintext[class_idx] != policy_vis:
                    raise ValueError(
                        f"class visibility mismatch at index {class_idx}"
                    )
                slot_vis = witness.expected_slot_visibility[i][j]
                if slot_vis != expected_vis:
                    raise ValueError(f"slot visibility not inherited at ({i},{j})")
            else:
                if witness.expected_slot_visibility[i][j] != 0:
                    raise ValueError(f"invalid slot must have visibility 0 at ({i},{j})")

    # 7. Top-k equivalence
    merged_labels = dict(class_labels)
    for idx, (lbl, valid) in enumerate(
        zip(witness.selected_class_labels, witness.selected_class_valids, strict=True)
    ):
        if valid:
            merged_labels[lbl.acl_class_id] = lbl

    cmp = compare_object_level_vs_acl_class_reference(
        candidates,
        bindings,
        merged_labels,
        user,
        checkpoint,
        top_k,
        n_probe=grid_n_probe,
        slots_per_list=grid_slots,
    )

    n_sel = sum(1 for c in candidates if c.valid)
    n_acl = len({bindings[c.cid].acl_class_id for c in candidates if c.valid})
    cost = estimate_acl_class_zk_cost(
        n_sel,
        n_acl,
        witness.n_acl_max,
        binding_openings=witness.n_probe * witness.slot_per_list,
    )

    if not cmp["equivalent"]:
        raise ValueError(
            f"top-k not equivalent: object={cmp['object_top_k']} acl={cmp['acl_top_k']}"
        )

    return {
        "valid": True,
        "topk_equivalent": cmp["equivalent"],
        "object_top_k": cmp["object_top_k"],
        "acl_top_k": cmp["acl_top_k"],
        "cost": cost,
    }


def split_acl_class_zk_witness_for_zk(witness: ACLClassZkWitness) -> dict[str, object]:
    """Split ACLClassZkWitness into arrays for py_set_based_auth_acl_class_with_merkle."""
    return {
        "root_acl_class": int(witness.root_acl_class),
        "root_object_class_binding": int(witness.root_object_class_binding),
        "n_acl_max": int(witness.n_acl_max),
        "selected_class_valids": [int(v) for v in witness.selected_class_valids],
        "selected_acl_class_ids": [
            int(lbl.acl_class_id) for lbl in witness.selected_class_labels
        ],
        "selected_class_tenant_ids": [
            int(lbl.tenant_id) for lbl in witness.selected_class_labels
        ],
        "selected_class_project_ids": [
            int(lbl.project_id) for lbl in witness.selected_class_labels
        ],
        "selected_class_required_clearances": [
            int(lbl.required_clearance) for lbl in witness.selected_class_labels
        ],
        "selected_class_states": [
            int(ZK_STATE_ID.get(lbl.state, 0)) for lbl in witness.selected_class_labels
        ],
        "selected_class_epochs": [int(lbl.epoch) for lbl in witness.selected_class_labels],
        "selected_class_path_directions": witness.selected_class_path_directions,
        "selected_class_path_siblings": witness.selected_class_path_siblings,
        "binding_acl_class_ids": [
            [int(b.acl_class_id) for b in row] for row in witness.per_slot_bindings
        ],
        "binding_epochs": [
            [int(b.epoch) for b in row] for row in witness.per_slot_bindings
        ],
        "binding_path_directions": witness.per_slot_binding_path_directions,
        "binding_path_siblings": witness.per_slot_binding_path_siblings,
        "per_slot_class_selector": witness.per_slot_class_selector,
    }


def top_k_cids_from_acl_class_ordered(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
    *,
    n_probe: int,
    slots_per_list: int,
) -> list[int]:
    """Return ACL-class compressed authorized top-k cids (oracle tie-break)."""
    from auth_reference.acl_class import authorized_topk_acl_compressed

    result = authorized_topk_acl_compressed(
        candidates,
        bindings,
        class_labels,
        user,
        checkpoint,
        top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    return list(result.top_k_cids)


def build_acl_class_zk_witness_for_v3db_query(
    query,
    center,
    code_books,
    quant_vecs,
    id_groups,
    n_probe: int,
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    *,
    n_acl_max: int | None = None,
) -> ACLClassZkWitness:
    """Build ACL-class ZK witness from V3DB query buffers + ACL bindings."""
    from auth_reference.v3db_adapter import build_candidates_from_v3db_query

    _candidates, _rows, buffers = build_candidates_from_v3db_query(
        query, center, code_books, quant_vecs, id_groups, n_probe, labels={}
    )
    return build_acl_class_zk_witness_for_buffers(
        buffers,
        bindings,
        class_labels,
        user,
        checkpoint,
        n_acl_max=n_acl_max,
    )
