# Phase 3B-1: Slot-Aligned Auth Commitment — Plaintext Builder Log

**Branch:** `phase3-slot-aligned-plaintext`  
**Related:** [phase3_slot_aligned_auth_commitment_design.md](phase3_slot_aligned_auth_commitment_design.md),
[phase3_slot_aligned_test_plan.md](phase3_slot_aligned_test_plan.md),
[phase2_auth_commitment_gadget_log.md](phase2_auth_commitment_gadget_log.md).

---

## 1. New files

| File | Purpose |
|------|---------|
| `auth_reference/slot_aligned_auth_commitment.py` | Two-level plaintext tree + witness builder |
| `tests/test_auth_slot_aligned_commitment.py` | Unit tests (11 cases) |
| `docs/phase3_slot_aligned_plaintext_log.md` | This log |

**Not modified:** Rust sources, PyO3 API, benchmark scripts, `v3db_adapter.py`.

---

## 2. Helpers

| Function | Role |
|----------|------|
| `build_intra_list_auth_tree(list_id, slot_labels)` | Merkle tree over slots in one IVF list |
| `build_top_auth_tree(list_roots)` | Top tree over list auth roots |
| `build_slot_aligned_auth_tree(n_list, slot_per_list, slot_labels)` | Full two-level index commitment |
| `open_list_auth_root(tree, list_id)` | Shared top-level opening for one list |
| `open_slot_in_list(tree, list_id, slot_id)` | Intra-list slot opening |
| `open_slot_aligned_auth_label(tree, list_id, slot_id)` | `(label, slot_op, list_op)` tuple |
| `verify_slot_aligned_opening_plaintext(...)` | Leaf → list root → `root_auth` |
| `build_slot_aligned_auth_witness_for_buffers(buffers, slot_labels, n_list=...)` | Probed-buffer witness |
| `estimate_global_opening_cost(n_probe, slot_per_list)` | Phase 2C-2 cost model |
| `estimate_slot_aligned_opening_cost(n_probe, slot_per_list, n_list)` | Shared top-path cost model |
| `estimate_slot_aligned_opening_cost_naive(...)` | Per-slot top+intra (no sharing) |

Dataclasses: `SlotAuthLabel`, `IntraListAuthTree`, `SlotAlignedAuthTree`,
`ListAuthOpening`, `SlotAuthOpening`, `SlotAlignedAuthWitness`.

---

## 3. Tree layout

**Intra-list (per list ℓ):**

$$
authLeaf_{\ell,j} = H(cid, tenant, project, level, state, epoch)
$$

$$
root^{auth}_{\ell} = MerkleRoot(\{authLeaf_{\ell,j}\}_{j=0}^{slot\_per\_list-1})
$$

**Top-level:**

$$
root_{auth} = MerkleRoot(\{root^{auth}_{\ell}\}_{\ell=0}^{n_{list}-1})
$$

Both levels pad leaf count to the next power of two with
`H(0,0,0,0,0,0)` (intra) or zero-hash leaf at top level (same convention as
Phase 2C-1 `build_auth_merkle_tree` padding).

---

## 4. Leaf field order

Unchanged from Phase 2C-1: `(cid, tenant, project, level, state, epoch)`.

Labels are keyed by **`(list_id, slot_id)`** via `SlotAuthLabel` or
`dict[tuple[int,int], AuthLabelLeaf]`. Missing grid cells default to
`DUMMY_PADDING_LEAF = (0,0,0,0,0,0)`.

---

## 5. Padding / invalid slots

| Case | Label |
|------|-------|
| Unassigned grid cell (publisher index) | `(cid=0, 0,0,0,0,0)` |
| Invalid probed slot (`valid=0`) | `(cid=itemss[i][j], 0,0,0,0,0)` — matches Phase 2C-2 |

Invalid slots still receive valid intra-list openings under `root^auth_ℓ`.

---

## 6. Opening witness layout

### Canonical shared representation (`SlotAlignedAuthWitness`)

| Field | Shape / type | Notes |
|-------|--------------|-------|
| `root_auth` | `int` | Public top root |
| `shared_list_openings` | `dict[list_id, ListAuthOpening]` | **One top path per probed list** |
| `probe_list_ids` | `[n_probe]` | `cluster_idxes[i]` |
| `slot_openings` | `[n_probe][slot_per_list]` | Intra paths + labels only |
| `object_*` arrays | `[n_probe][slot_per_list]` | ZK-ready integer label fields |

Each `ListAuthOpening` contains:

- `list_id`, `list_auth_root`
- `top_path` → `top_path_directions`, `top_path_siblings`

Each `SlotAuthOpening` contains:

- `list_id`, `slot_id`, `label`
- `intra_path` → `intra_path_directions`, `intra_path_siblings`

**Important:** Top-level path is **not** duplicated per slot. Slots in the same
list reference the same `shared_list_openings[list_id]` object.

---

## 7. Tests

| Test | Result |
|------|--------|
| Valid opening | Pass |
| Forged tenant / cid | Fail verify |
| Wrong intra / top path | Fail verify |
| Cross-list graft | Fail verify |
| Invalid padding dummy label | Pass |
| Shared top path (same list, two slots) | Identical `top_path` |
| Witness builder + buffers | Pass |
| Intra leaf = global leaf hash | Pass |
| Cost model sanity (4×64, n_list=8) | aligned < global < naive |
| Phase 2E grid cases | aligned < global |

```bash
PYTHONPATH=. pytest tests/test_auth_commitment.py tests/test_auth_slot_aligned_commitment.py -v
```

---

## 8. Cost model sanity (typical parameters)

For `n_probe=4`, `slot_per_list=64`, `n_list=8`:

| Model | Formula | Steps |
|-------|---------|-------|
| Global (2C-2) | `N_sel × depth_global` | 256 × 8 = **2048** |
| Slot-aligned (shared) | `n_probe × depth_top + N_sel × depth_slot` | 4×3 + 256×6 = **1548** |
| Slot-aligned (naive) | `N_sel × (depth_top + depth_slot)` | 256 × 9 = **2304** |

Slot-aligned with shared list opening is cheaper than global on all Phase 2E
grid points in unit tests. Real circuit savings require Phase 3B-2 shared
list-root gadget fan-out.

---

## 9. Current limitations

- Plaintext only; no Rust gadget or ZK path yet.
- `build_slot_aligned_auth_witness_for_buffers` requires explicit
  `(list_id, slot_id)` labels for valid probed slots (not cid-only map).
- Full `n_list` index must be supplied; non-probed lists commit dummy slots.
- Top-level padding uses zero-hash leaves (same as Phase 2C-1 tree padding).
- No integration with `py_set_based_auth_committed_with_merkle`.

---

## 10. Next: Phase 3B-2 Rust gadget

1. `slot_aligned_auth_commitment_gadget.rs`:
   - `intra_list_auth_verify_gadget(leaf, path, list_root)`
   - `top_list_auth_verify_gadget(list_root, path, root_auth)`
   - Shared `list_root` target per probe row
2. Wire into additive `set_based_auth_ivf_pq_gadget_committed_slot_aligned`
3. PyO3 + ZK tests per [phase3_slot_aligned_test_plan.md](phase3_slot_aligned_test_plan.md)
4. Global vs slot-aligned equivalence test on shared fixtures
