# Phase 3B-2: Slot-Aligned Auth Commitment Gadget Log

**Branch:** `phase3-slot-aligned-gadget`  
**Related:** [phase3_slot_aligned_auth_commitment_design.md](phase3_slot_aligned_auth_commitment_design.md),
[phase3_slot_aligned_plaintext_log.md](phase3_slot_aligned_plaintext_log.md),
[phase2_auth_commitment_gadget_log.md](phase2_auth_commitment_gadget_log.md).

---

## 1. New / modified files

| File | Change |
|------|--------|
| `src/merkle_ver/slot_aligned_auth_commitment_gadget.rs` | Two-level verify gadgets + 8 unit tests |
| `src/merkle_ver/mod.rs` | `pub mod slot_aligned_auth_commitment_gadget;` |
| `docs/phase3_slot_aligned_gadget_log.md` | This log |

**Not modified:** `set_based_auth.rs`, `set_based_auth_proof.rs`, `lib.rs`, Python, benchmarks, global committed path.

---

## 2. Two-level gadget semantics

**Intra-list (slot leaf → list root):**

$$
authLeaf_{\ell,j} = H(cid, tenant, project, level, state, epoch)
$$

Uses Phase 2C-1 `auth_label_merkle_verify_gadget` via `intra_list_auth_verify_gadget`.

**Top-level (list root → root_auth):**

$$
root_{auth} = MerkleVerify(root^{auth}_{\ell}, top\_path_{\ell}, root_{auth})
$$

List roots are **already hashed**; `top_list_auth_verify_gadget` uses
`merkle_back_from_hash_gadget` (does not re-hash the list root as a leaf field vector).

---

## 3. Public API

| Function | Role |
|----------|------|
| `slot_auth_leaf_hash_gadget` | Alias to `auth_label_leaf_hash_gadget` |
| `intra_list_auth_verify_gadget` | Label + intra path → `list_auth_root` |
| `top_list_auth_verify_gadget` | `list_auth_root` + top path → `root_auth` |
| `slot_aligned_probe_row_verify_gadget` | One probed list: fan-out + single top verify |
| `SlotAlignedSlotWitness` | Per-slot `{ label, intra_path }` |

---

## 4. Shared list-root fan-out design

`slot_aligned_probe_row_verify_gadget`:

1. For each slot in `slots`: `intra_root = intra_list_auth_verify_gadget(...)` then `connect(intra_root, list_auth_root)`.
2. Once: `top_root = top_list_auth_verify_gadget(list_auth_root, top_path)` then `connect(top_root, root_auth)`.

All slots in a probe row share **one** `list_auth_root` target and **one** `top_path`. The circuit enforces every intra opening recomputes the same list root; inconsistent witnesses fail at prove time (`fanout_mismatch` test).

---

## 5. list_id binding

**Not implemented in Phase 3B-2.**

Top-level Merkle path direction bits encode the list index in the tree, but the gadget does not yet constrain a witness `list_id` target to those bits. Cross-list graft is detected only when intra list root ≠ top path index (e.g. list 1 intra + list 2 top path fails).

**Phase 3B-3 integration risk:** Must bind `list_id[i]` to content `cluster_idxes[i]` and ideally to top-path direction bits; otherwise a prover could attach wrong-list auth subtrees if witness values are inconsistent but individually valid.

---

## 6. Tests

```bash
cargo test slot_aligned_auth --release
```

| Test | Expectation |
|------|-------------|
| `slot_aligned_auth_valid_two_level_opening_succeeds` | prove + verify OK |
| `slot_aligned_auth_forged_tenant_fails` | prove fails |
| `slot_aligned_auth_forged_cid_fails` | prove fails |
| `slot_aligned_auth_wrong_intra_list_path_fails` | prove fails |
| `slot_aligned_auth_wrong_top_level_path_fails` | prove fails |
| `slot_aligned_auth_cross_list_graft_fails` | list1 intra + list2 top path fails |
| `slot_aligned_auth_shared_list_root_fanout_succeeds` | 2 slots, 1 list root, 1 top path |
| `slot_aligned_auth_fanout_mismatch_fails` | 2 slots → different list roots, 1 shared target |

Fixtures use `hash_tree_gen` / `hash_tree_path` (same as Phase 2C-1) aligned with Python `auth_commitment.py` / `slot_aligned_auth_commitment.py`.

---

## 7. Current limitations

- Standalone gadget only; not wired into set-based auth proof.
- No `list_id_path_binding_gadget`.
- Top padding uses `H(0,0,0,0,0,0)` hash leaves (matches Python builder).
- No PyO3 exposure.

---

## 8. Next: Phase 3B-3 set_based_auth integration

1. Add `SlotAlignedAuthWitnessTargets` (shared top per list, intra per slot).
2. `set_based_auth_ivf_pq_gadget_committed_slot_aligned` — call probe-row gadget per probed list, then existing policy/mask/top-k.
3. Bind `list_id` to `cluster_idx_dis` / content probe selection.
4. Additive proof + PyO3 API + `tests/test_auth_zk_committed_slot_aligned.py`.
5. Global vs slot-aligned equivalence test on shared fixtures.
