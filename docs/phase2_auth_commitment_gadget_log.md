# Phase 2C-1: Auth Label Commitment Gadget Log

Standalone auth label Merkle commitment gadget. Binds per-object auth labels to
`root_auth` via leaf hash + opening path. **Not wired into set-based auth proof
path in this phase.**

**Branch:** `phase2-auth-label-commitment`  
**Related:** [phase2_set_based_auth_policy_log.md](phase2_set_based_auth_policy_log.md),
[phase2_witness_layout.md](phase2_witness_layout.md),
[phase2_zk_integration_design.md](phase2_zk_integration_design.md).

---

## 1. New files

| File | Purpose |
|------|---------|
| `src/merkle_ver/auth_commitment_gadget.rs` | Leaf hash + Merkle verify gadgets + Rust tests |
| `auth_reference/auth_commitment.py` | Plaintext Merkle tree helpers |
| `tests/test_auth_commitment.py` | Python commitment tests |
| `docs/phase2_auth_commitment_gadget_log.md` | This log |

## 2. Modified files

| File | Change |
|------|--------|
| `src/merkle_ver/mod.rs` | `pub mod auth_commitment_gadget;` |

**Not modified:** `set_based.rs`, `set_based_auth.rs`, `py_set_based_with_merkle`,
`py_set_based_auth_with_merkle`, existing proof paths.

---

## 3. Auth leaf format

$$
authLeaf_x = H(cid_x, tenant_x, project_x, level_x, state_x, epoch_x)
$$

| Index | Field | Notes |
|-------|-------|-------|
| 0 | `cid` | Content item id (must align with `itemss[i][j]`) |
| 1 | `tenant` | Integer tag (ZK policy field) |
| 2 | `project` | Integer tag |
| 3 | `level` | Clearance level |
| 4 | `state` | `1` = active |
| 5 | `epoch` | Authorization epoch |

### Hash function

- **Poseidon** `hash_no_pad` via `hash_gadget` / `hash_u64` (same as V3DB content Merkle)
- Six field elements fit in a single Poseidon hash (no layered hash needed)

### Merkle tree

- Full binary tree, leaf count **power of two** (matches `merkle_tree_gadget`)
- Internal nodes: `H(left, right)` via two-element `hash_gadget`
- Opening path: `[direction, sibling]` per level (`merkle_back_gadget` / `hash_tree_path`)

---

## 4. Rust API

| Symbol | Role |
|--------|------|
| `AuthLabelCommitmentTargets` | Six leaf field targets |
| `auth_label_leaf_hash_gadget` | Leaf Poseidon hash |
| `auth_label_merkle_verify_gadget` | Recompute root from label + path |
| `auth_label_leaf_hash_u64` | Plaintext leaf hash helper |

---

## 5. Python API (`auth_reference/auth_commitment.py`)

| Function | Role |
|----------|------|
| `compute_auth_leaf(...)` | Leaf hash via `single_hash` |
| `build_auth_merkle_tree(leaves)` | `(root, hash_tree)` |
| `open_auth_label(idx, tree)` | Merkle path |
| `verify_auth_opening_plaintext(label, path, root)` | Plaintext verify |

Field order: `(cid, tenant, project, level, state, epoch)`.

---

## 6. Tests

**Rust:**

```bash
cargo test auth_commitment --release
```

| Test | Case |
|------|------|
| `auth_commitment_valid_opening_succeeds` | Valid 4-leaf opening |
| `auth_commitment_forged_tenant_fails` | Wrong tenant |
| `auth_commitment_forged_project_fails` | Wrong project |
| `auth_commitment_forged_level_state_epoch_fails` | Wrong level/state/epoch |
| `auth_commitment_forged_cid_fails` | Wrong cid |
| `auth_commitment_wrong_merkle_path_fails` | Corrupted sibling |

**Python:**

```bash
PYTHONPATH=. pytest tests/test_auth_commitment.py -v
```

Mirrors the same six attack cases at plaintext layer.

---

## 7. Current limitations

- Standalone gadget only — **not integrated** into `set_based_auth_ivf_pq_gadget_policy`
- No public `root_auth` input in full proof yet
- No slot-aligned leaf `(list_id, slot_id, ...)` — Phase 2C-1 uses minimal
  `H(cid, ...)` per user spec (witness layout §4.2 slot extension deferred)
- Tree size must be power of two
- No PyO3 export for commitment helpers (Python uses `single_hash` directly)

---

## 8. Next step: Phase 2C-2 integration

1. Per slot in `set_based_auth_ivf_pq_gadget_policy`:
   - `auth_label_merkle_verify_gadget(label, path)` → local root
   - `builder.connect(local_root, root_auth_public)`
2. Witness builder: `open_auth_label` per slot from committed auth snapshot
3. Forbid sidecar label fields without valid opening under `root_auth`
4. Negative ZK tests: forged label / wrong path rejected in full proof

---

## 9. Constraints honored

- V3DB baseline unchanged
- Existing auth proof APIs unchanged
- Additive modules only
