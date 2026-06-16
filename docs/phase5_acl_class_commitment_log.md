# Phase 5B-1: ACL-Class Commitment and ZK Witness Layout Log

**Status:** plaintext commitment + witness layout only — **not** a ZK proof path  
**Branch target:** `phase5-acl-class-commitment`

Related: [phase5_acl_class_plaintext_log.md](phase5_acl_class_plaintext_log.md),
[next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md).

---

## 1. Motivation

ACL-class compression reduces repeated dynamic auth work when
\(N_{acl} \ll N_{sel}\). The core gain is **not** the Merkle tree shape alone,
but:

1. **Policy evaluated once per unique ACL class** (not per slot).
2. **Per-slot object-to-class binding** (static) separate from dynamic class state.

Phase 5B-1 materializes commitment leaves, Merkle trees, and a fixed-shape
ZK-ready witness for Phase 5B-2 Rust gadgets and Phase 5B-3 proof path.

---

## 2. Commitment layout

Two parallel Merkle trees:

| Tree | Root | Leaf |
|------|------|------|
| ACL class | `root_acl_class` | `aclClassLeaf` |
| Object binding | `root_object_class_binding` | `objClassLeaf` |

### Leaf field order (fixed for Rust)

**aclClassLeaf:**

```
H(acl_class_id, tenant_id, project_id, required_clearance, state, epoch)
```

**objClassLeaf:**

```
H(cid, acl_class_id, epoch)
```

- `state` encoded as integer (`active=1`, `inactive=0`), matching `v3db_adapter.ZK_STATE_ID`.
- Hash: Poseidon `single_hash` (same as `auth_commitment.py`).

Implementation: `auth_reference/acl_class_commitment.py`.

---

## 3. Selected class table design

Fixed-length table of size `N_acl_max` for circuit regularity:

| Field | Shape | Description |
|-------|-------|-------------|
| `selected_class_labels` | `[N_acl_max]` | ACL class labels (real + dummy padding) |
| `selected_class_valids` | `[N_acl_max]` | `1` = used class, `0` = dummy row |
| `selected_class_path_*` | `[N_acl_max][depth_class]` | Merkle openings to `root_acl_class` |

**Padding convention:** unused rows filled with `dummy_acl_class_label()`
(`acl_class_id=0`, inactive, epoch=0). Dummy class is always included in the
ACL class Merkle corpus for consistent openings.

**Per-slot lookup:**

| Field | Shape | Description |
|-------|-------|-------------|
| `per_slot_class_index` | `[n_probe][slot]` | Index into selected table |
| `per_slot_class_selector` | `[n_probe][slot][N_acl_max]` | One-hot selector (exactly one `1` per valid layout) |

Invalid / padding slots point to the first dummy table row; binding leaf uses
`(cid, 0, 0)`.

---

## 4. Witness layout

`ACLClassZkWitness` (see `build_acl_class_zk_witness_for_candidates`):

```
root_acl_class
root_object_class_binding
N_acl_max, n_probe, slot_per_list

selected_class_labels[N_acl_max]
selected_class_valids[N_acl_max]
selected_class_path_directions[N_acl_max][depth_class]
selected_class_path_siblings[N_acl_max][depth_class]

per_slot_bindings[n_probe][slot]
per_slot_binding_path_directions[n_probe][slot][depth_binding]
per_slot_binding_path_siblings[n_probe][slot][depth_binding]

per_slot_class_index[n_probe][slot]
per_slot_class_selector[n_probe][slot][N_acl_max]

class_visibility_plaintext[N_acl_max]
expected_slot_visibility[n_probe][slot]
```

Binding tree is row-major over the candidate grid (`n_probe × slot_per_list`).

---

## 5. Plaintext validation

`verify_acl_class_witness_plaintext` checks:

1. Class Merkle openings → `root_acl_class`
2. Binding Merkle openings → `root_object_class_binding`
3. `binding.cid == candidate.cid` for valid slots
4. `binding.acl_class_id == selected_class_labels[index].acl_class_id`
5. One-hot selector matches `per_slot_class_index`
6. Class visibility matches `evaluate_acl_class_visibility`
7. Slot visibility inherits class visibility
8. Top-k equivalent to object-level reference (`compare_object_level_vs_acl_class_reference`)

---

## 6. Class visibility inheritance

```
v_c = P(gamma_U, Lambda_c, sigma)     # once per selected class row
v_x = v_c  where class(binding(x)) = c  # inherited per slot
```

Invisible class → all bound objects masked to `d_max` (Phase 5A oracle).

---

## 7. Cost model

`estimate_acl_class_zk_cost`:

| Metric | Object-level | ACL-class |
|--------|--------------|-----------|
| Policy evals | `N_sel` | `N_acl` |
| Auth openings | `N_sel` label | `N_acl` class + `n_probe×slot` binding |

Relative costs stored in `ACLClassZkCost` for CSV / paper figures.

---

## 8. Tests

File: `tests/test_acl_class_commitment.py` (16 tests)

Covers: leaf determinism, valid/forged openings, witness verification, top-k
equivalence, table padding, index/cid mismatch rejection, `N_acl=1` and
`N_acl=N_sel` degenerate cases, cost model benefit / no-benefit.

```bash
PYTHONPATH=. pytest tests/test_acl_class_reference.py tests/test_acl_class_commitment.py -v
```

---

## 9. CSV artifact

`artifacts/acl_class_commitment_cases.csv` — witness validation snapshots.

```bash
PYTHONPATH=. python scripts/write_acl_class_commitment_cases.py
```

---

## 10. Limitations (Phase 5B-1)

- No Rust gadgets or PyO3 API.
- No ZK proof generation / verification.
- Class table matching constraints (selector ↔ opening) documented but not
  enforced in-circuit.
- Binding tree covers witness grid only (full corpus binding is Phase 5B-2 scope).

---

## 11. Next: Phase 5B-2 Rust gadget plan

1. **`acl_class_commitment_gadget.rs`**
   - `acl_class_leaf_hash_gadget` (field order as above)
   - `object_class_binding_leaf_hash_gadget`
   - Merkle verify helpers (reuse `merkle_back_gadget`)

2. **Class table matching**
   - `acl_class_selector_gadget`: one-hot + index binding
   - Prove `binding.acl_class_id == selected_class_table[index].acl_class_id`

3. **Policy-once wiring**
   - Evaluate policy on `N_acl_max` class rows (mask dummy rows via `selected_class_valids`)
   - Slot visibility = selected class visibility via selector dot-product

4. **Additive proof path** `auth_committed_acl_class` in `set_based_auth.rs`
   - Do **not** modify existing `auth_committed` regression path

5. **Tests**
   - `tests/test_auth_acl_class_commitment.py` (Rust leaf hash parity)
   - Phase 5B-3: `tests/test_auth_zk_acl_class.py` (full prove/verify)
