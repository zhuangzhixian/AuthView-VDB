# Phase 5B-2: ACL-Class Rust Standalone Gadgets Log

**Status:** standalone Rust gadgets + unit tests only  
**Branch target:** `phase5-acl-class-gadget`

Related: [phase5_acl_class_commitment_log.md](phase5_acl_class_commitment_log.md),
[phase5_acl_class_plaintext_log.md](phase5_acl_class_plaintext_log.md).

---

## 1. New gadget file

`src/merkle_ver/acl_class_commitment_gadget.rs` — exported from `src/merkle_ver/mod.rs`.

**Not modified:** `lib.rs`, `set_based_auth.rs`, `set_based_auth_proof.rs`, PyO3 API,
benchmark scripts.

---

## 2. Leaf field order

| Leaf | Fields (hash order) |
|------|---------------------|
| **aclClassLeaf** | `acl_class_id`, `tenant_id`, `project_id`, `required_clearance`, `state`, `epoch` |
| **objClassLeaf** | `cid`, `acl_class_id`, `epoch` |

Plaintext helpers: `acl_class_leaf_hash_u64`, `object_class_binding_leaf_hash_u64`.

Matches Python `auth_reference/acl_class_commitment.py`.

---

## 3. Merkle verify semantics

| Gadget | Role |
|--------|------|
| `verify_acl_class_opening_gadget` | Recompute `root_acl_class` from class label + path |
| `verify_object_class_binding_opening_gadget` | Recompute `root_object_class_binding` from binding + path |

Reuses `merkle_back_gadget` / path format from `auth_commitment_gadget`.

---

## 4. Selected class table matching

`acl_class_table_match_gadget` (per slot):

| Constraint | Rule |
|------------|------|
| Selector boolean | each `selector_j ∈ {0,1}` |
| Valid slot | `sum(selector) = slot_valid = 1` |
| Invalid slot | `sum(selector) = slot_valid = 0` |
| Selected row valid | `selector_j ⇒ selected_class_valids[j] = 1` |
| Class id match | `selector_j ⇒ binding_acl_class_id = selected_class_ids[j]` |

**Invalid slot convention:** all selector bits zero; no class row selected.
Dummy class (`acl_class_id = 0`, `valid = 0`) is not selected on invalid slots.

---

## 5. Policy-once design

`acl_class_policy_once_gadget`:

- Input: `UserContextTargets`, `[N_acl_max]` `ACLClassLabelTargets`, `selected_class_valids`, `checkpoint_epoch`
- Maps each class row to `ObjectLabelTargets` (`required_clearance` → `object_level`)
- Calls `auth_policy_visibility_gadget` **once per table row**
- Output: `class_visibilities[j] = raw_vis[j] * selected_class_valids[j]`
- Dummy rows (`valid=0`) forced to visibility 0 without affecting valid rows

**Core compression:** policy evaluated `N_acl` times at circuit level, not `N_sel`.

---

## 6. Slot visibility inheritance

`inherit_slot_visibility_from_class_gadget`:

```
slot_visibility = slot_valid * sum_j(selector_j * class_visibilities[j])
```

- Valid slot inherits selected class visibility
- Invalid slot → visibility 0
- Selector bits supplied by table matching gadget

---

## 7. Dummy / invalid slot convention

| Case | Binding | Selector | Visibility |
|------|---------|----------|------------|
| Valid slot | real `(cid, class_id, epoch)` | exactly one-hot on valid row | inherits class vis |
| Invalid slot | dummy `(cid, 0, 0)` allowed | all zeros | 0 |

---

## 8. Test coverage

```bash
cargo test acl_class --release
```

17 tests in `acl_class_commitment_gadget::tests`:

| Category | Tests |
|----------|-------|
| Leaf hash | deterministic ACL class + binding |
| Merkle | valid/forged ACL class opening; valid/forged binding opening |
| Table match | valid slot; class id mismatch; not one-hot; invalid row; invalid slot zero selector; degenerate N_acl=N_sel |
| Policy-once | matches object-level fields; dummy visibility 0 |
| Inheritance | success; wrong class fails; all-same-class reuse |

Regression (unchanged paths):

```bash
cargo test auth_commitment --release
cargo test slot_aligned_auth --release
cargo test auth_policy --release
```

---

## 9. Current limitations

- Standalone gadgets only — **not wired** into `set_based_auth` proof path
- No PyO3 witness ingestion
- Fixed `N_acl_max` in unit tests (`const N_ACL_MAX = 4`)
- No auth_mask / top-k / set equality integration (Phase 5B-3)
- No Python↔Rust hash parity test in this phase (field order documented; parity in 5B-3)

---

## 10. Next: Phase 5B-3 ACL-class proof path

1. Add `set_based_auth_acl_class` module (additive) wiring:
   - content openings (unchanged V3DB)
   - ACL class + binding Merkle openings per witness layout
   - `acl_class_table_match_gadget` per slot
   - `acl_class_policy_once_gadget` once per query
   - `inherit_slot_visibility_from_class_gadget` → existing auth_mask path
2. PyO3 API + `v3db_adapter` witness builder from `ACLClassZkWitness`
3. Equivalence tests vs `auth_committed` on shared fixtures
4. Attack matrix extension: forged binding / wrong class table row
5. Phase 5C: benchmark path + `N_acl/N_sel` figure (not in 5B-3 scope)

**Reminder:** ACL-class compression value is **class-level policy once + per-slot binding + visibility inheritance**, not Merkle shape alone.
