# Phase 5B-3: ACL-class Committed AuthView ZK Proof Path

## Summary

This phase adds an **additive** ACL-class committed proof path for authorized IVF-PQ set-based retrieval. Existing V3DB baseline, global committed (`auth_committed`), and slot-aligned paths are unchanged.

ACL-class compression evaluates policy **once per selected ACL class** (`N_acl`) instead of once per selected object (`N_sel`).

## New / Modified Files

| File | Change |
|------|--------|
| `src/merkle_ver/set_based_auth.rs` | Add `set_based_auth_ivf_pq_gadget_committed_acl_class`, witness target structs |
| `src/merkle_ver/set_based_auth_proof.rs` | Add `set_based_auth_ivf_pq_proof_committed_acl_class` |
| `src/lib.rs` | Add `py_set_based_auth_acl_class_with_merkle` PyO3 export |
| `auth_reference/acl_class_commitment.py` | `split_acl_class_zk_witness_for_zk`, `top_k_cids_from_acl_class_ordered`, probe-major V3DB grid (`_candidate_grid_from_v3db_buffers`), invalid-slot all-zero selectors |
| `tests/test_auth_zk_acl_class.py` | 11 positive/negative ZK tests |
| `docs/phase5_acl_class_proof_log.md` | This document |

**Not modified:** `py_set_based_with_merkle`, `py_set_based_auth_committed_with_merkle`, `py_set_based_auth_slot_aligned_with_merkle`, benchmark scripts.

## Proof Path Semantics

### A. Class commitment verify

For each row `j` in the fixed selected class table (`N_acl_max`):

- Merkle-open class label fields to public `root_acl_class` via `verify_acl_class_opening_gadget`.
- Dummy rows (`selected_class_valids[j]=0`) still verify an opening (dummy class id); policy forces `class_visibility[j]=0`.

### B. Policy-once

- `acl_class_policy_once_gadget` runs **once** over all `N_acl_max` rows.
- `class_visibilities[j] = P(user, class_label_j, checkpoint) * selected_class_valids[j]`.
- **No** per-slot call to `auth_policy_visibility_gadget`.

### C. Per-slot binding verify

For each candidate slot `(i,j)`:

- Merkle-open `(cid, acl_class_id, epoch)` to public `root_object_class_binding`.
- Constrain `binding.cid == itemss[i][j]` (slot cid target).
- Invalid slots (`valids[i][j]=0`): selector all zeros, inherited visibility 0.

### D. Table matching (`acl_class_table_match_gadget`)

- Valid slot: selector one-hot, selected row must be valid, `binding.acl_class_id == selected_class_ids[k]` for selected `k`.
- Invalid slot: selector sum = 0.

### E. Visibility inheritance

`inherit_slot_visibility_from_class_gadget`:

```
slot_visibility = slot_valid * Σ_k (selector_k * class_visibility_k)
```

### F. Masked distance + top-k

Same as committed path after visibility:

- `auth_mask_distance_gadget` → ordered distances → set equality → top-k content commitment.

## PyO3 API

```python
py_set_based_auth_acl_class_with_merkle(
    query, ivf_center, vpqss, valids, itemss, codebooks, ivf_roots,
    top_k, cluster_idx_dis,
    root_acl_class, root_object_class_binding,
    user_tenant_id, user_project_ids, user_project_valids,
    user_clearance, user_epoch, checkpoint_epoch,
    selected_class_valids, selected_acl_class_ids,
    selected_class_tenant_ids, selected_class_project_ids,
    selected_class_required_clearances, selected_class_states, selected_class_epochs,
    selected_class_path_directions, selected_class_path_siblings,
    binding_acl_class_ids, binding_epochs,
    binding_path_directions, binding_path_siblings,
    per_slot_class_selector,
) -> (build_time, prove_time, verify_time, proof_size, memory_used, num_gates)
```

## Witness Layout

Built by `build_acl_class_zk_witness_for_buffers` / `split_acl_class_zk_witness_for_zk`:

| Field | Shape | Notes |
|-------|-------|-------|
| `root_acl_class` | scalar | Merkle root over ACL class leaves |
| `root_object_class_binding` | scalar | Merkle root over binding leaves |
| Selected class table | `[N_acl_max]` | Fixed length; dummy padding when `N_acl < N_acl_max` |
| Per-slot bindings | `[n_probe][slot_per_list]` | Includes invalid slots (dummy binding leaf) |
| `per_slot_class_selector` | `[n_probe][slot][N_acl_max]` | One-hot if valid; **all zeros if invalid** |
| User context | encoded | Same as committed path |

Leaf hashes (match Phase 5B-1):

- `aclClassLeaf = H(acl_class_id, tenant_id, project_id, required_clearance, state, epoch)`
- `objClassLeaf = H(cid, acl_class_id, epoch)`

## Object-level vs ACL-class Equivalence

On the same fixture (partial-visible synthetic index):

- Object-level committed top-k == ACL-class compressed top-k (plaintext oracle).
- Both `py_set_based_auth_committed_with_merkle` and `py_set_based_auth_acl_class_with_merkle` verify successfully.

Degenerate case `N_acl = N_sel` (one class per object) remains semantically equivalent.

## Negative Tests (real ZK API)

| Test | Attack |
|------|--------|
| Forged class label fields | Tamper tenant/project/clearance/state/epoch vs opening |
| Forged binding | Tamper `binding_acl_class_ids` |
| Selector mismatch | Binding class A, selector selects class B |
| Invalid selected row | Valid slot selects dummy (`valid=0`) row |
| Root mixing | Wrong `root_acl_class` |
| User context mismatch | Low-clearance user yields different authorized top-k vs high-clearance oracle; proof with low-clearance public inputs still verifies (user context is public circuit input, not committed in Merkle leaves) |

## Current Limitations

- No Phase 5C benchmark / `N_acl/N_sel` cost evaluation in this phase.
- Dummy class rows still verify Merkle openings (documented; visibility forced to 0).
- `N_acl_max` defaults to `next_pow2(N_acl)` in witness builder.
- Witness per-slot arrays follow **probe-major order** (row `i` = probe `i`), matching `vpqss` / `valids` / `itemss` layout.
- Invalid slots: selector all-zero (not dummy-row one-hot).

## Next: Phase 5C Evaluation Plan

1. Measure prove/verify time and gate count vs `auth_committed` across `N_sel`, `N_acl`, `N_acl_max`.
2. Sweep compression ratios (shared-class vs one-class-per-object).
3. Record policy-once savings: `N_acl` policy gadgets vs `N_sel` in object-level path.
4. Optional: gate-count regression in CI (smoke only, no CSV artifacts in repo).
