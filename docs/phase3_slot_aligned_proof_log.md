# Phase 3B-3: Slot-Aligned Committed AuthView ZK Proof Path

## Summary

Phase 3B-3 adds an **additive** slot-aligned committed AuthView ZK proof path. The global committed path (`py_set_based_auth_committed_with_merkle`) is unchanged and remains the regression baseline.

## New / Modified Files

| File | Change |
|------|--------|
| `src/merkle_ver/set_based_auth.rs` | `SlotAlignedTopWitnessTargets`, `SlotAlignedIntraWitnessTargets`, `set_based_auth_ivf_pq_gadget_committed_slot_aligned` |
| `src/merkle_ver/set_based_auth_proof.rs` | `set_based_auth_ivf_pq_proof_committed_slot_aligned` |
| `src/merkle_ver/slot_aligned_auth_commitment_gadget.rs` | `list_id_top_path_binding_gadget`, `u64_bit_decompose_gadget`, unit tests |
| `src/lib.rs` | `py_set_based_auth_slot_aligned_with_merkle` |
| `auth_reference/v3db_adapter.py` | `slot_labels_from_cid_map`, `split_slot_aligned_paths_for_zk`, `build_slot_aligned_zk_witness_for_buffers`, `top_k_cids_from_slot_aligned_ordered` |
| `tests/test_auth_zk_slot_aligned.py` | 7 ZK integration tests |
| `docs/phase3_slot_aligned_proof_log.md` | This document |

**Not modified:** V3DB baseline, `py_set_based_with_merkle`, `py_set_based_auth_committed_with_merkle`, global committed gadget/proof, benchmark CSV schema.

## Proof Path Semantics

Per probed IVF list row `i`:

1. **list_id binding:** `list_ids[i]` is connected to `cluster_idx_dis[i][0]` (content probe list). Top path direction bits are constrained to decompose `list_id` (MSB-first Merkle order).
2. **Shared top opening:** One `list_auth_root[i]` + `top_path[i]` verified once against public `root_auth`.
3. **Per-slot intra openings:** Each slot `j` verifies `authLeaf → list_auth_root` via `intra_path[i][j]`.
4. **Same label targets** feed commitment verify, `auth_policy_visibility_gadget`, and `auth_mask_distance_gadget`.
5. Set equality, sorted top-k, and V3DB Merkle commitment unchanged from global committed path.

## PyO3 API

```python
py_set_based_auth_slot_aligned_with_merkle(
    query, ivf_center, vpqss, valids, itemss, codebooks, ivf_roots,
    top_k, cluster_idx_dis,
    root_auth,
    user_tenant_id, user_project_ids, user_project_valids,
    user_clearance, user_epoch, checkpoint_epoch,
    object_tenant_ids, object_project_ids, object_levels,
    object_states, object_epochs,          # [n_probe][n_slot]
    list_ids, list_auth_roots,             # [n_probe] each
    top_path_directions, top_path_siblings,  # [n_probe][depth_top]
    intra_path_directions, intra_path_siblings,  # [n_probe][n_slot][depth_slot]
) -> (build_time, prove_time, verify_time, proof_size, memory_used, num_gates)
```

## Witness Layout

Built via `build_slot_aligned_zk_witness_for_buffers(buffers, labels, n_list=...)`.

| Field | Shape | Semantics |
|-------|-------|-----------|
| `root_auth` | scalar | Top-level auth Merkle root |
| `list_ids` | `[n_probe]` | IVF list index per probe row (= `buffers.cluster_idxes[i]`) |
| `list_auth_roots` | `[n_probe]` | Intra-list Merkle root for that list |
| `top_path_*` | `[n_probe][depth_top]` | **Shared** top path; duplicated per row if same list probed twice |
| `intra_path_*` | `[n_probe][n_slot][depth_slot]` | Per-slot opening under list root |
| `object_*` | `[n_probe][n_slot]` | Auth label integer fields |

Canonical shared representation: `SlotAlignedAuthWitness.shared_list_openings[list_id]` (Phase 3B-1); PyO3 arrays expand this per probe row.

## list_id Binding

Implemented in `list_id_top_path_binding_gadget`:

- Decompose `list_id` into `top_depth` bits (little-endian internally).
- Connect `top_path[level][0]` to bit `level` of `list_id` (LSB-first, matching `hash_tree_path`).
- `list_ids[i]` also connected to `cluster_idx_dis[i][0]` in the main gadget.

**Current limit:** Power-of-two padded `n_list` (e.g. `n_list=8` → 3-bit binding). Non-power-of-two `n_list` needs extended binding (future work).

## Global vs Slot-Aligned Equivalence

Same cid labels + buffers → same auth-masked distances and witness top-k. Trees differ (global flat vs two-level slot-aligned) so `root_auth` values differ; each path verifies against its own root.

## Tests (`tests/test_auth_zk_slot_aligned.py`)

| Test | Result |
|------|--------|
| Partial-visible proof succeeds | Positive |
| All-visible regression | Positive |
| Global vs slot-aligned equivalence | Positive (both verify, same top-k) |
| Forged tenant | Negative (ZK fails) |
| Wrong intra path | Negative |
| Wrong top path | Negative |
| Cross-list top path graft | Negative (list_id binding) |

Rust unit tests: `list_id_top_path_binding_accepts_matching_bits`, `list_id_top_path_binding_rejects_mismatched_bits`.

## Current Limitations

- `n_list` must be power-of-two for correct top-depth / list_id bit binding.
- Slot-aligned and global trees produce different `root_auth`; no single-root dual-mode proof yet.
- Python witness uses expanded per-row top paths (not deduplicated on wire).

## Next: Phase 3C Evaluation

- Extend `scripts/bench_auth_paths.py` with slot-aligned path (preserve CSV columns).
- Compare gate count / prove time: baseline vs global committed vs slot-aligned.
- Scan `(n_probe, slot_per_list, n_list)` grid from Phase 2E scaling study.
- Report opening-cost ideal vs measured gates.
