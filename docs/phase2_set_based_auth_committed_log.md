# Phase 2C-2: Committed Auth-Label Set-Based Proof Path

## Summary

Additive AuthView proof path binding each slot's object auth label to a public
`root_auth` via Merkle opening before policy evaluation and distance masking.

## New / Modified Files

| File | Change |
|------|--------|
| `src/merkle_ver/set_based_auth.rs` | `SlotAuthMerkleWitnessTargets`, `set_based_auth_ivf_pq_gadget_committed` |
| `src/merkle_ver/set_based_auth_proof.rs` | `set_based_auth_ivf_pq_proof_committed`, `auth_tree_padded_size` |
| `src/lib.rs` | `py_set_based_auth_committed_with_merkle` |
| `auth_reference/auth_commitment.py` | `next_pow2`, `dummy_auth_label_for_slot`, `build_auth_tree_for_slot_labels`, `split_auth_path` |
| `auth_reference/v3db_adapter.py` | `build_committed_auth_witness` |
| `tests/test_auth_zk_committed.py` | Positive / negative committed-path tests |
| `docs/phase2_set_based_auth_committed_log.md` | This log |

Unchanged: `set_based_auth_ivf_pq_gadget_policy`, `set_based_auth_ivf_pq_proof_policy`,
`py_set_based_auth_with_merkle`, `py_set_based_auth_all_visible_with_merkle`,
`py_set_based_with_merkle`, V3DB baseline paths.

## Committed Path Semantics

Per slot \(x\) (probe \(i\), position \(j\)):

1. **Leaf:** \(\text{authLeaf}_x = H(\text{cid}_x, \text{tenant}_x, \text{project}_x, \text{level}_x, \text{state}_x, \text{epoch}_x)\)
   — field order matches Phase 2C-1 / `auth_commitment_gadget`.
2. **Merkle:** \(\text{MerkleVerify}(\text{authLeaf}_x, \text{path}_x, \text{root\_auth}) = 1\)
   — `auth_label_merkle_verify_gadget` connects each slot root to the same public `root_auth`.
3. **Policy:** \(v_x = P(\gamma_U, \lambda_x, \sigma)\) on the **same** label targets used for the leaf hash (`cid` from `itemss[i][j]`).
4. **Mask:** \(\hat d_x = (\text{valid}_x \cdot v_x)\, d_x + (1 - \text{valid}_x \cdot v_x)\, d_{\max}\).

Global auth tree: one Merkle tree over all `n_probe × n` slot leaves (row-major), padded to the next power of two with `H(0,0,0,0,0,0)` dummy leaves.

## Public Input: `root_auth`

- Type: single `u64` (same representation as V3DB IVF Merkle roots / Poseidon `hash_u64` output).
- Registered as a public input in the committed gadget (in addition to query and top-k cids).

## Auth Path Witness Layout

Shape aligned with object label arrays: **`[n_probe][n][depth]`**.

| Witness | Shape | Notes |
|---------|-------|-------|
| `object_tenant_ids` … `object_epochs` | `[n_probe][n]` | Must match leaf fields; `cid` implied by `itemss[i][j]` |
| `auth_path_directions` | `[n_probe][n][depth]` | `0` = current on left, `1` = current on right |
| `auth_path_siblings` | `[n_probe][n][depth]` | sibling hash at each level |

`depth = tree_depth(next_pow2(n_probe × n))`.

## Invalid Slot Handling

- Padding slots (`valid=0`): deterministic dummy label **`(cid, 0, 0, 0, 0, 0)`** with a valid Merkle opening under `root_auth`.
- Circuit still verifies Merkle for every slot (no conditional skip); distance is masked to `d_max` via `valid × visibility`.
- Fixed-shape witness requires full path arrays even when `valid=0`.

## Python API

```python
py_set_based_auth_committed_with_merkle(
    query, ivf_center, vpqss, valids, itemss, codebooks, ivf_roots,
    top_k, cluster_idx_dis,
    root_auth,                          # u64
    user_tenant_id, user_project_ids, user_project_valids,
    user_clearance, user_epoch, checkpoint_epoch,
    object_tenant_ids, object_project_ids, object_levels,
    object_states, object_epochs,       # [n_probe][n]
    auth_path_directions,               # [n_probe][n][depth]
    auth_path_siblings,                 # [n_probe][n][depth]
) -> (build_time, prove_time, verify_time, proof_size, memory, gates)
```

Witness builders:

- `build_auth_tree_for_slot_labels(slot_labels)` — global tree + padding
- `build_committed_auth_witness(buffers, labels)` — full committed witness from V3DB buffers
- `open_auth_label` / `dummy_auth_label_for_slot` — per-slot openings and invalid-slot labels

Prover-supplied ordered auth-masked distances are recomputed in Rust from policy + mask (same as policy path).

## Tests

| Test | Expectation |
|------|-------------|
| `test_auth_zk_committed_partial_visible_succeeds` | Partial visibility; oracle top-k == witness top-k; verify > 0 |
| `test_auth_zk_committed_forged_tenant_fails` | Tamper invisible slot tenant → `RuntimeError` at prove time |
| `test_auth_zk_committed_wrong_auth_path_fails` | Flip sibling bit → `RuntimeError` at prove time |
| `test_auth_zk_committed_all_visible_regression` | All visible; top-k matches policy oracle; verify succeeds |

Negative tests call the real ZK API; failures occur during proof generation (witness/circuit mismatch), surfaced as `PyRuntimeError`.

## Current Limitations

- **Non slot-aligned:** global auth tree over flattened slots, not per-cluster auth subtrees.
- **Power-of-two tree size** with zero-leaf padding.
- **No dynamic checkpoint registry** in-circuit; `checkpoint_epoch` is a witness/public policy input.
- **No slot-aligned commitment optimization** (deferred to Phase 3 evaluation).

## Next Steps (Phase 3)

1. Slot-aligned auth Merkle layout (auth root per IVF cluster / slot index).
2. Overhead evaluation: committed vs policy-only path (gates, prove/verify time, proof size).
3. Optional batch opening / shared path compression for adjacent slots.
4. Integration with V3DB checkpoint registry and production auth label ingestion.
