# Phase 2B-3a: Set-Based Auth All-Visible Log

Additive AuthView set-based Merkle proof path with fixed visibility
$$v_x \equiv 1$$. Validates that authorized masking degenerates to V3DB
valid-bit masking and that proofs succeed on synthetic data.

**Branch:** `phase2-auth-setbased-allvisible`  
**Related:** [phase2_auth_mask_gadget_log.md](phase2_auth_mask_gadget_log.md),
[phase2_auth_policy_gadget_log.md](phase2_auth_policy_gadget_log.md),
[phase2_zk_integration_design.md](phase2_zk_integration_design.md),
[phase2_test_plan.md](phase2_test_plan.md).

---

## 1. New files

| File | Purpose |
|------|---------|
| `src/merkle_ver/set_based_auth.rs` | `set_based_auth_ivf_pq_gadget_all_visible` |
| `src/merkle_ver/set_based_auth_proof.rs` | `set_based_auth_ivf_pq_proof_all_visible` |
| `tests/test_auth_zk_all_visible.py` | Smoke + baseline equivalence test |
| `docs/phase2_set_based_auth_all_visible_log.md` | This log |

## 2. Modified files

| File | Change |
|------|--------|
| `src/merkle_ver/mod.rs` | Export `set_based_auth`, `set_based_auth_proof` |
| `src/lib.rs` | Add `py_set_based_auth_all_visible_with_merkle` (additive) |

**Not modified:** `set_based.rs`, `set_based_proof.rs`, `py_set_based_with_merkle`
implementation logic.

---

## 3. All-visible semantics

Fixed visibility:

$$
v_x = 1
$$

Masked distance via `auth_mask_distance_gadget`:

$$
g_x = valid_x \cdot v_x = valid_x
$$

$$
\hat d_x = g_x \cdot d_x + (1 - g_x) \cdot d_{max}
= valid_x \cdot d_x + (1 - valid_x) \cdot d_{max}
$$

This matches V3DB baseline valid-bit masking in `set_based.rs` lines 91–96.

**Not used in this phase:** `auth_policy_gadget`, `root_auth`, slot-aligned auth
commitment.

---

## 4. New API

### Rust

- `set_based_auth_ivf_pq_gadget_all_visible(...)` — circuit gadget
- `set_based_auth_ivf_pq_proof_all_visible(...)` — prove + verify

### Python (PyO3)

```python
from zk_IVF_PQ.zk_IVF_PQ import py_set_based_auth_all_visible_with_merkle

metrics = py_set_based_auth_all_visible_with_merkle(
    query, ivf_center, vpqss, valids, itemss,
    codebooks, ivf_roots, top_k,
    cluster_idx_dis, ordered_vpqss_item_dis,  # [] ok; Rust recomputes
)
# returns (build_time, prove_time, verify_time, proof_size, memory_used, num_gates)
```

Signature matches `py_set_based_with_merkle` exactly.

---

## 5. Relationship to V3DB baseline

| Aspect | Baseline | Auth all-visible |
|--------|----------|------------------|
| Witness layout | Same | Same |
| Public top-k items | First k cids from sorted witness | Same |
| Distance masking | `valid * d + (1-valid) * d_max` | Via mask gadget with `v=1` |
| Merkle commitment | `standalone_commitment_gadget` | Same |
| Policy gadget | N/A | Not wired |

Circuit gate count is **≥ baseline** (extra mask gadget per slot).

---

## 6. Test results

**Commands:**

```bash
cargo test auth_mask --release
cargo test auth_policy --release
cargo build --release
maturin develop --release
PYTHONPATH=. pytest tests/test_auth_reference.py tests/test_v3db_adapter.py tests/test_auth_zk_all_visible.py -v
```

**`tests/test_auth_zk_all_visible.py`:**

1. Synthetic IVF-PQ index (`ivf_pq_learn`, no SIFT).
2. Plaintext oracle: `run_all_visible_authorized_reference` top-k == `v3db_baseline_topk`.
3. `py_set_based_with_merkle` and `py_set_based_auth_all_visible_with_merkle` both prove/verify.
4. Same witness inputs; verify times > 0.
5. Auth path gate count ≥ baseline.

**Note:** Python APIs return timing metrics only, not public top-k cids. Top-k
equivalence is validated via plaintext oracle + identical witness / masking
semantics when $$v_x \equiv 1$$.

---

## 7. Current limitations

- Visibility hard-coded to constant `1`; no per-slot policy.
- No `auth_policy_gadget` integration.
- No `root_auth` or auth Merkle opens.
- No Python helper returning public top-k from proof object.
- `ordered_vpqss_item_dis` still recomputed in Rust (same as baseline).

---

## 8. Next step: Phase 2B-3b (partial-visible + policy)

1. Add `set_based_auth_ivf_pq_gadget(...)` with per-slot
   `auth_policy_visibility_gadget(..., checkpoint_epoch)`.
2. Witness builder: per-slot auth labels from `v3db_adapter`.
3. Recompute `ordered_vpqss_item_dis` with auth-masked distances in prover.
4. Add `py_set_based_auth_with_merkle` (general path).
5. Tests: `tests/test_auth_zk_partial_visible.py` per
   [phase2_test_plan.md](phase2_test_plan.md).

---

## 9. Constraints honored

- V3DB baseline API and behavior unchanged
- Additive Python entry only
- No `root_auth` / slot-aligned auth commitment
