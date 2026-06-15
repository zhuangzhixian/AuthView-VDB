# Phase 2B-3b: Set-Based Auth Policy Integration Log

Partial-visible AuthView set-based Merkle proof path with per-slot policy
visibility and auth-masked distance ordering.

**Branch:** `phase2-auth-setbased-policy`  
**Related:** [phase2_set_based_auth_all_visible_log.md](phase2_set_based_auth_all_visible_log.md),
[phase2_auth_policy_gadget_log.md](phase2_auth_policy_gadget_log.md),
[phase2_test_plan.md](phase2_test_plan.md).

---

## 1. New / modified files

| File | Change |
|------|--------|
| `src/merkle_ver/set_based_auth.rs` | `set_based_auth_ivf_pq_gadget_policy`, `SlotAuthLabelTargets` |
| `src/merkle_ver/set_based_auth_proof.rs` | `set_based_auth_ivf_pq_proof_policy`, witness helpers |
| `src/lib.rs` | `py_set_based_auth_with_merkle` (additive) |
| `auth_reference/v3db_adapter.py` | ZK integer encoding + ordered auth witness builders |
| `tests/test_auth_zk_partial_visible.py` | Partial-visible + all-visible policy regression |
| `docs/phase2_set_based_auth_policy_log.md` | This log |

**Not modified:** `set_based.rs`, `set_based_proof.rs`, `py_set_based_with_merkle`,
`py_set_based_auth_all_visible_with_merkle` logic.

---

## 2. Policy-integrated proof semantics

Per slot $$x$$:

1. $$v_x = P(\gamma_U, \lambda_x, \sigma)$$ via `auth_policy_visibility_gadget`
2. $$\hat d_x = (valid_x \cdot v_x)\, d_x + (1 - valid_x \cdot v_x)\, d_{max}$$
   via `auth_mask_distance_gadget`
3. Sorted witness `ordered_vpqss_item_dis` uses $$\hat d_x$$ (not raw $$d_x$$)
4. Set equality + non-decreasing + top-k public cids (same as baseline)

Auth labels are **sidecar witness** inputs (not Merkle-bound).

---

## 3. Python API

```python
from zk_IVF_PQ.zk_IVF_PQ import py_set_based_auth_with_merkle

metrics = py_set_based_auth_with_merkle(
    query, ivf_center, vpqss, valids, itemss, codebooks, ivf_roots,
    top_k, cluster_idx_dis,
    user_tenant_id,          # u64
    user_project_ids,        # list[u64], len 4
    user_project_valids,     # list[u64], len 4
    user_clearance,          # u64
    user_epoch,              # u64
    checkpoint_epoch,        # u64
    object_tenant_ids,       # list[list[u64]] [n_probe][n]
    object_project_ids,
    object_levels,
    object_states,
    object_epochs,
)
```

Baseline args unchanged; auth fields appended. Integer tags via
`auth_reference/v3db_adapter.py` registries (`ZK_TENANT_ID`, etc.).

---

## 4. Witness layout

### User context (shared)

| Field | Source |
|-------|--------|
| `user_tenant_id` | `encode_user_context_for_zk` |
| `user_project_ids[4]` | Sorted user projects |
| `user_project_valids[4]` | Slot occupancy |
| `user_clearance` | `UserContext.clearance` |
| `user_epoch` | `UserContext.epoch` |
| `checkpoint_epoch` | `Checkpoint.epoch` |

### Per-slot labels `[n_probe][capacity]`

| Field | Source |
|-------|--------|
| `object_tenant_ids` | `AuthLabel.tenant` → int |
| `object_project_ids` | `AuthLabel.project` → int |
| `object_levels` | `AuthLabel.level` |
| `object_states` | `AuthLabel.state` → int (`active`=1) |
| `object_epochs` | `AuthLabel.epoch` |

### Ordered distances

`build_ordered_auth_item_dis(candidates, user, checkpoint)`:

- Oracle: `compute_visibility` + `compute_masked_distance`
- Stable sort by masked distance (V3DB tie-break)
- Prover/Rust proof recomputes with `policy_visibility_witness` +
  `auth_masked_distance_witness` (integer semantics matching circuit)

---

## 5. Test results

```bash
cargo test auth_mask --release
cargo test auth_policy --release
cargo build --release
maturin develop --release
PYTHONPATH=. pytest tests/test_auth_reference.py tests/test_v3db_adapter.py \
  tests/test_auth_zk_all_visible.py tests/test_auth_zk_partial_visible.py -v
```

| Test | Checks |
|------|--------|
| `test_auth_zk_partial_visible_matches_plaintext_oracle` | Partial visibility; witness top-k == oracle; proof verifies; invisible masked |
| `test_auth_zk_policy_all_visible_matches_all_visible_path` | Policy path == oracle; proof verifies; gates ≥ all-visible path |

---

## 6. Plaintext oracle alignment

- Oracle: `auth_reference/reference.py` + `policy.py` (string tags)
- Circuit: integer tags via `v3db_adapter` registries
- Tests use labels from `build_partial_visible_labels` / `build_all_visible_auth_labels`
  with epochs set to `checkpoint.epoch` so string and integer epoch rules agree
- Top-k comparison uses `authorized_topk_v3db_tiebreak` (distance-only stable sort,
  matching circuit / V3DB)

---

## 7. Current limitations

- No `root_auth`; auth labels are unconstrained sidecar witness (only policy gadget binds semantics)
- No slot-aligned auth Merkle commitment
- Integer tag registries are test-scale, not production ID mapping
- Python policy role checks not in circuit
- APIs return timing metrics only, not extracted public cids

---

## 8. Next step: Phase 2C (root_auth / slot-aligned commitment)

1. Auth Merkle leaf: `(list_id, slot_id, cid, tenant, project, level, state, epoch, ...)`
2. Public `root_auth`; per-slot Merkle opens
3. Bind sidecar labels to committed auth snapshot
4. Extend witness layout per [phase2_witness_layout.md](phase2_witness_layout.md) §4.2

---

## 9. Constraints honored

- V3DB baseline unchanged
- All-visible AuthView path unchanged
- Additive APIs only
