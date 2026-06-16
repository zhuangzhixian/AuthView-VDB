# Phase 3A: Slot-Aligned Auth Commitment — Test Plan

**Status:** test plan for Phase 3B implementation (no tests in Phase 3A).  
**Branch:** `phase3-slot-aligned-design`  
**Related:** [phase3_slot_aligned_auth_commitment_design.md](phase3_slot_aligned_auth_commitment_design.md),
[tests/test_auth_zk_committed.py](../tests/test_auth_zk_committed.py),
[tests/test_auth_commitment.py](../tests/test_auth_commitment.py),
[tests/test_auth_overhead_script.py](../tests/test_auth_overhead_script.py).

---

## 1. Scope

Verify that the slot-aligned committed-auth path:

1. Produces **semantically equivalent** results to the global committed path.
2. Preserves **negative security** (forged labels, bad paths fail).
3. Reduces **Merkle opening cost** vs global layout when shared list-root
   verification is implemented.

Existing global committed tests remain unchanged as regression suite.

---

## 2. Plaintext / unit tests (Python)

**File (proposed):** `tests/test_auth_slot_aligned_commitment.py`  
**Helpers under test:** `build_slot_aligned_auth_tree`, `open_auth_list_root`,
`open_auth_slot_in_list`, `build_slot_aligned_committed_witness`

### 2.1 Tree builder correctness

| Test | Description |
|------|-------------|
| `test_intra_list_leaf_matches_global_leaf` | Same `(cid, tenant, …, epoch)` → same `authLeaf` hash as Phase 2C-1 |
| `test_list_root_from_leaves` | Recompute `root^{auth}_{\ell}` from leaves matches builder |
| `test_top_root_from_list_roots` | Recompute `root_auth` from list roots matches builder |
| `test_power_of_two_padding_intra` | Non-power-of-two slot count pads with `H(0,…,0)` leaves |
| `test_power_of_two_padding_top` | Non-power-of-two `n_list` pads at top level |
| `test_open_list_root_under_top` | Top path verifies `root^{auth}_{\ell}` under `root_auth` |
| `test_open_slot_under_list_root` | Intra path verifies leaf under `root^{auth}_{\ell}` |

### 2.2 Witness layout

| Test | Description |
|------|-------------|
| `test_witness_shapes` | `top_path`: `[n_probe][depth_list]`; `intra_path`: `[n_probe][n_slot][depth_slot]` |
| `test_list_id_aligns_cluster_idx` | `list_id[i] == cluster_idxes[i]` for each probe row |
| `test_invalid_slot_dummy_label` | `valid=0` → `(cid,0,0,0,0,0)` with valid intra opening |
| `test_cid_aligns_itemss` | Leaf `cid` field matches `itemss[i][j]` |

### 2.3 Negative plaintext

| Test | Description |
|------|-------------|
| `test_forged_tenant_intra_fails` | Tamper tenant; intra opening does not verify |
| `test_wrong_intra_path_fails` | Flip sibling at intra level |
| `test_wrong_top_path_fails` | Valid intra paths but list root opens to wrong `root_auth` |
| `test_wrong_list_id_fails` | Opening from list A attached to probe row for list B (witness builder guard) |

---

## 3. Rust gadget tests

**File (proposed):** `src/merkle_ver/slot_aligned_auth_commitment_gadget.rs`  
**Pattern:** mirror `auth_commitment_gadget.rs` tests

| Test | Description |
|------|-------------|
| `test_intra_list_merkle_verify` | Gadget connects leaf to supplied list root |
| `test_top_list_merkle_verify` | Gadget connects list root to `root_auth` |
| `test_chained_two_level_verify` | Leaf → list root → top root in one builder |
| `test_shared_list_root_fanout` | Two slots same list share one list root target |
| `test_forged_leaf_fails_witness` | Bad witness → proof generation fails |

---

## 4. ZK integration tests (Python)

**File (proposed):** `tests/test_auth_zk_committed_slot_aligned.py`  
**Fixture:** reuse `synthetic_zk_index` from `test_auth_zk_committed.py`

### 4.1 Positive tests

| Test | Description |
|------|-------------|
| `test_slot_aligned_partial_visible_succeeds` | Partial-visible labels; prove/verify via new PyO3 API; `verify_time > 0` |
| `test_slot_aligned_oracle_topk_matches` | Plaintext authorized top-k == witness top-k |
| `test_slot_aligned_all_visible_regression` | All visible; matches policy / all-visible oracle |

### 4.2 Negative tests (must call real ZK API)

| Test | Description |
|------|-------------|
| `test_slot_aligned_forged_tenant_fails` | Correct tree; tamper invisible slot tenant → `RuntimeError` or verify false |
| `test_slot_aligned_wrong_intra_path_fails` | Flip intra sibling |
| `test_slot_aligned_wrong_top_path_fails` | Flip top-level sibling |
| `test_slot_aligned_list_id_mismatch_fails` | Top/intra paths for list ℓ attached to wrong probe row |

### 4.3 Global vs slot-aligned equivalence

| Test | Description |
|------|-------------|
| `test_global_vs_slot_aligned_same_topk` | Identical synthetic index, labels, user; both paths prove; public top-k cids equal |
| `test_global_vs_slot_aligned_same_visibility` | Per-slot policy visibility bits identical (plaintext oracle cross-check) |

Equivalence holds **only** when both layouts commit the same label multiset per
list/slot; builder tests must construct slot-aligned and global trees from the
same label source.

---

## 5. Overhead comparison

Extend **`scripts/bench_auth_paths.py`** (Phase 3B, not 3A) with optional fifth path:

```
auth_committed_slot_aligned
```

**Metrics (same CSV schema + path column):**

| Comparison | Expected on scaling grid |
|------------|--------------------------|
| `gates(slot_aligned) < gates(global_committed)` | When shared list-root implemented |
| `prove_time` / `proof_size` ratios | Document alongside Phase 2E baseline |
| Per-workload `depth_list`, `depth_slot` columns | Optional CSV extensions |

**Regression guard:** On minimal grid, assert

```
committed_slot_aligned_gates <= committed_global_gates
```

If not satisfied, treat as **implementation bug** (likely missing shared top path),
not as acceptable variance.

**Suggested grid:** reuse Phase 2E light config

```
n_probe ∈ {2, 4}, slot_per_list ∈ {32, 64}, top_k=5, repeat=1
```

Output: `artifacts/auth_zk_slot_aligned_scaling_metrics.csv` (separate file to
avoid overwriting Phase 2E artifact).

---

## 6. Test commands (Phase 3B target)

```bash
cargo test slot_aligned_auth --release
maturin develop --release

PYTHONPATH=. pytest \
  tests/test_auth_slot_aligned_commitment.py \
  tests/test_auth_zk_committed_slot_aligned.py \
  tests/test_auth_zk_committed.py \
  -v

python scripts/bench_auth_paths.py \
  --include-slot-aligned \
  --repeat 1 \
  --n-probe-list 2,4 \
  --slot-per-list-list 32,64 \
  --top-k-list 5 \
  --output artifacts/auth_zk_slot_aligned_scaling_metrics.csv
```

---

## 7. Acceptance criteria (Phase 3B done)

- [ ] All plaintext tree tests pass; leaf format matches Phase 2C-1
- [ ] Rust gadget tests pass including shared list-root fanout
- [ ] ZK positive tests prove and verify on partial-visible + all-visible fixtures
- [ ] All four negative ZK tests fail at prove or verify (not plaintext-only)
- [ ] Global vs slot-aligned equivalence tests pass on shared fixtures
- [ ] Scaling benchmark shows gate reduction vs global committed on ≥3/4 grid points
- [ ] Existing Phase 2C-2 tests unchanged and passing
- [ ] No changes to V3DB baseline API or semantics

---

## 8. Out of scope for test plan

- SIFT / large-scale dataset benchmarks
- Dynamic checkpoint registry
- Fuzzing / property-based testing (optional future work)
- Formal verification of circuit ↔ spec equivalence
