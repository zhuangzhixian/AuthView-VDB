# Phase 6B-1: Access-Aware Proof Planning Plaintext Reference

**Phase:** 6B-1  
**Branch:** `phase6-proof-planning-reference`  
**Status:** plaintext reference + tests (no ZK, no CSV)

---

## Goal

Implement a **plaintext proof planning oracle** that:

1. Partitions fixed-shape candidate slots into `pure_visible`, `pure_invisible`, and `impure` regions.
2. Executes planned scoring semantics with top-k **equivalent** to masked-distance baseline.
3. Validates region purity against committed auth visibility (not prover-controlled).
4. Exports relative **cost-model counters** for Phase 6B-2 sweeps.

This phase does **not** modify Rust, PyO3, or ZK circuits.

---

## New Files

| File | Role |
|------|------|
| `auth_reference/proof_planning_reference.py` | Plan builder, planned execution, validation, cost model |
| `tests/test_proof_planning_reference.py` | PP/PV/PI/IM/COV/AT/CM/EQ/DEG tests |
| `docs/phase6_proof_planning_reference_log.md` | This document |

---

## Region Data Model

### `ProofRegion`

| Field | Meaning |
|-------|---------|
| `region_id` | Stable id within plan |
| `region_type` | `pure_visible` \| `pure_invisible` \| `impure` |
| `region_key` | Grouping key (e.g. `acl-1`, `list-0`, `block-2`) |
| `grouping_strategy` | `acl_class` \| `ivf_list` \| `fixed_block` |
| `candidate_indices` | Indices into candidate list (0..N_slots-1) |
| `valid_count` | Valid slots in region |
| `visible_count` / `invisible_count` | Among valid slots |
| `estimated_distance_count` | Conservative distance work counter |
| `estimated_visibility_count` | Conservative visibility work counter |

### `ProofPlan`

Aggregates regions plus metrics:

- **N_slots** = `len(candidates)` (includes invalid padding)
- **N_valid** = valid candidate count
- **N_vis** / **N_invis** = visible / invisible among valid
- Region counts and ratios (`pure_region_ratio`, `impure_region_ratio`)
- Cost estimates and `N_dist_*` counters

---

## Grouping Strategies

### 1. ACL-class (`acl_class`)

- Valid slots grouped by `ObjectClassBinding.acl_class_id`.
- Invalid slots grouped as `invalid-list-{list_id}` (impure padding).
- Purity from **per-object** visibility under committed labels (same as baseline).

### 2. IVF-list (`ivf_list`)

- One region per `list_id` (probed IVF list row).
- Purity from valid slots in that list.

### 3. Fixed-block (`fixed_block`)

- Candidates sorted by `(list_id, slot_id)`, chunked by `block_size` (default 16).
- Simulates access-aware block layout without building a Veda index.

**Rules:**

- Empty regions are not emitted.
- Every slot index appears in exactly one region.
- Invalid slots do not affect purity typing but are included for coverage.

---

## Planned Execution Semantics

`run_authorized_reference_planned(candidates, user, checkpoint, plan, top_k)`:

| Region type | Valid slot scoring | Distance computation (semantic) |
|-------------|-------------------|--------------------------------|
| `pure_visible` | `hat_d = d`, visibility treated as 1 | Yes (all valid in region) |
| `pure_invisible` | `hat_d = d_max`, visibility 0 | No |
| `impure` | Per-slot `P(γ_U, λ_x, σ)` + masked distance | Yes (per-slot fallback) |
| Invalid slot | `masked = d_max` | N/A |

Top-k uses same `(masked_distance, cid)` ordering as `run_authorized_reference`.

---

## Validation Rules

`validate_proof_plan(...)` checks:

1. **Coverage:** every slot index covered; every valid index exactly once among valid coverage.
2. **Disjointness:** no duplicate indices across regions.
3. **Purity correctness:** `region_type` must match visibility of valid slots in region.
4. **Anti-tamper:** false `pure_invisible` on visible slot → fail (authorized exclusion attack).
5. **Top-k equivalence** (optional): planned ≡ masked baseline.

Region types are **derived from auth state**, not free prover labels.

---

## Cost Model (Plaintext Only)

Default weights (`DEFAULT_COST_PARAMS`):

| Param | Value |
|-------|-------|
| C_dist | 10 |
| C_vis | 3 |
| C_mask | 1 |
| C_region_pure | 5 |
| C_region_impure | 2 |
| C_topk_per_candidate | 1 |
| C_compact | 5 |

**Masked baseline:**

```
C_masked = N_valid * (C_vis + C_dist + C_mask) + N_valid * C_topk
N_dist_masked = N_valid
```

**Conservative plan:**

```
pure_visible:  C_region_pure + valid_count * C_dist
pure_invisible: C_region_pure
impure:        C_region_impure + valid_count * (C_vis + C_dist + C_mask)
+ N_valid * C_topk
N_dist_plan = sum(pure_visible.valid_count) + sum(impure.valid_count)
```

**Ideal visible compaction:**

```
C_ideal = N_valid * C_vis + N_vis * C_dist + C_compact + N_vis * C_topk
N_dist_ideal = N_vis
```

### Static circuit caveat

Per-candidate conditional mux in a **fixed-shape ZK circuit does not reduce gates**. This module models **ideal / structural** savings when circuit shape can omit ADC or batch policy proofs. Phase 6B-1 does **not** claim measured ZK gate reduction.

---

## Tests

`tests/test_proof_planning_reference.py` — 18 tests:

| ID | Test |
|----|------|
| PP-01 | ACL-class produces three region types |
| PP-02 | IVF-list full coverage |
| PP-03 | Fixed-block full coverage |
| PV-01 | pure_visible ≡ masked |
| PI-01 | pure_invisible, N_dist=0, ≡ masked |
| IM-01 | impure fallback ≡ masked |
| COV-01 | missing coverage fails |
| COV-02 | duplicate coverage fails |
| AT-01 | false pure_invisible fails |
| AT-02 | false pure_visible fails |
| CM-01 | pure_invisible lowers N_dist_plan |
| CM-02 | all-visible: N_dist_plan = N_valid |
| CM-03 | all-invisible: N_dist_plan = 0 |
| EQ-01 | mixed fixture top-k match |
| DEG-01 | all impure ≡ masked |

Run:

```bash
PYTHONPATH=. pytest tests/test_proof_planning_reference.py -v
```

---

## Limitations

- Plaintext only; no ZK region purity gadget.
- Cost weights are relative units, not measured gates.
- ACL-class grouping uses per-object labels for purity (not class-level visibility alone) — conservative for impure detection when object labels diverge within a class.
- No CSV output in this phase.
- Does not implement visible-subset dynamic compaction.

---

## Next: Phase 6B-2 Cost-Model Sweep

1. **Script:** `scripts/bench_proof_planning_model.py` (plaintext counter only).
2. **Sweeps:** visible ratio, ACL clustering, grouping strategy, block_size.
3. **Figures:** N_vis/N_sel vs ideal cost; pure/impure ratio vs PA (normalized to masked).
4. **Outputs:** CSV artifacts for paper plots (deferred to 6B-2).
5. **Monotonicity:** CM-P01–P06 from [phase6_access_aware_proof_plan_test_plan.md](phase6_access_aware_proof_plan_test_plan.md).

Do **not** connect to Rust until 6B-2 break-even analysis supports optional 6B-3 region purity ZK gadget.
