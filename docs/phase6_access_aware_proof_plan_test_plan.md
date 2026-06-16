# Phase 6A-2: Access-Structure-Aware Proof Planning — Test Plan

**Phase:** 6A-2 (planning) → 6B (implementation)  
**Companion:** [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md), [phase6_visibility_gated_test_plan.md](phase6_visibility_gated_test_plan.md)

Tests for **proof planning reference** (plaintext first). Phase 6A-2 implements none of these.

---

## 1. Test Philosophy

1. **Plan ≡ masked baseline** before any performance claim.
2. **Region purity is security-critical** — pure-invisible false positives are authorized-exclusion attacks.
3. **Coverage is mandatory** — missing slots break retrieval soundness.
4. **Impure fallback** must reduce to existing Phase 5/6A semantics.
5. **Cost model** tests structural purity, not only global `N_vis/N_sel`.

---

## 2. Phase 6B-1 — Plaintext Plan Equivalence

**Module (proposed):** `auth_reference/proof_planning_reference.py`  
**File (proposed):** `tests/test_proof_planning_reference.py`

| ID | Test | Description | Blocking? |
|----|------|-------------|-----------|
| PP-01 | `test_planned_topk_equals_masked_all_visible` | Single pure-visible plan over full grid | Yes |
| PP-02 | `test_planned_topk_equals_masked_partial_visible` | Mix of region types | Yes |
| PP-03 | `test_planned_masked_distance_multiset_equal` | Full `(cid, hat_d)` equality | Yes |
| PP-04 | `test_planned_equals_gated_candidate_oracle` | Plan ≡ Phase 6A gated oracle (when built) | Yes |
| PP-05 | `test_planned_equals_acl_class_oracle` | Same top-k as ACL-class compressed path | Yes |
| PP-06 | `test_degenerate_all_impure_equals_committed` | Every region impure → same as per-slot | Yes |

---

## 3. Pure-Visible Region Correctness

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| PV-01 | `test_pure_visible_region_all_slots_visible` | Internal check: ∀x∈R, v_x=1 | Pass |
| PV-02 | `test_pure_visible_assigns_raw_distance` | hat_d_x = d_x for x∈R | Pass |
| PV-03 | `test_false_pure_visible_rejected_by_classifier` | Region with one invisible slot must not type as pure-visible | Planner types as impure |
| PV-04 | `test_pure_visible_skips_per_slot_policy_in_counter` | Plaintext policy eval count < \|R\| | Cost model only |
| PV-05 | `test_merged_pure_visible_blocks` | Two lists both pure-visible, merged region | Equivalence |

---

## 4. Pure-Invisible Region & Authorized Exclusion Attacks

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| PI-01 | `test_pure_invisible_all_hat_d_max` | ∀x∈R, hat_d_x = d_max | Pass |
| PI-02 | `test_pure_invisible_skips_adc_in_counter` | ADC eval count 0 for R | Cost model |
| PI-03 | `test_false_pure_invisible_exclusion_changes_topk` | Force invisible typing on visible slot in oracle | top-k ≠ masked |
| PI-04 | `test_planner_never_types_mixed_region_pure_invisible` | Impure list classification | impure |
| PI-05 | `test_close_visible_in_list_not_pure_invisible` | Nearest neighbor visible in IVF list | impure or pure-visible sub-split |
| PI-06 | `test_pure_invisible_large_block_sweep` | Large pure-invisible region; equivalence | Pass |

**PI-03** is the plaintext analogue of authorized exclusion (blocking for planner design).

---

## 5. Impure Fallback Tests

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| IM-01 | `test_impure_region_per_slot_visibility` | Each slot v_x from P | Pass |
| IM-02 | `test_impure_region_uses_masked_distance` | Same hat_d as baseline | Pass |
| IM-03 | `test_impure_with_acl_class_path` | ACL-class inside impure region | Equivalence |
| IM-04 | `test_impure_single_slot_region` | Region size 1 | ≡ candidate-level |
| IM-05 | `test_split_impure_list_by_acl_class` | Sub-regions reduce impure fraction | Equivalence + metrics |

---

## 6. Region Coverage Tests

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| COV-01 | `test_plan_covers_all_reference_slots` | ∪ R_i.slots = Cand | Pass |
| COV-02 | `test_plan_regions_disjoint` | No slot in two regions | Pass |
| COV-03 | `test_invalid_padding_slots_included` | Padding slots in plan | Covered |
| COV-04 | `test_missing_slot_detected` | Deliberately drop slot in test harness | Coverage check fails |
| COV-05 | `test_n_probe_list_partition` | Default planner: one region per probed list minimum | Pass |

---

## 7. Cost Model Monotonicity Tests

**File (proposed):** `tests/test_proof_planning_cost_model.py`

| ID | Test | Description |
|----|------|-------------|
| CM-P01 | `test_planned_cost_decreases_with_pure_invisible_ratio` | More pure-invisible area → lower ideal cost |
| CM-P02 | `test_planned_cost_at_least_masked_when_all_impure` | All impure ≥ masked cost model |
| CM-P03 | `test_same_n_vis_different_structure_different_cost` | Equal N_vis/N_sel, different purity layout |
| CM-P04 | `test_region_proof_overhead_break_even` | Compute minimum \|R\| for purity proof to pay off |
| CM-P05 | `test_acl_plus_plan_composition` | C_acl + region planning combined model |
| CM-P06 | `test_n_dist_visible_equals_visible_slot_count` | Counter sanity |

---

## 8. SA / PA Metadata Tests

These validate **metrics exported for paper discussion**, not full SA/PA benchmark infrastructure.

| ID | Test | Description |
|----|------|-------------|
| SA-01 | `test_sa_metadata_region_tree_count` | Count extra auth/commitment structures in plan metadata |
| SA-02 | `test_sa_non_negative` | SA ≥ 1 in defined model |
| PA-01 | `test_pa_planned_le_pa_masked_when_pure_blocks_exist` | PA(plan) ≤ PA(masked) in ideal model |
| PA-02 | `test_pa_masked_equals_one_at_oracle` | Normalization baseline |
| PA-03 | `test_pa_monotone_with_pure_invisible_ratio` | Ideal PA decreases as pure-invisible grows |

---

## 9. Workload Sweeps (Plaintext Benchmark)

**Script (proposed):** `scripts/bench_proof_planning_model.py`

| ID | Test | Description |
|----|------|-------------|
| SW-01 | Sweep `visible_ratio` with **scattered** vs **block** invisible layout |
| SW-02 | Same `N_vis/N_sel`, compare planned cost (block should win) |
| SW-03 | Export `pure_visible_ratio`, `pure_invisible_ratio`, `impure_ratio` |
| SW-04 | IVF list = region default; record per-list purity histogram |

---

## 10. Phase 6B-3 — Optional ZK Component Tests

Only if region purity gadget is implemented.

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| ZK-R01 | `test_region_pure_invisible_gadget_sound` | Valid pure-invisible region | Verify ok |
| ZK-R02 | `test_region_pure_invisible_with_visible_slot_fails` | One visible slot | Proof fail |
| ZK-R03 | `test_region_pure_visible_gadget` | All visible | Verify ok |
| ZK-R04 | `test_planned_zk_topk_equals_committed` | Full path | Equivalence |
| ZK-R05 | `test_free_region_type_witness_fails` | Prover-chosen type without proof | Fail |

---

## 11. Regression & Integration

| ID | Test | Scope |
|----|------|-------|
| REG-01 | All Phase 0–5C tests unchanged | No baseline mutation |
| REG-02 | Phase 6A PG-* tests still pass when gated oracle exists | Candidate-level semantics preserved |
| INT-01 | Plan + ACL-class fixtures from Phase 5 | Combined equivalence |
| INT-02 | Attack matrix authorized-exclusion scenarios | Planner must not worsen attack surface in plaintext |

---

## 12. Acceptance Criteria

### Phase 6B-1 minimum

- [ ] PP-01…PP-06, PI-01…PI-04, IM-01…IM-02, COV-01…COV-03 pass
- [ ] CM-P01…CM-P03 pass
- [ ] Block vs scattered sweep (SW-01…SW-02) demonstrates structural purity effect

### Phase 6B-2 (benchmark)

- [ ] SW-03 exported for paper figures (optional CSV outside 6A-2 scope)
- [ ] PA-01…PA-03 pass in ideal model

### Phase 6B-3 (optional ZK)

- [ ] ZK-R01…ZK-R03 pass
- [ ] No regression in committed / ACL-class ZK suites

---

## 13. Traceability to Soundness (Design Doc §D)

| Soundness ID | Primary tests |
|--------------|---------------|
| S1 Coverage | COV-01…COV-05 |
| S2 Purity soundness | PV-03, PI-04, PI-05 |
| S3 No unauthorized inclusion | IM-01, PP-03 |
| S4 No authorized exclusion | PI-03, PI-05, ZK-R02 |
| S5 Impure fallback | IM-01…IM-05 |
| S6 Top-k equivalence | PP-01…PP-06 |
| S7 Checkpoint binding | REG-02 + future ZK root tests |
