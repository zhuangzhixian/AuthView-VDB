# Phase 6: Visibility-Gated Scoring — Test Plan

**Phase:** 6A (planning) → 6B (implementation)  
**Companion:** [phase6_visibility_gated_design.md](phase6_visibility_gated_design.md)

This document lists tests required before visibility-gated scoring can be claimed as sound and before any optimization can be reported in a paper.

Tests are grouped by phase. **Phase 6A implements none of these.**

---

## 1. Test Philosophy

1. **Equivalence first:** gated program must match masked baseline outputs before any performance claim.
2. **Security before savings:** authorized-exclusion tests are blocking for ZK paths.
3. **Honest cost tests:** separate plaintext ideal model from static-circuit gate counts.
4. **Additive paths:** new ZK APIs must not regress existing `auth_committed`, `auth_slot_aligned`, `auth_acl_class` tests.

---

## 2. Phase 6B-1 — Plaintext Reference Tests

**File (proposed):** `tests/test_visibility_gated_reference.py`  
**Module (proposed):** `auth_reference/visibility_gated_reference.py`

### 2.1 Equivalence with masked baseline

| ID | Test | Description | Blocking? |
|----|------|-------------|-----------|
| PG-01 | `test_gated_topk_equals_masked_all_visible` | All slots visible; same top-k cids | Yes |
| PG-02 | `test_gated_topk_equals_masked_partial_visible` | Mixed visible/invisible (existing partial-visible fixture) | Yes |
| PG-03 | `test_gated_topk_equals_masked_post_filter_contrast` | Contrast fixture where post-filter ≠ authorized | Yes |
| PG-04 | `test_gated_masked_distance_multiset_equal` | Full `(cid, hat_d)` multiset equality, not just top-k | Yes |
| PG-05 | `test_gated_visibility_bits_match_policy` | Every slot: `v_x` from gated oracle = `P(γ_U, λ_x, σ)` | Yes |
| PG-06 | `test_gated_invalid_slots_use_d_max` | `valid_x=0` → `hat_d_x = d_max` | Yes |
| PG-07 | `test_gated_invisible_slots_use_d_max` | `v_x=0` → `hat_d_x = d_max` regardless of raw distance | Yes |

### 2.2 Visibility ratio sweeps

| ID | Test | Description | Blocking? |
|----|------|-------------|-----------|
| PG-10 | `test_gated_equivalence_sweep_visible_ratios` | Parameterized sweep: `visible_ratio` ∈ {0.05,…,1.0} | Yes |
| PG-11 | `test_gated_adc_eval_count_scales_with_n_vis` | Plaintext counter: ADC evals ≈ `N_vis`, not `N_sel` | For cost model |
| PG-12 | `test_gated_policy_eval_count` | Policy evals still account for all valid slots (or document class-level reduction) | For cost model |

### 2.3 Degenerate cases

| ID | Test | Description | Blocking? |
|----|------|-------------|-----------|
| PG-20 | `test_gated_all_invisible_topk` | All invisible → top-k from visible set empty / all `d_max` tie-break | Yes |
| PG-21 | `test_gated_single_visible` | `N_vis=1` | Yes |
| PG-22 | `test_gated_n_vis_equals_n_sel` | Gated ≡ masked; ADC count = `N_sel` | Yes |

---

## 3. Authorized Exclusion & Attack Tests (Plaintext)

These encode **Risk D.3** from the design doc.

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| AT-01 | `test_cannot_exclude_visible_by_forcing_gate_zero` | Manually zero gate on visible slot in **oracle** must change top-k vs baseline | Detect mismatch |
| AT-02 | `test_invisible_with_low_raw_distance_still_d_max` | Invisible slot with best raw ADC still masked to `d_max` | `hat_d = d_max` |
| AT-03 | `test_visible_must_use_raw_distance` | Visible slot cannot use `d_max` unless raw distance already maximal | Equivalence fail if swapped |

**Note:** AT-* in plaintext validate oracle design before ZK wiring.

---

## 4. Phase 6B-1 — Cost Model Tests

**File (proposed):** `tests/test_visibility_gated_cost_model.py`

| ID | Test | Description |
|----|------|-------------|
| CM-01 | `test_ideal_cost_monotone_in_visible_ratio` | `C_gated,ideal` decreases as `N_vis/N_sel` drops (holding `C_compact` fixed) |
| CM-02 | `test_compact_overhead_break_even` | Compute `N_vis*` where `(N_sel-N_vis)·C_dist > C_compact` |
| CM-03 | `test_current_cost_flat_in_visible_ratio` | Model: current path ADC term independent of visibility ratio |
| CM-04 | `test_acl_plus_gated_cost_composition` | Combined model: policy-once + distance-on-visible |

---

## 5. Phase 6B-2 — Component Gadget Tests (Rust)

**File (proposed):** `src/merkle_ver/visibility_gate_gadget.rs` + unit tests

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| GT-01 | `visibility_gate_derives_from_policy_output` | Gate wire connected to policy visibility, not free witness | Prove/verify ok |
| GT-02 | `gated_mask_matches_auth_mask_when_g_is_policy_derived` | Output equals `auth_mask_distance_gadget` | Algebraic equality |
| GT-03 | `free_gate_bit_with_low_distance_fails` | Adversarial gate witness (if wired for negative test) | Proof fail |
| GT-04 | `simulated_adc_constraint_count` | Test harness counts enabled ADC sub-constraints vs `N_vis` | Document static vs ideal gap |

**Important:** GT-04 is a **measurement** test, not a claim that production circuit already saves gates.

---

## 6. Phase 6B-3 — Full ZK Path Tests (if implemented)

**File (proposed):** `tests/test_auth_zk_visibility_gated.py`

### 6.1 Positive equivalence

| ID | Test | Description |
|----|------|-------------|
| ZK-01 | `test_auth_zk_gated_partial_visible_succeeds` | ZK verify succeeds |
| ZK-02 | `test_auth_zk_gated_topk_equals_committed` | Same fixture: gated top-k = `auth_committed` top-k |
| ZK-03 | `test_auth_zk_gated_all_visible_regression` | `visible_ratio=1` ≡ committed path outcomes |
| ZK-04 | `test_auth_zk_gated_equivalent_to_acl_class_topk` | Optional combined fixture |

### 6.2 Negative attacks (must call real ZK API)

| ID | Test | Attack | Expected |
|----|------|--------|----------|
| ZK-10 | `test_forged_gate_visible_as_invisible_fails` | Force gate=0 on visible slot while distance witness omits slot | Proof fail |
| ZK-11 | `test_forged_low_hat_d_on_invisible_fails` | Invisible slot with hat_d < d_max | Proof fail |
| ZK-12 | `test_visibility_label_mismatch_fails` | Open label satisfying P but claim v=0 without circuit support | Proof fail |
| ZK-13 | `test_compaction_drops_visible_slot_fails` | Omit visible slot from compact buffer | Proof fail |
| ZK-14 | `test_compaction_includes_invisible_fails` | Include invisible in visible buffer with low d | Proof fail |
| ZK-15 | `test_checkpoint_user_context_mismatch_fails` | Reuse committed tests pattern | Proof fail |

### 6.3 Regression

| ID | Test | Description |
|----|------|-------------|
| ZK-20 | `test_existing_auth_committed_unchanged` | Full committed suite still passes |
| ZK-21 | `test_existing_auth_acl_class_unchanged` | ACL-class suite still passes |

---

## 7. Benchmark / Evaluation Tests

**File (proposed):** `tests/test_visibility_gated_benchmark.py`  
**Scripts (proposed):** `scripts/bench_visibility_gated_paths.py`, `scripts/summarize_visibility_gated_metrics.py`

| ID | Test | Description |
|----|------|-------------|
| BM-01 | Bench script runs small config | Smoke |
| BM-02 | Raw CSV contains `auth_committed` + `auth_gated` (or ideal model rows) |
| BM-03 | `N_vis <= N_sel`, `visible_ratio = N_vis/N_sel` |
| BM-04 | Summary CSV: ideal gated cost ratio monotone trend (where applicable) |
| BM-05 | At low `visible_ratio`, ideal model below current (does **not** require implemented ZK win) |
| BM-06 | At `visible_ratio=1`, ideal ≈ current distance cost |

---

## 8. Integration with ACL-Class (Phase 5 + 6)

| ID | Test | Description |
|----|------|-------------|
| INT-01 | Plaintext: ACL-class gated ≡ ACL-class masked ≡ object-level masked | Single fixture |
| INT-02 | ZK (optional): `auth_acl_class_gated` ≡ `auth_acl_class` top-k |
| INT-03 | Cost model: policy-once + distance-on-visible combined |

---

## 9. Test Data Requirements

| Fixture | Source | Use |
|---------|--------|-----|
| All-visible synthetic IVF-PQ | `test_auth_zk_all_visible` pattern | Regression |
| Partial-visible | `build_partial_visible_labels` + tunable fraction | N_vis sweep |
| Compliant / post-filter contrast | `auth_reference/attacks.py` | Semantic gap |
| Attack matrix scenarios | `tests/test_auth_attack_matrix.py` | Security regression |

---

## 10. Acceptance Criteria (Phase 6 complete)

### Minimum (paper-supporting)

- [ ] All PG-* equivalence tests pass
- [ ] AT-* plaintext exclusion tests pass
- [ ] CM-* cost model tests pass
- [ ] N_vis/N_sel ideal curve generated (plaintext model)
- [ ] Documented static-circuit gap (6B-2)

### Strong (full ZK claim)

- [ ] All ZK-01…ZK-15 pass on real PyO3 API
- [ ] BM-* benchmark smoke passes
- [ ] No regression in Phase 0–5C test suites
- [ ] `auth_gated` additive path only; baselines unchanged

### Explicit non-requirement

- Implemented ZK gates < committed at all visibility ratios (may fail at high `N_vis/N_sel`; degenerate case documented)

---

## 11. Traceability Matrix

| Design soundness condition | Primary tests |
|--------------------------|---------------|
| D.1 Invisible cannot rank highly | PG-07, ZK-11 |
| D.2 Visible distance correct | PG-04, ZK-02 |
| D.3 No authorized exclusion | AT-01, GT-03, ZK-10 |
| D.4 No invisible as visible | PG-05, ZK-12 |
| D.5 Top-k equivalence | PG-01…PG-04, ZK-02 |
| D.6 Coverage | PG-04, ZK-13 |
