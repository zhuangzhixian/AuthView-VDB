# Phase 10: ZK Implementation Gap Audit

**Phase:** 10  
**Purpose:** Pause paper consolidation; audit what is **actually implemented in ZK** vs plaintext evaluation layers (Phase 8C–9C)  
**Branch:** `phase10-zk-implementation-gap-audit`  
**Companion:** [zk_path_status_matrix.md](zk_path_status_matrix.md), [public_trace_to_zk_pilot_plan.md](public_trace_to_zk_pilot_plan.md)

---

## 1. Executive summary

AuthView has a **mature synthetic-workload ZK stack** (5 measured proof paths + content-only baseline) and a **separate public-benchmark evaluation layer** (Phase 8C unrestricted utility, Phase 9A authorization overlay, Phase 9B full-base calibration, Phase 9C consolidation).

**These layers are not connected.**

| Layer | Status |
|-------|--------|
| ZK proof paths on controlled parameterized workloads | **Implemented, tested, benchmarked** |
| Plaintext authorized reference + public trace semantics | **Implemented, tested** (Phase 1B, 9A, 9B) |
| Access-aware proof planning | **Cost-model only** (Phase 6; no circuit change) |
| Public-trace-derived ZK proof instances | **Not implemented** |

Phase 8C/9A/9B/9C strengthen **public dataset and authorization semantics evidence**. They do **not** complete the proof-carrying pipeline. Phase 7 overhead figures use **controlled parameterized proof workloads**, not public benchmark traces.

---

## 2. What is real ZK today?

### 2.1 Rust / PyO3 proof entrypoints (`src/lib.rs`)

| Internal path | PyO3 function | Relation |
|---------------|---------------|----------|
| `baseline` | `py_set_based_with_merkle` | Content-only V3DB-shaped IVF-PQ |
| `auth_all_visible` | `py_set_based_auth_all_visible_with_merkle` | Auth mask gadget; visibility ≡ 1 |
| `auth_policy` | `py_set_based_auth_with_merkle` | Policy + mask; labels as witness (no Merkle bind) |
| `auth_committed` | `py_set_based_auth_committed_with_merkle` | Committed auth (`root_auth`) |
| `auth_slot_aligned` | `py_set_based_auth_slot_aligned_with_merkle` | Two-level slot-aligned commitment |
| `auth_acl_class` | `py_set_based_auth_acl_class_with_merkle` | ACL-class table + object binding |

Proof drivers: `src/merkle_ver/set_based_auth_proof.rs`, gadgets under `src/merkle_ver/`.

### 2.2 Witness and plaintext reference (`auth_reference/`)

| Module | Role | ZK? |
|--------|------|-----|
| `reference.py` | Authorized masked top-k oracle | Plaintext |
| `post_filter.py` | Post-filter baseline | Plaintext |
| `policy.py` | Visibility predicate P(U,λ,σ) | Used by ZK + plaintext |
| `auth_commitment.py` | Flat auth Merkle witness | Witness for `auth_committed` |
| `slot_aligned_auth_commitment.py` | Slot-aligned Merkle witness | Witness for `auth_slot_aligned` |
| `acl_class_commitment.py` | ACL-class witness | Witness for `auth_acl_class` |
| `v3db_adapter.py` | Synthetic slot buffers → ZK inputs | **Synthetic workloads only** |
| `proof_planning_reference.py` | Region-based cost model | **Cost-model only** |
| `layout_planning_reference.py` | SA/PA layout cost model | **Cost-model only** |

### 2.3 Benchmarks and artifacts

| Script | Paths | Output |
|--------|-------|--------|
| `scripts/bench_auth_paths.py` | baseline, auth_all_visible, auth_policy, auth_committed, auth_slot_aligned | `artifacts/auth_zk_paper_ready_*.csv` |
| `scripts/bench_acl_class_paths.py` | auth_committed vs auth_acl_class | `artifacts/auth_zk_acl_class_*_repeat3.csv` |
| `scripts/bench_proof_planning_*.py` | Cost-model regions | `artifacts/proof_planning_*.csv` |

Figures/tables: Phase 7 proof overhead/scaling/ACL-class exports under `artifacts/figures/`, `artifacts/tables/`.

### 2.4 Public benchmark layer (NOT ZK)

| Phase | Scripts | Artifacts | ZK? |
|-------|---------|-----------|-----|
| 8C | `run_public_utility_baseline.py` | `sift_gist_utility_summary.csv`, traces NPZ | No |
| 9A | `generate_authorization_overlay.py`, `evaluate_authorized_trace.py` | `public_trace_auth_*.csv` | No |
| 9B | `select_authorized_calibration_queries.py`, `calibrate_full_authorized_reference.py` | `calibration_queries.csv`, `full_authorized_reference_*.csv` | No |
| 9C | `build_evaluation_inventory.py` | `evaluation_inventory/*.csv` | No |

---

## 3. End-to-end pipeline assessment

### 3.1 Implemented: synthetic ZK pipeline

```text
ivf_pq_learn (synthetic index)
  → v3db_adapter.build slot buffers + distances
  → policy labels / visibility
  → auth_commitment | slot_aligned | acl_class witness builders
  → py_set_based_auth_* (Plonky2 prove + verify)
  → compare to run_authorized_reference (plaintext)
```

**Evidence:** `tests/test_auth_zk_*.py`, `tests/test_auth_attack_matrix.py`, `scripts/bench_auth_paths.py`.

### 3.2 Implemented: public plaintext pipeline

```text
Phase 8C trace (pred, gt from full 1M IVF-PQ)
  → Phase 9A generated ACL overlay (visibility NPZ)
  → post-filter / candidate-level / (9B) full-base exact L2
  → CSV metrics + figures
```

**Evidence:** Phase 9A/9B logs, `public_trace_auth_summary.csv`, `full_authorized_reference_summary.csv`.

### 3.3 Missing: public-trace → ZK bridge

```text
[NOT IMPLEMENTED]
Phase 8C trace query_id + pred[:N_sel]
  → Phase 9A visibility mask → auth labels / ACL bindings
  → V3DB-shaped slot buffers from public candidates
  → witness builders
  → py_set_based_auth_*
  → prove / verify metrics joined to overlay CSV
```

**Gap:** No module maps `artifacts/public_utility/traces/*.npz` or `artifacts/auth_overlay/*_visibility.npz` into `v3db_adapter` / witness builders. ZK benches use **fresh synthetic indices**, not public trace prefixes.

---

## 4. Answers to audit questions

### Q1. Which ZK proof paths exist?

| Path | Exists in ZK? |
|------|---------------|
| Content-only (`baseline`) | Yes |
| Auth-static ablation (`auth_all_visible`, `auth_policy`) | Yes |
| Auth-committed (`auth_committed`) | Yes |
| Slot-aligned (`auth_slot_aligned`) | Yes |
| ACL-class (`auth_acl_class`) | Yes |
| Access-aware proof planning | **No** (cost-model only) |
| Public-trace-derived proof instance | **No** (planned Phase 11) |

### Q2–Q3. Status and evidence per path

See [zk_path_status_matrix.md](zk_path_status_matrix.md).

### Q4. End-to-end public → ZK pipeline?

**No.** Public phases stop at plaintext/reference evaluation.

### Q5. Missing bridge modules

1. **`public_trace_candidate_extractor`** — load trace row `(query_id, pred[:N_sel], gt)`; align `N_sel` with proof circuit shape.
2. **`overlay_to_auth_labels`** — map Phase 9A visibility mask + policy mode to per-object labels / ACL class table for witness encoding.
3. **`public_slot_buffer_builder`** — populate `V3DBSlotBuffers` from public candidate IDs + stored distances (or recompute ADC from index).
4. **`calibration_query_pilot_selector`** — read `calibration_queries.csv`; pick stratified pilot set.
5. **`run_public_trace_zk_pilot.py`** — orchestrate witness → prove → verify → CSV (Phase 11).
6. **`join_zk_metrics_to_overlay`** — attach gates/time/size to Phase 9A/9B rows for paper table.

---

## 5. Honest scope boundaries

| Claim | Valid today? |
|-------|--------------|
| “We prove authorized-view IVF-PQ on synthetic workloads” | **Yes** (committed / slot / ACL paths) |
| “We measured overhead vs content-only baseline” | **Yes** (Phase 7 CSV, controlled workloads) |
| “Public benchmarks show authorization utility gaps” | **Yes** (Phase 9A/9B, **plaintext/reference**) |
| “Public benchmark queries are proof-carrying today” | **No** |
| “Proof planning reduces measured ZK gates” | **No** (cost-model only) |
| “Visibility-gated distance skip is in circuits” | **No** (Phase 6 design deferred) |

---

## 6. Test coverage summary

| Area | Test files | Proves ZK? |
|------|------------|------------|
| Plaintext auth | `test_auth_reference.py` | No |
| Baseline ZK | `test_auth_zk_all_visible.py` | Yes |
| Policy path | `test_auth_zk_partial_visible.py` | Yes |
| Committed | `test_auth_zk_committed.py`, `test_auth_commitment.py` | Yes |
| Slot-aligned | `test_auth_zk_slot_aligned.py`, `test_auth_slot_aligned_commitment.py` | Yes |
| ACL-class | `test_auth_zk_acl_class.py`, `test_acl_class_*.py` | Yes |
| Attack matrix | `test_auth_attack_matrix.py` | Yes (rejection) |
| Proof planning | `test_proof_planning_*.py` | No |
| Public overlay | `test_authorization_overlay.py`, `test_authorized_reference_calibration.py` | No |
| Bench smoke | `test_auth_overhead_script.py`, `test_auth_metrics_summary.py` | Invokes PyO3 |

**No test** proves ZK on public trace inputs.

---

## 7. Recommended next step

Implement **Phase 11: public-trace-derived ZK proof pilot** per [public_trace_to_zk_pilot_plan.md](public_trace_to_zk_pilot_plan.md) — minimal bridge from `calibration_queries.csv` to existing `auth_committed` / `auth_slot_aligned` / `auth_acl_class` entrypoints.

---

## 8. Related documents

- [zk_path_status_matrix.md](zk_path_status_matrix.md)
- [public_trace_to_zk_pilot_plan.md](public_trace_to_zk_pilot_plan.md)
- [phase9c_evaluation_consolidation.md](phase9c_evaluation_consolidation.md)
- [phase2_overhead_eval_log.md](phase2_overhead_eval_log.md)
- [phase5_acl_class_eval_log.md](phase5_acl_class_eval_log.md)
