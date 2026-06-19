# ZK Path Status Matrix

**Phase:** 10  
**Purpose:** Per-path implementation, test, benchmark, and public-integration status  
**Updated:** Phase 10 gap audit

Legend — **implementation status:** `implemented` · `cost-model only` · `planned`  
Legend — **risk level:** `low` · `medium` · `high` (paper/reviewer risk if misclaimed)

---

## Master matrix

| proof path | relation components | implementation status | test coverage | benchmark status | public workload integration | missing bridge | paper placement | risk level |
|------------|---------------------|----------------------|---------------|------------------|----------------------------|----------------|-----------------|------------|
| **content-only** (`baseline`) | Content Merkle, valid-bit mask, IVF-PQ ADC, top-k sort | **implemented** | `test_auth_zk_all_visible.py`, `test_v3db_adapter.py` | `bench_auth_paths.py`; `auth_zk_paper_ready_summary.csv` | None (unrestricted utility in 8C is plaintext) | Public trace → slot buffers | Main RQ2 lower bound | low |
| **auth-static ablation — all-visible** (`auth_all_visible`) | + `auth_mask_distance_gadget`, v≡1 | **implemented** | `test_auth_zk_all_visible.py` | Same as overhead bench | None | Same as baseline | Appendix ablation | low |
| **auth-static — policy witness** (`auth_policy`) | + `auth_policy_visibility_gadget`, witness labels (no Merkle) | **implemented** | `test_auth_zk_partial_visible.py` | Same as overhead bench | None | Overlay → witness labels | Appendix ablation | medium (must not claim committed auth) |
| **auth-committed** (`auth_committed`) | + `auth_label_merkle_verify_gadget`, public `root_auth`, user context | **implemented** | `test_auth_zk_committed.py`, `test_auth_commitment.py`, `test_auth_attack_matrix.py` (A2–A5, A12) | `bench_auth_paths.py`; paper-ready CSV | **None** | Public trace + overlay → committed witness | Main RQ2/RQ5 | low (if scoped to controlled workloads) |
| **slot-aligned committed** (`auth_slot_aligned`) | + two-level auth Merkle, `list_id` binding | **implemented** | `test_auth_zk_slot_aligned.py`, `test_auth_slot_aligned_commitment.py`, attack A6–A8 | `bench_auth_paths.py`; slot ratio columns in summary CSV | **None** | Public slot layout + overlay → slot-aligned witness | Main / appendix RQ3 | low |
| **ACL-class committed** (`auth_acl_class`) | + ACL class table Merkle, object↔class binding, public `root_acl_class` | **implemented** | `test_auth_zk_acl_class.py`, `test_acl_class_*.py` | `bench_acl_class_paths.py`; `auth_zk_acl_class_summary_repeat3.csv` | **None** | Overlay ACL classes → ACL witness | Main RQ3 | low |
| **access-aware proof planning** | Pure/impure regions, merged-k, SA/PA cost units | **cost-model only** | `test_proof_planning_reference.py`, `test_proof_planning_cost_model.py`, layout tests | `bench_proof_planning_model.py`, `bench_proof_planning_layout.py`; `proof_planning_paper_*.csv` | None | ZK region gadgets (Phase 6B-3 deferred) | Main RQ4 with **cost-model disclaimer** | **high** if claimed as gate reduction |
| **visibility-gated distance skip** | Skip ADC for invisible slots in circuit | **planned** | Design memos only (`phase6_visibility_gated_*.md`) | None | None | Circuit + witness spec | Future work | medium |
| **public-trace-derived proof instance** | Phase 8C pred prefix + 9A mask + committed/slot/ACL path | **planned** | None | None | Artifacts exist upstream (traces, overlay, calibration CSV) | Full bridge stack (see below) | Appendix pilot (Phase 11) | **high** until pilot runs |

---

## Evidence index by path

### content-only (`baseline`)

| Kind | Path |
|------|------|
| Gadget | `src/merkle_ver/set_based.rs` |
| Proof | `src/merkle_ver/set_based_proof.rs` |
| PyO3 | `src/lib.rs` → `py_set_based_with_merkle` |
| Python | `ivf_pq/merkle_zk.py`, `auth_reference/v3db_adapter.py` |
| Bench | `scripts/bench_auth_paths.py` |
| CSV | `artifacts/auth_zk_paper_ready_summary.csv` |
| Figures | `artifacts/figures/main_proof_overhead_*.pdf` |
| Limitation | Controlled parameterized workloads; not public traces |

### auth-committed (`auth_committed`)

| Kind | Path |
|------|------|
| Gadget | `src/merkle_ver/set_based_auth.rs`, `auth_commitment_gadget.rs`, `auth_mask_gadget.rs`, `auth_policy_gadget.rs` |
| Proof | `src/merkle_ver/set_based_auth_proof.rs` |
| Witness | `auth_reference/auth_commitment.py` → `build_committed_auth_witness` |
| PyO3 | `py_set_based_auth_committed_with_merkle` |
| Security | `artifacts/auth_attack_matrix.csv`, `tests/test_auth_attack_matrix.py` |
| Limitation | No public-trace witness source |

### slot-aligned (`auth_slot_aligned`)

| Kind | Path |
|------|------|
| Gadget | `slot_aligned_auth_commitment_gadget.rs` |
| Witness | `auth_reference/slot_aligned_auth_commitment.py` |
| PyO3 | `py_set_based_auth_slot_aligned_with_merkle` |
| CSV | `artifacts/auth_zk_slot_aligned_metrics.csv` (snapshot) |
| Limitation | ~2–5% gate delta vs flat committed; public layout not wired |

### ACL-class (`auth_acl_class`)

| Kind | Path |
|------|------|
| Gadget | `acl_class_commitment_gadget.rs` |
| Witness | `auth_reference/acl_class_commitment.py` |
| PyO3 | `py_set_based_auth_acl_class_with_merkle` |
| Bench | `scripts/bench_acl_class_paths.py` |
| CSV | `artifacts/auth_zk_acl_class_summary_repeat3.csv` |
| Figures | `artifacts/figures/main_acl_class_*.pdf` |
| Limitation | N_acl sweep on controlled workloads; overlay ACL not wired |

### access-aware proof planning

| Kind | Path |
|------|------|
| Reference | `auth_reference/proof_planning_reference.py`, `layout_planning_reference.py` |
| Bench | `scripts/bench_proof_planning_model.py`, `bench_proof_planning_layout.py` |
| Figures | `artifacts/figures/main_merged_k_knob.pdf`, `main_cost_breakdown_clean.pdf` |
| Limitation | **Does not modify ZK circuits or measured gates** |

### public-trace-derived (planned)

| Kind | Path |
|------|------|
| Upstream traces | `artifacts/public_utility/traces/*_results.npz` |
| Visibility | `artifacts/auth_overlay/*_visibility.npz` |
| Query selection | `artifacts/auth_calibration/calibration_queries.csv` (~572 rows) |
| Pilot plan | [public_trace_to_zk_pilot_plan.md](public_trace_to_zk_pilot_plan.md) |
| Limitation | **Not implemented** |

---

## Missing bridge modules (ordered)

| # | Module | Input | Output | Blocks |
|---|--------|-------|--------|--------|
| B1 | `public_trace_candidate_extractor` | trace NPZ, query_id, N_sel | candidate IDs, gt, config metadata | All public ZK |
| B2 | `overlay_to_auth_labels` | visibility NPZ, policy_mode, selectivity | per-slot labels, ACL table, visibility bits | auth_committed, ACL-class |
| B3 | `public_slot_buffer_builder` | candidates + IVF index or stored distances | `V3DBSlotBuffers` | Witness encoding |
| B4 | `calibration_query_pilot_selector` | `calibration_queries.csv`, case filters | pilot query manifest CSV | Pilot scope |
| B5 | `run_public_trace_zk_pilot.py` | manifest + paths | prove/verify metrics CSV | Phase 11 deliverable |
| B6 | `join_zk_metrics_to_overlay` | pilot CSV + 9A/9B summary | unified evaluation row | Paper table |

---

## Paper placement quick reference

| Path | Main | Appendix | Do not claim |
|------|------|----------|--------------|
| baseline | Overhead figure/table | — | Public trace proven |
| auth_committed | Overhead + security | — | Production IAM |
| auth_slot_aligned | Optional overhead detail | Slot diagram | Public layout measured |
| auth_acl_class | Compression figure | N_acl table | Public ACL overlay proven |
| proof planning | Cost-model subfigures | SA/PA frontier | Measured gate savings |
| public-trace ZK | — | Phase 11 pilot only | Completed today |
