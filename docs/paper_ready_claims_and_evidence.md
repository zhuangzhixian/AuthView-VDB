# Paper-Ready Claims and Evidence Map

**Phase:** 9C  
**Purpose:** Map research claims to experiments, figures, metrics, caveats, and reviewer risks  
**Companion:** [phase9c_evaluation_consolidation.md](phase9c_evaluation_consolidation.md)

---

## Claim 1

**Authorization constraints alter retrieval semantics and cannot be handled by naive post-filtering.**

### Supporting experiments

- Phase 9A authorization overlay on Phase 8C public traces
- Phase 1B controlled contrast fixture (`tests/test_auth_reference.py::test_post_filter_missing_authorized_neighbor`)
- Phase 9B calibration (post-filter vs full authorized on visible 1M base)

### Figures

| Artifact | Placement |
|----------|-----------|
| `main_auth_overlay_utility_gap.pdf` | Main |
| `main_auth_overlay_underfill.pdf` | Main |
| `main_authorized_reference_calibration.pdf` | Appendix |

### Tables

| Artifact | Placement |
|----------|-----------|
| `table_auth_overlay_summary.tex` | Main |
| `table_authorized_reference_calibration.tex` | Appendix |

### Key metrics

- `utility_gap` = authorized − post_filter recall (Phase 9A, **candidate_level**)
- `underfill_rate` at k=10,100 (Phase 9A: ~100% at sel=0.1 @k=10)
- `violation_rate` = 0 (post-filter correctly excludes invisible when implemented)
- `post_full_recall_gap` (Phase 9B: post-filter vs full-base authorized)

### Caveats

- Phase 9A authorized reference is **candidate_level** (pred depth 100), not full-database ANN.
- **Generated ACL overlays** / controlled authorization overlays, not enterprise IAM.
- Post-filter “failure” includes underfill, not authorization bypass (violations are zero by construction).

### Paper wording suggestion

> Under visibility constraints, naive post-filtering of unrestricted top-k results yields systematic underfill and lower recall than authorized-view reference semantics. At selectivity 0.1 and k=10 on full SIFT1M/GIST1M query sets, post-filter recall drops to 2.5–7.3% vs 8.4–9.2% for candidate-level authorized reference, with near-complete underfill.

### Reviewer risk

| Risk | Mitigation |
|------|------------|
| “Post-filter is a strawman” | Cite as common deployment pattern; show underfill + recall gap on **full public query sets** |
| “Authorized reference is approximate” | Phase 9B **full_base_calibration** bounds gap; explicit `reference_scope` labels |
| “Overlays are not production IAM” | Acknowledge; position as controlled sensitivity analysis over generated ACL overlays |

---

## Claim 2

**Authorized-view evaluation introduces measurable utility differences under public ANN benchmark traces.**

### Supporting experiments

- Phase 8C unrestricted public utility baseline (SIFT1M/GIST1M, full 1M)
- Phase 9A full-trace overlay (10k / 1k queries × 3 policies × 4 selectivities)

### Figures

| Artifact | Placement |
|----------|-----------|
| `main_public_utility_recall.pdf` | Main |
| `main_auth_overlay_utility_gap.pdf` | Main |

### Tables

| Artifact | Placement |
|----------|-----------|
| `table_public_utility_summary.tex` | Main |
| `table_auth_overlay_summary.tex` | Main |

### Key metrics

- Phase 8C unrestricted: SIFT R@10 0.749 (high-acc), 0.668 (zk-opt); GIST R@10 0.241 / 0.211
- Phase 9A at sel=0.5, k=10: post-filter R@10 ~0.33–0.37 (SIFT zk-opt) vs unrestricted 0.668
- `affected_query_rate` up to ~100% at low k / low selectivity

### Caveats

- Utility measured on **plaintext reference / trace replay**, not ZK prover path latency.
- GIST1M has 1k queries (benchmark standard).
- No MS MARCO in current evidence.

### Paper wording suggestion

> On full SIFT1M and GIST1M corpora, authorization overlays induce substantial utility separation between unrestricted IVF-PQ, post-filtering, and authorized-view reference semantics, with effects intensifying at lower selectivity.

### Reviewer risk

| Risk | Mitigation |
|------|------------|
| “Only two datasets” | Standard ANN benchmarks + blueprint for MS MARCO |
| “No ZK utility” | Separate RQ2; RQ1 is reference correctness/utility |
| “zk-opt looks weak” | Explain proof-aware config; pair with high-acc |

---

## Claim 3

**Candidate-level authorization overlay captures broad trends, while full-base calibration quantifies approximation boundaries.**

### Supporting experiments

- Phase 9A: `reference_scope=candidate_level`, 144 summary rows, full query sets
- Phase 9B: `reference_scope=full_base_calibration`, exact L2 on visible 1M subset, ~572 calibrated queries

### Figures

| Artifact | Placement |
|----------|-----------|
| `main_auth_overlay_utility_gap.pdf` | Main (trends) |
| `main_authorized_reference_calibration.pdf` | Appendix (boundary) |

### Tables

| Artifact | Placement |
|----------|-----------|
| `table_auth_overlay_summary.tex` | Main |
| `table_authorized_reference_calibration.tex` | Appendix |

### Key metrics

- Phase 9A: `utility_gap` at k=10 up to ~0.05 (SIFT), ~0.04 (GIST)
- Phase 9B: `candidate_full_recall_gap` (often ≤ 0 — candidate underestimates full)
- Phase 9B: `candidate_vs_full_overlap` at k=10
- Phase 9A at k=100, low sel: gap → 0 (prefix-limited visible set)

### Caveats

- Phase 9B aggregates ~10–15 queries per summary cell (**stratified calibration query set**), not all 11k queries.
- Full authorized reference uses **exact L2**, not IVF-PQ approximate search on authorized view.
- Calibration validates **reference semantics**, not index build cost.

### Paper wording suggestion

> Full-corpus trace overlays (candidate_level) expose consistent post-filter vs authorized-view trends across selectivities and policies. Query-calibrated exact search over the full 1M visible subset (full_base_calibration) quantifies when the top-100 trace prefix suffices and when full authorized neighbors lie deeper in the authorized view.

### Reviewer risk

| Risk | Mitigation |
|------|------------|
| “9A pretends to be full reference” | Mandatory scope labels; 9B dedicated section |
| “9B too small” | Stratified calibration query set; report n per cell; full 1M base unchanged |
| “Exact L2 ≠ IVF-PQ authorized” | State as semantic oracle; IVF-PQ authorized search is future work |

---

## Claim 4

**Proof planning and ACL-aware optimization provide a feasible path toward proof-carrying authorized retrieval.**

### Supporting experiments

- Phase 6 proof-planning cost model (merged-k, purity, grouping)
- Phase 7A measured ZK overhead (5 paths, repeat=3)
- Phase 7B ACL-class compression vs N_acl
- Phase 7C proof scaling vs N_sel
- Attack matrix tests + CSV

### Figures

| Artifact | Placement |
|----------|-----------|
| `main_proof_overhead_gates.pdf`, `main_proof_overhead_time.pdf` | Main |
| `main_acl_class_compression.pdf` | Main |
| `main_merged_k_knob.pdf`, `main_cost_breakdown_clean.pdf` | Main |
| `main_proof_scaling_*.pdf`, `main_impure_fallback_clean.pdf` | Appendix |

### Tables

| Artifact | Placement |
|----------|-----------|
| `table_proof_overhead.tex` | Main |
| `table_acl_class_summary.tex` | Main |
| `table_proof_scaling_summary.tex` | Appendix |

### Key metrics

- `median_gates`, `median_prove_time`, `median_verify_time`, `median_proof_size` by path
- ACL-class vs committed gate ratios at N_acl ≪ N_sel
- Proof-planning cost model ratios (Phase 6 — **not ZK measured**)

### Caveats

- Phase 6/7 proof workloads are **parameterized proof workload grids** on **controlled proof workloads** — used for overhead-trend measurement, not public 1M utility benchmarks and not claimed as substitutes for them.
- ACL-class repeat count: verify repeat=3 in final CSV before camera-ready.
- Proof planning ≠ implemented circuit optimization.

### Paper wording suggestion

> Measured ZK overhead shows authorization-aware proof paths remain feasible relative to a V3DB-shaped content-only baseline, with ACL-class compression reducing commitment scope when N_acl ≪ N_sel. Complementary proof-planning analysis (plaintext cost model) identifies merged-k and purity-aware grouping as design levers for future circuit specialization.

### Reviewer risk

| Risk | Mitigation |
|------|------------|
| “Cost model ≠ real gates” | Separate captions; Phase 7 measured ZK for overhead claims |
| “No end-to-end public ZK” | Acknowledge; propose 9B stratified calibration query set for ZK pilot |
| “V3DB comparison unfair” | Label baseline as content-only lower bound |

---

## Cross-claim evidence matrix

| Evidence module | C1 | C2 | C3 | C4 |
|-----------------|:--:|:--:|:--:|:--:|
| Phase 8C public utility | | ✓ | | |
| Phase 9A auth overlay | ✓ | ✓ | ✓ | |
| Phase 9B calibration | ✓ | | ✓ | |
| Phase 6 proof planning | | | | ✓ |
| Phase 7 ZK overhead | | | | ✓ |
| Attack matrix | ✓ | | | ✓ |

---

## Inventory reference

Auto-generated: `artifacts/evaluation_inventory/figure_table_inventory.csv`, `result_summary_inventory.csv`.
