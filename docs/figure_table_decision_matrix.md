# Figure and Table Decision Matrix

**Phase:** 9C  
**Purpose:** Per-artifact placement, readiness, and action checklist  
**Generated inventory:** `artifacts/evaluation_inventory/figure_table_inventory.csv`  
**Companion:** [paper_figure_table_inventory.md](paper_figure_table_inventory.md) (Phase 6C blueprint — superseded for placement by this audit where updated)

Legend — **recommended_placement:**

| Value | Meaning |
|-------|---------|
| `main_paper` | Target main text |
| `appendix` | Appendix or supplementary |
| `internal_only` | Do not submit; exploratory or superseded |

Legend — **readiness:** `ready` · `partial` · `missing`

---

## Main paper — figures

| artifact_path | phase | title / purpose | placement | claim | readiness | caveat | action_needed |
|---------------|-------|-----------------|-----------|-------|-----------|--------|---------------|
| `artifacts/figures/main_public_utility_recall.pdf` | 8C | Public IVF-PQ R@1/10/100 | main_paper | C2 | ready | Unrestricted only | Caption: full 1M base, SIFT 10k / GIST 1k queries |
| `artifacts/figures/main_auth_overlay_utility_gap.pdf` | 9A | Utility gap vs selectivity @k=10 | main_paper | C1,C2 | ready | candidate_level | Caption: trace prefix depth 100 |
| `artifacts/figures/main_auth_overlay_underfill.pdf` | 9A | Underfill vs selectivity | main_paper | C1 | ready | candidate_level | Pair with utility gap |
| `artifacts/figures/main_proof_overhead_gates.pdf` | 7A | ZK gates by path | main_paper | C4 | ready | Controlled proof workloads | Label V3DB-shaped baseline |
| `artifacts/figures/main_proof_overhead_time.pdf` | 7A | Prove/verify time | main_paper | C4 | ready | Controlled proof workloads | Same as gates |
| `artifacts/figures/main_acl_class_compression.pdf` | 7B | ACL-class gate compression | main_paper | C4 | partial | Check repeat=3 | Confirm CSV repeat in caption |
| `artifacts/figures/main_merged_k_knob.pdf` | 6 | Merged-k SA/PA knob | main_paper | C4 | ready | **Cost model only** | Mandatory disclaimer |
| `artifacts/figures/main_cost_breakdown_clean.pdf` | 6 | Cost component breakdown | main_paper | C4 | ready | **Cost model only** | Mandatory disclaimer |

---

## Appendix — figures

| artifact_path | phase | title / purpose | placement | claim | readiness | caveat | action_needed |
|---------------|-------|-----------------|-----------|-------|-----------|--------|---------------|
| `artifacts/figures/main_authorized_reference_calibration.pdf` | 9B | Candidate vs full recall gap | appendix | C3 | ready | Stratified calibration query set; full 1M base | Say query-calibrated, full_base on corpus |
| `artifacts/figures/main_proof_overhead_size.pdf` | 7A | Proof size | appendix | C4 | ready | Controlled proof workloads | Optional main if space |
| `artifacts/figures/main_acl_class_prove_time.pdf` | 7B | ACL prove time | appendix | C4 | partial | repeat caveat | Pair with compression |
| `artifacts/figures/main_proof_scaling_gates.pdf` | 7C | Scaling gates vs N_sel | appendix | C4 | ready | Parameterized proof grid | Cross-ref scaling table |
| `artifacts/figures/main_proof_scaling_time.pdf` | 7C | Scaling time | appendix | C4 | ready | Parameterized proof grid | Optional |
| `artifacts/figures/main_impure_fallback_clean.pdf` | 6 | Impure fallback PA | appendix | C4 | ready | Cost model | Subfigure of RQ4 |

---

## Internal only — figures

| artifact_path | phase | title / purpose | placement | claim | readiness | caveat | action_needed |
|---------------|-------|-----------------|-----------|-------|-----------|--------|---------------|
| `artifacts/figures/main_sa_pa_frontier_clean.pdf` | 6 | SA/PA frontier | internal_only | C4 | ready | Oracle off-scale | Do not use in main |
| `artifacts/figures/archive/*` | various | Superseded exports | internal_only | — | — | Deprecated per Phase 6 log | Do not submit |

---

## Main paper — tables

| artifact_path | phase | title / purpose | placement | claim | readiness | caveat | action_needed |
|---------------|-------|-----------------|-----------|-------|-----------|--------|---------------|
| `artifacts/tables/table_public_utility_summary.tex` | 8C | Public utility summary | main_paper | C2 | ready | full_base=true | Dataset setup / RQ1 |
| `artifacts/tables/table_auth_overlay_summary.tex` | 9A | Auth overlay R@10 | main_paper | C1,C2 | ready | candidate_level | Scope in caption |
| `artifacts/tables/table_proof_overhead.tex` | 7A | Proof overhead medians | main_paper | C4 | ready | Controlled proof workloads | Table 2 equivalent |
| `artifacts/tables/table_acl_class_summary.tex` | 7B | ACL-class ablation | main_paper | C4 | partial | repeat check | Table 4 equivalent |

---

## Appendix — tables

| artifact_path | phase | title / purpose | placement | claim | readiness | caveat | action_needed |
|---------------|-------|-----------------|-----------|-------|-----------|--------|---------------|
| `artifacts/tables/table_authorized_reference_calibration.tex` | 9B | Full-base calibration | appendix | C3 | ready | Stratified calibration query set; full 1M base | Distinguish query calibration from base truncation |
| `artifacts/tables/table_proof_scaling_summary.tex` | 7C | N_sel scaling | appendix | C4 | ready | Parameterized proof grid | Appendix scaling |

---

## Result CSV inventory

| artifact_path | phase | reference_scope | full_base | rows | role |
|---------------|-------|-----------------|-----------|------|------|
| `artifacts/public_utility/sift_gist_utility_summary.csv` | 8C | unrestricted_baseline | true | 4 | Public utility anchor |
| `artifacts/auth_overlay/public_trace_auth_summary.csv` | 9A | candidate_level | trace_on_full_base | 144 | Full-trace auth semantics |
| `artifacts/auth_calibration/full_authorized_reference_summary.csv` | 9B | full_base_calibration | true | 144 | Query-calibrated exact reference |

See `artifacts/evaluation_inventory/result_summary_inventory.csv` for live row counts and metric summaries.

---

## Missing P0 items (blueprint gap)

| Item | Type | Priority | Notes |
|------|------|----------|-------|
| System architecture / workflow | Figure | P0 | Design — not code |
| Authorized semantics diagram | Figure | P0 | Design |
| Attack matrix LaTeX table | Table | P0 | CSV exists; format for paper |
| MS MARCO utility | CSV/Figure | P1 | Phase 8D planned |

---

## Placement summary counts (current artifacts)

| Placement | Figures | Tables |
|-----------|---------|--------|
| main_paper | 8 | 4 |
| appendix | 6 | 2 |
| internal_only | 1+ | 0 |

---

## Review checklist before submission

- [ ] Every figure caption states ZK / REF / COST / candidate_level / full_base_calibration
- [ ] Phase 6 figures include cost-model disclaimer
- [ ] Phase 9A never labeled as full-database authorized ANN
- [ ] Phase 9B labeled as query calibration on full 1M base
- [ ] zk-opt described as proof-aware, not as an intentionally degraded baseline
- [ ] V3DB baseline labeled content-only lower bound
- [ ] ACL-class repeat=3 verified in source CSV

---

## Regenerate inventory

```bash
PYTHONPATH=. .venv/bin/python scripts/build_evaluation_inventory.py \
  --output-dir artifacts/evaluation_inventory
```
