# Evaluation Plan — Paper Tables and Figures

**Phase:** 4A planning (maps existing CSV and tests to paper RQs).  
**Data source of record:** `artifacts/auth_zk_paper_ready_summary.csv` (median, repeat=3) and `artifacts/auth_zk_paper_ready_metrics.csv` (raw).

No new experiments required for this document.

---

## 1. Research question organization

### RQ1 — Correctness and security tests

**Question:** Does the implementation enforce authorized masked top-k semantics and reject known attacks?

| Evidence | Source |
|----------|--------|
| Plaintext oracle vs adapter | `tests/test_auth_reference.py`, `tests/test_v3db_adapter.py` |
| Partial-visible ZK vs oracle | `tests/test_auth_zk_partial_visible.py` |
| Committed path positive/negative | `tests/test_auth_zk_committed.py` |
| Slot-aligned path + list_id graft | `tests/test_auth_zk_slot_aligned.py` |
| Auth Merkle plaintext | `tests/test_auth_commitment.py`, `tests/test_auth_slot_aligned_commitment.py` |
| All-visible regression | `tests/test_auth_zk_all_visible.py` |

**Paper placement:** §Evaluation "Correctness" + optional Appendix test matrix.

**Suggested Table RQ1-A — Security test coverage**

| Attack / property | Plaintext | ZK API |
|-------------------|-----------|--------|
| Compliant authorized top-k | ✓ reference | ✓ partial/all visible |
| Skipped candidate (coverage) | ✓ | (inherited V3DB circuit) |
| Forged label / tenant | ✓ | ✓ committed + slot-aligned |
| Visibility manipulation | ✓ | ✓ policy path |
| Post-filter missing neighbor | ✓ | ✓ partial-visible oracle match |
| Wrong Merkle path | ✓ | ✓ committed + slot-aligned |
| Cross-list top-path graft | ✓ plaintext | ✓ slot-aligned ZK |

---

### RQ2 — Overhead of authorization-aware proof paths

**Question:** What is the gate and latency overhead of auth paths vs V3DB baseline?

| Evidence | Source |
|----------|--------|
| Paper-ready medians | `artifacts/auth_zk_paper_ready_summary.csv` |
| Raw repeats | `artifacts/auth_zk_paper_ready_metrics.csv` |
| Light snapshot | `artifacts/auth_zk_slot_aligned_metrics.csv` |
| Phase 2D snapshot | `artifacts/auth_zk_path_metrics.csv` |

**Paper placement:** §Evaluation "Overhead" — **main text Table 1**.

**Suggested Table 1 — Median proof cost by path (one representative workload)**

Pick one row from summary, e.g. `n_probe=4`, `slot_per_list=64`, `N_sel=256`:

| Path | median_gates | median_prove_time | vs baseline gates |
|------|--------------|-------------------|-------------------|
| baseline | from `path=baseline` | … | 1.00 |
| auth_all_visible | … | … | ~1.00 |
| auth_policy | … | … | ~1.08 |
| auth_committed | … | … | ~1.26 |
| auth_slot_aligned | … | … | ~1.22 |

Columns from summary CSV: `median_gates`, `median_prove_time`, `median_proof_size`, `policy_vs_baseline_gates`, `committed_vs_baseline_gates`.

**Suggested Figure 1 — Overhead breakdown (stacked or grouped bar)**

X = path; Y = median_gates; one bar group per workload or single representative workload.

---

### RQ3 — Scaling behavior

**Question:** How does cost grow with \(N_{sel}\), `n_probe`, and slot capacity?

| Evidence | Source |
|----------|--------|
| Full 6-workload grid | `artifacts/auth_zk_paper_ready_summary.csv` |
| Phase 2E grid | `artifacts/auth_zk_scaling_metrics.csv` |
| `N_sel`, `auth_tree_depth` columns | raw metrics CSV |

**Paper placement:** §Evaluation "Scaling" — **main text Figure 2**.

**Suggested Figure 2 — Gates vs \(N_{sel}\)**

- X-axis: `N_sel` ∈ {64, 128, 256, 512} from summary rows
- Y-axis: `median_gates`
- Lines/series: `baseline`, `auth_committed` (primary); `auth_policy` optional
- Annotate `auth_tree_depth` for committed path (global depth)

**Suggested Table 2 — Scaling grid (committed vs baseline)**

All six workloads; columns: `n_probe`, `slot_per_list`, `N_sel`, `median_gates` (baseline, committed), `committed_vs_baseline_gates`.

Filter summary CSV: `path in {baseline, auth_committed}`; pivot or join on workload keys.

---

### RQ4 — Commitment layout comparison (secondary)

**Question:** Does slot-aligned auth Merkle layout reduce cost vs global flat committed tree?

| Evidence | Source |
|----------|--------|
| Slot vs committed ratios | `artifacts/auth_zk_paper_ready_summary.csv` (`slot_vs_committed_gates`, `slot_vs_committed_prove_time`) |
| Plaintext opening cost model | `tests/test_auth_slot_aligned_commitment.py` (`estimate_*_opening_cost`) |
| Equivalence test | `tests/test_auth_zk_slot_aligned.py::test_auth_zk_global_vs_slot_aligned_equivalence` |

**Paper placement:** §Evaluation subsection or **Appendix** — not a primary claim.

**Suggested Table 3 — Layout comparison (appendix-friendly)**

| n_probe | slot | N_sel | median committed gates | median slot gates | slot_vs_committed_gates | slot_vs_committed_prove_time |
|---------|------|-------|------------------------|-------------------|-------------------------|------------------------------|

All rows from summary where `path=auth_slot_aligned` (ratio columns populated).

**Observed trend (repeat=3, seed=42):** slot_vs_committed_gates ∈ [0.953, 0.992] — **2–5% gate reduction**; largest at `N_sel=512`.

**Important caveat for text:** global committed baseline in benchmark is a **probe-local flat tree** over selected slots; slot-aligned savings are a **conservative** estimate vs a full index-wide auth tree.

---

## 2. CSV → paper mapping cheat sheet

| Paper artifact | CSV / test | Key columns |
|--------------|------------|-------------|
| Table 1 (overhead) | `auth_zk_paper_ready_summary.csv` | `median_gates`, `median_prove_time`, `*_vs_baseline_gates` |
| Table 2 (scaling) | same | workload keys + `N_sel`, pivot by `path` |
| Table 3 (layout) | same | `slot_vs_committed_*` on `auth_slot_aligned` rows |
| Figure 2 (scaling curve) | same | `N_sel` vs `median_gates`, series=`path` |
| Test coverage table | `tests/test_auth_*.py` | pytest names from phase logs |
| V3DB baseline anchor | `artifacts/v3db_reproduce_metrics.csv` | optional intro baseline |

### Summary CSV schema (for reproducibility)

```
num_vectors, dim, n_list, n_probe, slot_per_list, top_k, N_sel, visible_ratio,
auth_tree_depth, path, n_repeats, median_gates, median_prove_time,
median_verify_time, median_proof_size, median_build_time,
policy_vs_baseline_gates, committed_vs_baseline_gates,
slot_vs_committed_gates, slot_vs_committed_prove_time
```

### Raw metrics schema (unchanged, 16 columns)

Used for repeat dispersion analysis if needed; paper main text should prefer **summary medians**.

---

## 3. Main text vs appendix vs artifact-only

| Content | Placement |
|---------|-----------|
| RQ1 test matrix (short) | Main text §Evaluation |
| Table 1 overhead (one workload) | Main text |
| Figure 2 scaling (committed vs baseline) | Main text |
| Full 6×5 median grid | Appendix Table A.1 |
| Slot-aligned layout (Table 3) | Appendix or short §5.4 |
| Raw 90-row metrics + repeat variance | Artifact / supplementary CSV |
| `auth_zk_path_metrics.csv`, `auth_zk_scaling_metrics.csv` | Cite as earlier phases; superseded by paper-ready for final numbers |
| Witness layout byte sizes | Appendix implementation |
| Rust gadget unit test counts | Appendix |
| `plaintext_attack_cases.json` | Artifact (attack fixtures) |
| Memory column (`memory` in raw CSV) | Appendix only (environment-dependent) |
| build_time | Appendix (implementation noise) |

---

## 4. Current experimental limitations (state in paper)

1. **Synthetic workload only** — 400 vectors, dim 64, 8 IVF lists; random integers, not SIFT/GIST.
2. **Single machine, 3 repeats** — report medians; no confidence intervals in current CSV.
3. **Public user context** — \(\gamma_U\) not hidden.
4. **Simplified policy** — tenant, project set, clearance, epoch, active state.
5. **Global committed baseline scope** — flat tree over probed slots, not entire corpus auth state.
6. **Slot-aligned wire duplication** — shared top paths expanded per probe row in PyO3 input.
7. **ANN recall** — fixed \(n_{probe}\) and slot capacity; inherited V3DB limitation.
8. **No end-to-end networked verifier** — local prove/verify timing only.

---

## 5. Recommended paper-ready run (future, beyond 4A)

Already completed for Phase 3D:

```bash
python scripts/bench_auth_paths.py \
  --repeat 3 \
  --n-probe-list 2,4 \
  --slot-per-list-list 32,64,128 \
  --top-k-list 5 \
  --output artifacts/auth_zk_paper_ready_metrics.csv

python scripts/summarize_auth_metrics.py \
  --input artifacts/auth_zk_paper_ready_metrics.csv \
  --output artifacts/auth_zk_paper_ready_summary.csv
```

**Extensions for camera-ready:**

| Extension | Purpose |
|-----------|---------|
| `repeat=5` or `10` | Confidence intervals |
| SIFT1M 10k–100k subset | Real embedding distribution |
| Fixed public snapshot hash | Reproducible `root_content`, `root_auth` |
| Index-wide global auth tree baseline | Fairer RQ4 comparison |
| Separate timing table: prove vs verify | Verifier cost emphasis |

---

## 6. Figure sketch (scaling)

```
median_gates
    ^
    |                                    * auth_committed
    |                               *
    |                          *
    |                     *
    |                * baseline
    +----+----+----+----+----+----> N_sel
        64  128  256  384  512
```

Use six summary workloads; connect points with same `n_probe` style (solid vs dashed) if showing both probe counts.

---

## 7. Scripts reference

| Script | Role |
|--------|------|
| `scripts/bench_auth_paths.py` | Generate raw metrics CSV (5 paths) |
| `scripts/summarize_auth_metrics.py` | Aggregate medians and ratios |

Tests validating pipeline: `tests/test_auth_overhead_script.py`, `tests/test_auth_metrics_summary.py`.
