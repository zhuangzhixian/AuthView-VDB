# Phase 7A: Proof Overhead Figures and Table (RQ2)

**Phase:** 7A  
**RQ:** RQ2 — What is the overhead of proof-carrying authorization vs content-only V3DB-shaped baseline?  
**Status:** Export from existing CSV only; no new ZK runs

**Related:** [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md), [paper_figure_table_inventory.md](paper_figure_table_inventory.md)

---

## 1. Evaluation goal

Quantify measured ZK proof cost (gates, prove/verify time, proof size, memory) for AuthView proof paths relative to the **content-only baseline** (`baseline` = V3DB-shaped IVF-PQ proof without authorization view).

AuthView paths are **additive extensions** — not a V3DB plugin.

---

## 2. Input data

| File | Role |
|------|------|
| `artifacts/auth_zk_paper_ready_summary.csv` | Primary input (median, repeat=3) |
| `artifacts/auth_zk_paper_ready_metrics.csv` | Optional — median memory column |

### Summary CSV schema

| Column | Description |
|--------|-------------|
| `path` | Proof path identifier |
| `n_probe`, `slot_per_list`, `N_sel` | Workload shape |
| `median_gates` | Circuit gate count (median of 3 repeats) |
| `median_prove_time` | Prover time (seconds) |
| `median_verify_time` | Verifier time (seconds) |
| `median_proof_size` | Proof size (bytes) |
| `committed_vs_baseline_gates`, etc. | Precomputed ratios (some paths) |

**Paths in summary (no `auth_acl_class`):** `baseline`, `auth_all_visible`, `auth_policy`, `auth_committed`, `auth_slot_aligned`.

**Representative workload for figures/table:** `n_probe=4`, `slot_per_list=64`, `N_sel=256`.

---

## 3. Commands

```bash
PYTHONPATH=. python scripts/plot_proof_overhead_figures.py \
  --input artifacts/auth_zk_paper_ready_summary.csv \
  --output-dir artifacts/figures

PYTHONPATH=. python scripts/make_proof_overhead_table.py \
  --input artifacts/auth_zk_paper_ready_summary.csv \
  --output artifacts/tables/table_proof_overhead.tex

PYTHONPATH=. pytest tests/test_proof_overhead_outputs.py -v
```

Optional flags: `--n-probe`, `--slot-per-list`, `--no-size-figure`, `--no-metrics`.

---

## 4. Generated figures

| File | Role | Paper placement |
|------|------|-----------------|
| `artifacts/figures/main_proof_overhead_gates.pdf` | Normalized gates (baseline = 1.0) | **RQ2 main figure / subfigure** |
| `artifacts/figures/main_proof_overhead_time.pdf` | Median prove time (s) | RQ2 main or appendix |
| `artifacts/figures/main_proof_overhead_size.pdf` | Proof size (KB) | **Optional** — small cross-path variation |

Measurement type: **real ZK** (not cost model).

---

## 5. Generated table

| File | Role |
|------|------|
| `artifacts/tables/table_proof_overhead.tex` | LaTeX Table 2 — proof overhead |

Columns: Path, Gates, Prove (s), Verify (ms/s), Size (KB), Memory (MB), Gates OH, Prove OH.

---

## 6. Path label mapping

| CSV `path` | Figure label | Table label |
|------------|--------------|-------------|
| `baseline` | Content-only | Content-only |
| `auth_all_visible` | Auth-mask | Auth-mask |
| `auth_policy` | Policy | Policy |
| `auth_committed` | Committed | Committed-auth |
| `auth_slot_aligned` | Slot-aligned | Slot-aligned |
| `auth_acl_class` | ACL-class | ACL-class *(not in paper_ready summary)* |

---

## 7. Main observations (representative workload N_sel=256)

| Path | Norm. gates | vs baseline |
|------|-------------|-------------|
| Content-only | 1.00 | — |
| Auth-mask | ~1.00 | Mask gadget negligible at high visibility |
| Policy | ~1.09 | Policy evaluation overhead |
| Committed-auth | ~1.26 | Merkle + committed auth binding |
| Slot-aligned | ~0.97× committed gates | ~3% gate reduction vs committed |

- **Prove time** tracks gates roughly; slot-aligned slightly higher prove time than committed at some workloads despite fewer gates.
- **Verify time** ~5 ms — negligible vs prove time; reported in table only.
- **Proof size** ~140 KB — stable across paths (~±2%).

---

## 8. Limitations

1. **Synthetic fixed-shape workload** — 400 vectors, dim 64, 8 IVF lists; not public dataset (D1 later).
2. **No `auth_acl_class` in this summary** — ACL-class overhead uses separate `auth_zk_acl_class_summary.csv` (RQ3).
3. **No new proof runs** — figures/table from existing Phase 3D bench.
4. **No Rust/PyO3 changes** in Phase 7A.
5. Public dataset utility deferred to D1 phase.

---

## 9. Paper placement

| Artifact | Section |
|----------|---------|
| `main_proof_overhead_gates.pdf` | §5.3 RQ2 — primary overhead figure |
| `main_proof_overhead_time.pdf` | §5.3 RQ2 or appendix |
| `table_proof_overhead.tex` | Table 2 |
| Caption note | “Median of 3 repeats; synthetic fixed-shape IVF-PQ proof workload; content-only baseline is V3DB-shaped.” |

---

## 10. Claim boundaries

**Can claim:**

- Measured gate and latency overhead of committed auth paths vs content-only baseline on documented workload.

**Cannot claim:**

- Overhead on SIFT1M / production scale (not yet measured).
- ACL-class compression from this table (different CSV).
- Gate reduction from proof-planning cost model (Phase 6B).
