# Phase 7C: Proof Scaling Figures and Table (RQ6)

**Phase:** 7C  
**RQ:** RQ6 — How does proof cost scale with configuration (N_sel, n_probe, slot capacity)?  
**Status:** Export from existing paper-ready summary CSV only

**Related:** [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md), [phase7_proof_overhead_figures_log.md](phase7_proof_overhead_figures_log.md)

---

## 1. RQ6 goal

Show that ZK proof cost (gates, prove time) grows with candidate set size `N_sel = n_probe × slot_per_list`, and compare scaling trends across proof paths on the **same synthetic fixed-shape workload grid**.

---

## 2. Input CSV and workloads

| File | Role |
|------|------|
| `artifacts/auth_zk_paper_ready_summary.csv` | Primary (30 rows = 6 workloads × 5 paths, repeat=3 median) |
| `artifacts/auth_zk_paper_ready_metrics.csv` | Raw repeats (optional; not used in Phase 7C export) |

### Workload grid (6 configurations)

| n_probe | slot_per_list | N_sel |
|---------|---------------|-------|
| 2 | 32 | 64 |
| 2 | 64 | 128 |
| 2 | 128 | 256 |
| 4 | 32 | 128 |
| 4 | 64 | 256 |
| 4 | 128 | 512 |

**Paths:** baseline, auth_all_visible, auth_policy, auth_committed, auth_slot_aligned

**Aggregation for figures:** At each `(path, N_sel)`, median across workloads that share the same N_sel (e.g. N_sel=128 merges n_probe=2/4 workloads).

---

## 3. Commands

```bash
PYTHONPATH=. python scripts/plot_proof_scaling_figures.py \
  --input artifacts/auth_zk_paper_ready_summary.csv \
  --output-dir artifacts/figures

PYTHONPATH=. python scripts/make_proof_scaling_table.py \
  --input artifacts/auth_zk_paper_ready_summary.csv \
  --output artifacts/tables/table_proof_scaling_summary.tex

PYTHONPATH=. pytest tests/test_proof_scaling_outputs.py -v
```

---

## 4. Generated figures / tables

| Artifact | Role |
|----------|------|
| `artifacts/figures/main_proof_scaling_gates.pdf` | **RQ6 main/appendix** — median gates vs N_sel |
| `artifacts/figures/main_proof_scaling_time.pdf` | Optional — prove time vs N_sel |
| `artifacts/tables/table_proof_scaling_summary.tex` | Appendix — min/max N_sel growth ratios |

Measurement type: **real ZK** (not cost model).

---

## 5. Main observations (N_sel 64 → 512)

| Path | Gates@64 | Gates@512 | Gate growth | Trend |
|------|----------|-----------|-------------|-------|
| Content-only | ~10,032 | ~20,432 | ~2.04× | Near-linear baseline scaling |
| Policy | ~10,442 | ~23,708 | ~2.27× | Slightly super-linear |
| Committed-auth | ~11,062 | ~30,902 | ~2.79× | Steeper — auth Merkle + binding |
| Slot-aligned | ~10,979 | ~29,437 | ~2.68× | Similar to committed, ~3% lower at large N_sel |
| Auth-mask | ~10,039 | ~20,483 | ~2.04× | Tracks baseline |

- **Committed-auth** shows the steepest gate growth (largest absolute overhead at N_sel=512).
- **Prove time** scaling is noisier (n_probe=4 jumps at N_sel=128) — treat time figure as optional/appendix.
- **Verify time** stable ~5 ms across grid (see RQ2 table).

---

## 6. Limitations

1. Synthetic fixed-shape proof workload (400×64, 8 lists) — not public dataset.
2. N_sel=128 and N_sel=256 each appear from two workload configs; figures aggregate by median.
3. No new proof runs; no Rust/PyO3 changes.
4. Does not include ACL-class path (separate RQ3 sweep).

---

## 7. Paper placement

| Artifact | Section |
|----------|---------|
| `main_proof_scaling_gates.pdf` | §5.7 RQ6 — main or appendix scaling figure |
| `main_proof_scaling_time.pdf` | Appendix (optional) |
| `table_proof_scaling_summary.tex` | Appendix supporting table |

Caption note: *Median of 3 repeats; six workload configurations; N_sel = n_probe × slot_per_list.*

---

## 8. Claim boundaries

**Can claim:** Measured gate/prove scaling trends vs N_sel on documented synthetic grid.

**Cannot claim:** Production-scale or public-dataset scaling; linear asymptotic bounds without further analysis.
