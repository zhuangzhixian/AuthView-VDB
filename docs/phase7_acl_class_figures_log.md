# Phase 7B: ACL-class Repeat=3 and RQ3 Figures

**Phase:** 7B  
**RQ:** RQ3 — How do authorization commitment layout and ACL-class compression affect proof cost?  
**Status:** repeat=3 benchmark + figure/table export

**Related:** [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md), [phase5_acl_class_eval_log.md](phase5_acl_class_eval_log.md)

---

## 1. RQ3 goal

Compare **object-level committed auth** (`auth_committed`) vs **ACL-class compression** (`auth_acl_class`) as `N_acl` sweeps from 1 to 64 at fixed `N_sel=256`.

Show that ACL-class wins when `N_acl ≪ N_sel` and degrades toward object-level cost as `N_acl → N_sel`.

---

## 2. Repeat=3 setting

| Parameter | Value |
|-----------|-------|
| repeat | **3** |
| num_vectors | 400 |
| dim | 64 |
| n_list | 8 |
| n_probe | 4 |
| slot_per_list | 64 |
| N_sel | 256 |
| top_k | 5 |
| N_acl sweep | 1, 2, 4, 8, 16, 32, 64 |
| seed | 42 (+ repeat offset) |

---

## 3. Commands

```bash
PYTHONPATH=. python scripts/bench_acl_class_paths.py \
  --repeat 3 \
  --metrics-out artifacts/auth_zk_acl_class_metrics_repeat3.csv

PYTHONPATH=. python scripts/summarize_acl_class_metrics.py \
  --input artifacts/auth_zk_acl_class_metrics_repeat3.csv \
  --summary-out artifacts/auth_zk_acl_class_summary_repeat3.csv

PYTHONPATH=. python scripts/plot_acl_class_figures.py \
  --input artifacts/auth_zk_acl_class_summary_repeat3.csv \
  --output-dir artifacts/figures

PYTHONPATH=. python scripts/make_acl_class_table.py \
  --input artifacts/auth_zk_acl_class_summary_repeat3.csv \
  --output artifacts/tables/table_acl_class_summary.tex

PYTHONPATH=. pytest tests/test_acl_class_outputs.py -v
```

---

## 4. Input / output CSV

| File | Role |
|------|------|
| `artifacts/auth_zk_acl_class_metrics_repeat3.csv` | Raw metrics (42 rows = 7 N_acl × 2 paths × 3 repeats) |
| `artifacts/auth_zk_acl_class_summary_repeat3.csv` | Median summary (14 rows = 7 N_acl × 2 paths) |

Prior repeat=1 data remains in `auth_zk_acl_class_*.csv` unchanged.

---

## 5. Generated figures / tables

| Artifact | Role |
|----------|------|
| `artifacts/figures/main_acl_class_compression.pdf` | **RQ3 main figure** — gates ratio vs N_acl |
| `artifacts/figures/main_acl_class_prove_time.pdf` | Optional — prove time ratio |
| `artifacts/tables/table_acl_class_summary.tex` | RQ3 supporting table |

Measurement type: **real ZK** (not cost model).

---

## 6. Main observations (repeat=3, N_sel=256)

| N_acl | Gates ratio | Prove ratio | Trend |
|-------|-------------|-------------|-------|
| 1 | 0.94 | 0.97 | Strong sharing — single policy row |
| 2 | 0.95 | 1.01 | Strong sharing |
| 4 | 0.97 | 0.99 | Moderate — near break-even |
| 8 | 1.00 | 1.02 | Moderate |
| 16 | 1.07 | 1.03 | Weak sharing |
| 32 | 1.20 | 1.06 | Weak sharing |
| 64 | 1.47 | 1.83 | Degenerate — ACL-class loses |

- **Prove time** follows gates loosely but with higher variance at large N_acl.
- **Verify time** ~5 ms — stable.
- **Proof size** ~140 KB — small variation across N_acl.

---

## 7. Limitations

1. Synthetic fixed-shape proof workload (400×64, 8 lists) — not public dataset.
2. ACL-class helps only when **N_acl ≪ N_sel** with shared policy rows.
3. Degenerate one-class-per-object (`N_acl → N_valid`) is not beneficial.
4. `N_acl_max = N_acl` (tight table); production fixed-capacity tables may differ.
5. No Rust/PyO3/ACL gadget changes in Phase 7B.

---

## 8. Paper placement

| Artifact | Section |
|----------|---------|
| `main_acl_class_compression.pdf` | §5.4 RQ3 — main figure |
| `table_acl_class_summary.tex` | Table 3 or appendix |
| Caption | Median of 3 repeats; committed-auth = 1.0 baseline |

---

## 9. Interpretation mapping (table)

| Gates ratio | Label |
|-------------|-------|
| < 0.95 | strong sharing |
| 0.95–1.05 | moderate sharing |
| 1.05–1.20 | weak sharing |
| > 1.20 | degenerate / near object-level |
