# Phase 8C: Public Utility Baseline Log

**Phase:** 8C (sanity audit + finalization)  
**RQ:** RQ1 — retrieval utility on public benchmarks  
**Scope:** SIFT1M + GIST1M **full** public benchmark plaintext IVF-PQ utility (V3DB-aligned)

**Companion:** [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md), [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md), [phase8_sift_gist_acquisition.md](phase8_sift_gist_acquisition.md)

---

## 1. RQ1 goal

Establish a **V3DB-comparable IVF-PQ utility baseline** on standard ANN public datasets before authorization overlays (later phase) and MS MARCO (Phase 8D).

Paper-facing metrics use the **standard (plaintext float ADC)** IVF-PQ path. ZK-shaped metrics are recorded in `sift_gist_utility_metrics.csv` for V3DB comparison only — **no ZK proofs were run in this phase**.

---

## 2. Full public benchmark confirmation

This phase uses the **complete** SIFT1M and GIST1M public releases — not toy subsets or truncated databases.

| Dataset | num_base | num_queries | dim | full_base |
|---------|----------|-------------|-----|-----------|
| SIFT1M | **1,000,000** | **10,000** | **128** | **true** |
| GIST1M | **1,000,000** | **1,000** | **960** | **true** |

Loader paths: `data/sift` → `public/sift1m`, `data/gist` → `public/gist1m`.

The summary CSV column `full_base=true` confirms all four configs ran against the expected full corpus sizes.

---

## 3. Parameter semantics (important)

### 3.1 `scale_n=65536`

`scale_n` is the **ZK-friendly rescale bound** inherited from V3DB `acc_bench` (integer quantization range for the ZK-shaped path). It is **not** a database size limit, query cap, or vector truncation parameter. The full 1M base vectors are loaded and indexed.

### 3.2 FAISS/PQ training subset sampling

Log lines such as:

```text
Sampling a subset of 65536 / 1000000 for training
```

refer to **PQ codebook training sampling** inside FAISS/IVF-PQ — a standard training-time subsample for k-means on product-quantizer subspaces. This does **not** mean the indexed database contains only 65,536 vectors. All 1M base vectors participate in IVF assignment and retrieval.

---

## 4. V3DB-aligned configurations

Common: `M=8`, `K=256`, `top_k=100`, `scale_n=65536`, `layout=none`, `report_ks=1,10,100`.

| Dataset | Config | n_list | n_probe | cluster_bound |
|---------|--------|--------|---------|---------------|
| SIFT1M | high-acc | 8192 | 64 | 256 |
| SIFT1M | zk-opt | 1024 | 8 | 2048 |
| GIST1M | high-acc | 8192 | 64 | 256 |
| GIST1M | zk-opt | 512 | 4 | 4096 |

**Pipeline:** `bench.acc_bench.run_accuracy_bench` via `scripts/run_public_utility_baseline.py` (same core as `tests/acc_bench.py` / `scripts/acc_bench.sh`).

---

## 5. Results (standard IVF-PQ path, full data)

| Dataset | Config | R@1 | R@10 | R@100 | Build (s) | Query (s) | QPS |
|---------|--------|-----|------|-------|-----------|-----------|-----|
| SIFT1M | high-acc | 0.3217 | 0.7487 | 0.9581 | 98.9 | 37.2 | 268.9 |
| SIFT1M | zk-opt | 0.2816 | 0.6702 | 0.8713 | 7.0 | 25.3 | 395.4 |
| GIST1M | high-acc | 0.0840 | 0.2410 | 0.5520 | 247.9 | 13.9 | 72.0 |
| GIST1M | zk-opt | 0.0800 | 0.2110 | 0.4380 | 18.9 | 9.0 | 110.9 |

Recall uses V3DB legacy hit-style semantics: R@k = 1 iff the rank-1 GT neighbor appears in pred[:k].

### 5.1 Observations

1. **high-acc > zk-opt** at all reported k for both datasets — expected, because high-acc uses larger `n_list` / `n_probe`.
2. **SIFT recall >> GIST recall** — GIST1M is 960-dimensional; PQ approximation and ADC error are harder at high dimension with the same `M=8`, `K=256` shape.
3. **GIST build time dominates** (~248 s high-acc) due to 960D × 1M vectors vs SIFT 128D.
4. **zk-opt trades recall for faster build/query** — especially visible on SIFT (7 s vs 99 s build).

---

## 6. Commands

```bash
# Data sanity
PYTHONPATH=. python scripts/check_fvecs_dataset.py --dataset sift1m --data-root data/public
PYTHONPATH=. python scripts/check_fvecs_dataset.py --dataset gist1m --data-root data/public

# Full / resumable baseline
PYTHONPATH=. python scripts/run_public_utility_baseline.py \
  --datasets sift1m,gist1m \
  --configs high-acc,zk-opt \
  --data-root data \
  --output-dir artifacts/public_utility

# Resume / skip completed configs
PYTHONPATH=. python scripts/run_public_utility_baseline.py \
  --datasets sift1m,gist1m \
  --configs high-acc,zk-opt \
  --data-root data \
  --output-dir artifacts/public_utility \
  --resume --skip-existing

# Re-aggregate only (add full_base, rebuild top-level CSV)
PYTHONPATH=. python scripts/run_public_utility_baseline.py \
  --output-dir artifacts/public_utility \
  --aggregate-only

# Screen/tmux wrapper
bash scripts/run_phase8c_public_utility_screen.sh

# Figures and table
PYTHONPATH=. python scripts/plot_public_utility_figures.py \
  --input artifacts/public_utility/sift_gist_utility_summary.csv \
  --output-dir artifacts/figures

PYTHONPATH=. python scripts/make_public_utility_table.py \
  --input artifacts/public_utility/sift_gist_utility_summary.csv \
  --output artifacts/tables/table_public_utility_summary.tex

# Tests (mock only)
PYTHONPATH=. pytest tests/test_public_utility_baseline.py -v
```

Logs: `artifacts/logs/phase8c_public_utility_baseline.log`, `artifacts/logs/phase8c_public_utility_screen.log`

---

## 7. Output artifacts

| Artifact | Description |
|----------|-------------|
| `artifacts/public_utility/sift_gist_utility_summary.csv` | Paper summary (standard path; includes `full_base`) |
| `artifacts/public_utility/sift_gist_utility_metrics.csv` | standard + zk rows |
| `artifacts/public_utility/per_config/*_{summary,metrics}.csv` | Per-config checkpoint (resumable) |
| `artifacts/public_utility/traces/*_results.npz` | Per-query standard preds + GT |
| `artifacts/figures/main_public_utility_recall.pdf` | RQ1 main figure |
| `artifacts/tables/table_public_utility_summary.tex` | LaTeX table |
| `data/acc_bench/*.json` | Internal V3DB cache (not paper artifact) |

---

## 8. Resumable execution

`scripts/run_public_utility_baseline.py` supports:

| Flag | Behavior |
|------|----------|
| `--datasets sift1m,gist1m` | Subset of datasets |
| `--configs high-acc,zk-opt` | Subset of configs |
| `--skip-existing` | Skip configs with per-config outputs |
| `--only-missing` | Run only configs without per-config summary |
| `--resume` | `--skip-existing` + aggregate at end |
| `--aggregate-only` | Migrate legacy CSV → per_config; rebuild top-level CSV |

Each config writes `per_config/{dataset}_{config}_{summary,metrics}.csv` immediately on completion. If a trace exists but summary is missing, recalls can be **recovered from trace** (build/query times unavailable).

---

## 9. Git hygiene — do not commit

| Path | Reason |
|------|--------|
| `data/public/` | Large fvecs |
| `data/sift`, `data/gist` | Symlinks to local data |
| `artifacts/public_utility/traces/` | Large NPZ per-query traces |
| `artifacts/logs/` | Machine-local run logs |
| `artifacts/checkpoints/` | Resumable experiment state |

Summary CSV / PDF / TEX may be curated for paper release; default policy keeps large artifacts local. See `.gitignore` entries for traces/logs/checkpoints.

---

## 10. Limitations and next phases

| Item | Status |
|------|--------|
| SIFT1M / GIST1M utility baseline | **Complete (this phase)** |
| MS MARCO utility | **Phase 8D** |
| Authorization overlay / post-filter | **Next phase** (uses traces) |
| ZK proof sampling | **D1-E** from public traces |
| Rust/PyO3 changes | **None** |

---

## 11. Paper placement

| Output | Placement |
|--------|-----------|
| `main_public_utility_recall.pdf` | RQ1 main figure |
| `table_public_utility_summary.tex` | Dataset/config utility table |

---

## 12. Deliverables

| File | Role |
|------|------|
| `scripts/run_public_utility_baseline.py` | Resumable V3DB acc_bench wrapper |
| `scripts/run_phase8c_public_utility_screen.sh` | Screen/tmux runner |
| `scripts/plot_public_utility_figures.py` | Recall figure |
| `scripts/make_public_utility_table.py` | LaTeX table |
| `tests/test_public_utility_baseline.py` | Mock tests |
| `docs/phase8_public_utility_baseline_log.md` | This log |

**Rust/PyO3 changes:** None.
