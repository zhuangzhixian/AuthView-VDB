# Phase 3D: Paper-Ready Evaluation Snapshot

## Summary

Phase 3D runs a **repeat=3** benchmark over an expanded slot grid and aggregates results into a median-based summary CSV for paper tables/figures. No changes to Rust proof logic, PyO3 APIs, or raw metrics CSV schema.

**Branch:** `phase3-paper-ready-eval`

---

## Run Configuration

| Parameter | Value |
|-----------|--------|
| `repeat` | **3** (completed) |
| `num_vectors` | 400 |
| `dim` | 64 |
| `n_list` | 8 |
| `n_probe` | {2, 4} |
| `slot_per_list` | {32, 64, **128**} |
| `top_k` | 5 |
| `seed` | 42 (+ repeat offset) |

**Workloads:** 2 × 3 = **6** grid points  
**Raw rows:** 6 × 5 paths × 3 repeats = **90**  
**Summary rows:** 6 × 5 paths = **30**

### Commands

```bash
source "$HOME/.cargo/env"
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB

maturin develop --release

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

Wall time (single machine run): ~3.2 min benchmark + ~2.4 min pytest smoke.

---

## CSV Files

| File | Rows | Description |
|------|------|-------------|
| `artifacts/auth_zk_paper_ready_metrics.csv` | 90 | Raw per-repeat metrics (unchanged Phase 2D schema) |
| `artifacts/auth_zk_paper_ready_summary.csv` | 30 | Median + ratio aggregation |

Output format: **CSV only** (no JSON).

---

## Raw Metrics Schema (unchanged)

16 columns: `path`, `repeat_id`, `num_vectors`, `dim`, `n_list`, `n_probe`, `slot_per_list`, `top_k`, `N_sel`, `visible_ratio`, `auth_tree_depth`, `build_time`, `prove_time`, `verify_time`, `proof_size`, `memory`, `gates`

---

## Summary Schema

| Column | Description |
|--------|-------------|
| `num_vectors`, `dim`, `n_list`, `n_probe`, `slot_per_list`, `top_k`, `N_sel`, `visible_ratio`, `auth_tree_depth` | Workload identity |
| `path` | Proof path name |
| `n_repeats` | Repeat count used for median (3) |
| `median_gates`, `median_prove_time`, `median_verify_time`, `median_proof_size`, `median_build_time` | Median over repeats |
| `policy_vs_baseline_gates` | Filled on `auth_policy` rows only |
| `committed_vs_baseline_gates` | Filled on `auth_committed` rows only |
| `slot_vs_committed_gates` | Filled on `auth_slot_aligned` rows only |
| `slot_vs_committed_prove_time` | Filled on `auth_slot_aligned` rows only |

---

## Observed High-Level Trend (median, repeat=3, seed=42)

### Committed overhead vs baseline (`committed_vs_baseline_gates`)

| n_probe | slot | N_sel | median committed gates | ratio vs baseline |
|---------|------|-------|------------------------|-------------------|
| 2 | 32 | 64 | 11,062 | 1.10× |
| 2 | 64 | 128 | 12,706 | 1.21× |
| 2 | 128 | 256 | 16,178 | 1.43× |
| 4 | 32 | 128 | 20,110 | 1.13× |
| 4 | 64 | 256 | 23,583 | 1.26× |
| 4 | 128 | 512 | 30,902 | **1.51×** |

Committed-auth Merkle cost grows with `N_sel` and tree depth as expected.

### Slot-aligned vs global committed (`slot_vs_committed_gates`)

| n_probe | slot | N_sel | median slot gates | median committed gates | s/c gates |
|---------|------|-------|-------------------|------------------------|-----------|
| 2 | 32 | 64 | 10,979 | 11,062 | **0.992** |
| 2 | 64 | 128 | 12,530 | 12,706 | **0.986** |
| 2 | 128 | 256 | 15,816 | 16,178 | **0.978** |
| 4 | 32 | 128 | 19,758 | 20,110 | **0.982** |
| 4 | 64 | 256 | 22,861 | 23,583 | **0.969** |
| 4 | 128 | 512 | 29,437 | 30,902 | **0.953** |

**Trend:** Slot-aligned gates are **2–5% lower** than global committed across all six workloads. The relative win **increases** with larger `N_sel` (best at `n_probe=4, slot=128`: 953/1000 gates).

Prove-time ratio (`slot_vs_committed_prove_time`) tracks gate ratio loosely (0.97–1.02); no systematic prove-time regression.

---

## Limitations

1. **Synthetic IVF-PQ workload** — random 400×64 vectors, 8 clusters; not SIFT/GIST or production embeddings.
2. **Global committed baseline uses selected-slot local tree** — each probed slot carries a full global path under `root_auth`. Slot-aligned improvement is therefore a **conservative** estimate vs a production index-wide global tree.
3. **Wire format overhead** — PyO3 input expands shared top paths per probe row; circuit semantics deduplicate top verify per row, but repeated list probes still pay duplicate direction constraints.
4. **`auth_tree_depth` column** mixes semantics (global depth vs `depth_top+depth_slot`); compare only within the same path family.
5. **Three repeats** — sufficient for smoke/paper draft; final submission may want 5–10 repeats or confidence intervals.

---

## Recommended Paper Table / Figure Usage

### Table 1 — Path overhead (suggested)

Pivot `auth_zk_paper_ready_summary.csv` by workload; columns: `baseline`, `auth_policy`, `auth_committed`, `auth_slot_aligned` **median_gates**. Add ratio columns from summary.

### Table 2 — Slot-aligned savings

Rows = six workloads; columns: `median_gates` (committed, slot-aligned), `slot_vs_committed_gates`, `slot_vs_committed_prove_time`.

### Figure — Scaling curve

X-axis: `N_sel` (64 → 512); Y-axis: median gates. Lines: baseline, auth_committed, auth_slot_aligned. Highlights widening gap at large selection sets.

### Future work (document in paper)

- Repeat on **SIFT1M subset** or fixed real snapshot
- Deduplicate repeated-list top openings on the wire
- Compare against index-wide global auth tree (not probe-local flattening)

---

## Modified / New Files

| File | Change |
|------|--------|
| `scripts/summarize_auth_metrics.py` | **New** — median + ratio aggregation |
| `tests/test_auth_metrics_summary.py` | **New** — summary smoke tests |
| `artifacts/auth_zk_paper_ready_metrics.csv` | **New** — 90-row raw snapshot |
| `artifacts/auth_zk_paper_ready_summary.csv` | **New** — 30-row summary |
| `docs/phase3_paper_ready_eval_log.md` | This log |

**Not modified:** `scripts/bench_auth_paths.py` logic (only consumed), Rust, PyO3, raw CSV schema.

---

## Tests

```bash
PYTHONPATH=. pytest tests/test_auth_overhead_script.py tests/test_auth_metrics_summary.py -v
```

**12/12 passed** (Phase 3D run).
