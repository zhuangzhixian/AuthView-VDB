# Phase 9B: Full Authorized-Reference Calibration Log

**Phase:** 9B  
**RQ:** RQ1 calibration — validate Phase 9A candidate-level authorization metrics  
**Scope:** SIFT1M + GIST1M representative queries; full 1M base exact authorized top-k (no MS MARCO, no ZK, no Rust/PyO3)

**Companion:** [phase9_authorization_overlay_log.md](phase9_authorization_overlay_log.md), [phase8_public_utility_baseline_log.md](phase8_public_utility_baseline_log.md)

---

## 1. Why Phase 9B

Phase 9A compared post-filter vs **candidate-level** authorized reference using only `pred[:100]` from Phase 8C traces. That scope is honest but **cannot** certify how close candidate-level recall is to true authorized-view ANN on the full 1M corpus.

Phase 9B **calibrates** Phase 9A by computing **full authorized reference** on selected public benchmark queries:

| Method | Scope |
|--------|-------|
| Post-filter | `pred[:k]` filtered by visibility |
| Candidate-level | visible items in `pred[:100]` (Phase 9A) |
| **Full authorized** | exact top-k over all visible base vectors (1M filtered) |

Output `reference_scope=full_base_calibration`.

---

## 2. Phase 9A candidate_level boundary

Phase 8C traces store IVF-PQ top-100 predictions only. Phase 9A authorized reference cannot rank neighbors outside that prefix. Phase 9B quantifies the **calibration gap**:

- `candidate_full_recall_gap = candidate_recall − full_recall`
- `post_full_recall_gap = post_filter_recall − full_recall`

Negative gap means candidate/post **underestimates** full authorized recall (true neighbor deeper in authorized view).

---

## 3. Calibration query selection

Script: `scripts/select_authorized_calibration_queries.py`

Per (dataset, config, policy, selectivity), scan Phase 8C trace at k=10:

| Bucket | Rule |
|--------|------|
| `gap_bucket=low` | candidate and post agree on recall hit |
| `gap_bucket=medium` | post ≠ candidate lists but same recall |
| `gap_bucket=high` | candidate hits GT, post-filter does not |
| `underfill_bucket` | `underfill` if post-filter returns fewer than k else `filled` |

Sample `--queries-per-bucket` queries per bucket (seeded), cap with `--max-queries-per-dataset`.

Output: `artifacts/auth_calibration/calibration_queries.csv`

---

## 4. Full authorized reference computation

Script: `scripts/calibrate_full_authorized_reference.py`  
Library: `scripts/auth_calibration_lib.py`

1. Load query vector from `data/public/{sift1m,gist1m}/{prefix}_query.fvecs`.
2. Load visibility mask from Phase 9A NPZ.
3. Scan **full base** `{prefix}_base.fvecs` (1M vectors) in chunks over visible IDs.
4. Compute squared L2 distance; maintain top-k heap.
5. Optional FAISS `IndexFlatL2` on visible subset when available; numpy chunked fallback otherwise.

Metadata per row: `num_base=1000000`, `full_base=true`, `reference_scope=full_base_calibration`.

Per query @k:

- `post_filter_recall`, `candidate_reference_recall`, `full_authorized_recall`
- `post_filter_underfill`
- `candidate_vs_full_overlap`, `post_filter_vs_full_overlap`

---

## 5. full_base=true confirmation

| Dataset | num_base | dim | Queries (public) |
|---------|----------|-----|------------------|
| SIFT1M | 1,000,000 | 128 | 10,000 |
| GIST1M | 1,000,000 | 960 | 1,000 |

Data path: `data/public/sift1m/`, `data/public/gist1m/` (TEXMEX fvecs).  
Calibration reads **all visible base vectors** from fvecs — not trace prefix.

---

## 6. Cost, chunking, resume

**Cost drivers:** `num_calibration_queries × visible_count × dim` distance ops per query.

Flags:

| Flag | Purpose |
|------|---------|
| `--dry-run` / `--estimate-cost` | Print query counts and op estimate only |
| `--chunk-size` | Visible-ID batch size (default 50,000) |
| `--resume` / `--skip-existing` | Skip completed (query, k) in checkpoint |
| `--max-queries-per-dataset` | Subsample calibration set |

Checkpoint: `artifacts/auth_calibration/full_authorized_reference_checkpoint.csv` (append per batch; **not committed**).

Long runs: use `scripts/run_phase9b_auth_calibration_screen.sh` inside `screen -S authview-phase9b`.

---

## 7. Commands

```bash
# Tests
PYTHONPATH=. .venv/bin/python -m pytest tests/test_authorized_reference_calibration.py -v

# Select queries
PYTHONPATH=. .venv/bin/python scripts/select_authorized_calibration_queries.py \
  --auth-summary artifacts/auth_overlay/public_trace_auth_summary.csv \
  --auth-metrics artifacts/auth_overlay/public_trace_auth_metrics.csv \
  --output artifacts/auth_calibration/calibration_queries.csv \
  --queries-per-bucket 5 \
  --max-queries-per-dataset 500 \
  --seed 42

# Dry-run cost estimate
PYTHONPATH=. .venv/bin/python scripts/calibrate_full_authorized_reference.py \
  --calibration-queries artifacts/auth_calibration/calibration_queries.csv \
  --data-root data/public \
  --overlay-dir artifacts/auth_overlay \
  --trace-dir artifacts/public_utility/traces \
  --output-dir artifacts/auth_calibration \
  --ks 1,10,100 \
  --chunk-size 50000 \
  --estimate-cost

# Full run (screen recommended)
screen -S authview-phase9b
bash scripts/run_phase9b_auth_calibration_screen.sh
```

---

## 8. Output artifacts

| Artifact | Git |
|----------|-----|
| `calibration_queries.csv` | Commit |
| `full_authorized_reference_summary.csv` | Commit |
| `full_authorized_reference_metrics.csv` | Commit (if small) |
| `full_authorized_reference_checkpoint.csv` | Ignore |
| `main_authorized_reference_calibration.pdf` | Commit |
| `table_authorized_reference_calibration.tex` | Commit |

---

## 9. Paper placement

- **Main paper:** Phase 9A trace trends (full query sets, all policies/selectivities).
- **Calibration appendix / footnote:** Phase 9B subset with `full_base_calibration` to bound candidate-level error vs exact authorized top-k.
- Report `candidate_full_recall_gap` and overlap@k as confidence intervals on the approximation.

---

## 10. Limitations

1. **Calibration subset** — not a replacement for Phase 9A full-trace trends.
2. **Exact L2 scan** — correct for TEXMEX SIFT/GIST (L2 benchmark); no IVF-PQ approximate search in authorized view.
3. **No MS MARCO / ZK proof** in this phase.
4. **Compute heavy** — requires screen/long run for full calibration set.

---

## Files added (Phase 9B)

- `scripts/auth_calibration_lib.py`
- `scripts/select_authorized_calibration_queries.py`
- `scripts/calibrate_full_authorized_reference.py`
- `scripts/plot_authorized_calibration_figures.py`
- `scripts/make_authorized_calibration_table.py`
- `scripts/run_phase9b_auth_calibration_screen.sh`
- `tests/test_authorized_reference_calibration.py`
- `docs/phase9b_authorized_reference_calibration_log.md`
