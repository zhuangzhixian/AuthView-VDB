# Phase 9A: Authorization Overlay on Public Benchmark Traces

**Phase:** 9A  
**RQ:** RQ1 extension — authorization utility on public IVF-PQ traces  
**Scope:** SIFT1M + GIST1M Phase 8C traces only (no MS MARCO, no ZK proof, no Rust/PyO3 changes)

**Companion:** [phase8_public_utility_baseline_log.md](phase8_public_utility_baseline_log.md), [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md), [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md)

---

## 1. Phase 9A goal

Compare three retrieval semantics on **fixed Phase 8C public benchmark traces**:

| Method | Definition |
|--------|------------|
| **Unrestricted baseline** | Original IVF-PQ top-k from Phase 8C (`pred[:k]` vs rank-1 GT). |
| **Post-filter baseline** | Filter `pred[:k]` to visible objects only; may **underfill** if fewer than k visible items remain. |
| **Authorized reference (approximation)** | Scan the full trace candidate list (`pred[:depth]`, depth=100 in Phase 8C), keep visible items in ANN order, take first k. |

Core metrics: selectivity / visible ratio, post-filter vs authorized recall@k, underfill rate, violation rate, utility gap, affected query rate.

---

## 2. Why after Phase 8C public utility traces

Phase 8C established **full-base** (1M vectors) unrestricted IVF-PQ utility with persisted `pred` / `gt` NPZ traces. Phase 9A **reuses those traces** and overlays synthetic authorization policies — no index rebuild, no new ANN queries, no ZK circuits.

This isolates **authorization semantics** from index construction and proof cost.

---

## 3. Overlay generation method

Script: `scripts/generate_authorization_overlay.py`  
Library: `scripts/auth_overlay_lib.py`

**Policy modes:**

| Mode | Description |
|------|-------------|
| `uniform_random` | Each object visible independently with probability = target selectivity. |
| `clustered_acl` | Objects assigned to ACL classes; user sees a prefix of classes matching target selectivity. |
| `skewed_acl` | Zipf-weighted class assignment; visible classes chosen to approximate target global selectivity. |

**Selectivities:** 0.1, 0.25, 0.5, 0.75  
**Seed:** `--seed 42` with per-(dataset, mode, selectivity) derived sub-seeds for reproducibility.

**Outputs:**

- `{dataset}_{mode}_overlay_summary.csv` — one row per selectivity (observed selectivity, mask path).
- `{dataset}_{mode}_sel{sel}_visibility.npz` — full boolean mask + ACL class array (not committed to git).
- `{dataset}_{mode}_sel{sel}_object_visibility_sample.csv` — sampled rows with `object_id, acl_class, visible`.

---

## 4. Post-filter baseline definition

For query `q` and top-k prefix `pred_q[:k]`:

1. Keep only candidates `c` where `visible[c] == true`.
2. Preserve original ANN order among survivors.
3. Return up to k items; if fewer than k visible items exist in the prefix, the result is **underfilled**.

This matches the weak but common “retrieve then filter” deployment pattern (`auth_reference/post_filter.py` semantics at trace level).

---

## 5. Authorized reference boundary

Phase 8C traces store **`pred` with depth = top_k = 100** and rank-1 `gt` only. They do **not** contain full-database neighbor rankings or per-query candidate pools beyond the stored prefix.

Therefore:

- **`reference_scope = candidate_level`** for all Phase 9A metrics.
- Authorized reference = best visible ranking **within the trace candidate prefix**, not full-database authorized ANN.
- We **do not** label this as full-database authorized top-k.

A true full authorized reference would require re-running ANN search on `V(U,σ)` or storing complete candidate sets — out of scope for 9A.

---

## 6. Metrics definitions

All recalls use V3DB hit-style semantics: R@k = 1 iff rank-1 GT ∈ result set.

| Metric | Definition |
|--------|------------|
| `visible_ratio` | Mean fraction of visible items in `pred[:depth]` per query. |
| `unrestricted_recall` | GT hit rate in unrestricted `pred[:k]`. |
| `post_filter_recall` | GT hit rate after post-filter on `pred[:k]`. |
| `authorized_recall` | GT hit rate in candidate-level authorized reference. |
| `underfill_rate` | Fraction of queries where post-filter returns fewer than k items. |
| `avg_visible_results` | Mean count of visible items in post-filter output at k. |
| `violation_count` / `violation_rate` | Invisible objects incorrectly present in post-filter output (should be 0). |
| `utility_gap` | `authorized_recall − post_filter_recall`. |
| `affected_query_rate` | Fraction of queries where post-filter output ≠ authorized reference at k. |
| `reference_scope` | Always `candidate_level` in Phase 9A. |

---

## 7. Commands

```bash
# Tests (mock only)
PYTHONPATH=. .venv/bin/python -m pytest tests/test_authorization_overlay.py -v

# Generate overlays
PYTHONPATH=. .venv/bin/python scripts/generate_authorization_overlay.py \
  --datasets sift1m,gist1m \
  --num-base-from-summary artifacts/public_utility/sift_gist_utility_summary.csv \
  --policy-modes uniform_random,clustered_acl,skewed_acl \
  --selectivities 0.1,0.25,0.5,0.75 \
  --output-dir artifacts/auth_overlay \
  --seed 42

# Evaluate traces
PYTHONPATH=. .venv/bin/python scripts/evaluate_authorized_trace.py \
  --trace-dir artifacts/public_utility/traces \
  --summary artifacts/public_utility/sift_gist_utility_summary.csv \
  --overlay-dir artifacts/auth_overlay \
  --output-dir artifacts/auth_overlay \
  --ks 1,10,100

# Figures and table
PYTHONPATH=. .venv/bin/python scripts/plot_authorization_overlay_figures.py \
  --input artifacts/auth_overlay/public_trace_auth_summary.csv \
  --output-dir artifacts/figures

PYTHONPATH=. .venv/bin/python scripts/make_authorization_overlay_table.py \
  --input artifacts/auth_overlay/public_trace_auth_summary.csv \
  --output artifacts/tables/table_auth_overlay_summary.tex
```

---

## 8. Output artifacts

| Artifact | Git |
|----------|-----|
| `artifacts/auth_overlay/*_overlay_summary.csv` | Commit |
| `artifacts/auth_overlay/public_trace_auth_metrics.csv` | Commit |
| `artifacts/auth_overlay/public_trace_auth_summary.csv` | Commit |
| `artifacts/auth_overlay/*_visibility.npz` | **Ignore** (large) |
| `artifacts/auth_overlay/*_object_visibility_sample.csv` | Optional / ignore |
| `artifacts/figures/main_auth_overlay_utility_gap.pdf` | Commit |
| `artifacts/figures/main_auth_overlay_underfill.pdf` | Commit |
| `artifacts/tables/table_auth_overlay_summary.tex` | Commit |

---

## 9. Current limitations

1. **Trace-only** — no MS MARCO, no live ANN re-query.
2. **No ZK proof** — plaintext overlay evaluation only.
3. **Candidate-level reference** — authorized recall is bounded by trace depth (100), not full corpus.
4. **Synthetic policies** — uniform / clustered / skewed ACL; not production IAM.
5. **No Rust/PyO3 / index rebuild** — overlays applied post hoc to stored `pred`/`gt`.

---

## 10. Next step: proof sampling

Phase 9B+ can:

1. Sample queries where `utility_gap > 0` or `underfill_rate` is high for ZK proof case studies.
2. Wire candidate-level authorized results into existing auth path benches (`bench_auth_paths.py`) for proof-size / gate overhead on **representative** authorized views.
3. Optionally re-run plaintext authorized reference on expanded candidate pools for a subset of queries to quantify candidate-level vs full reference gap.

---

## Files added (Phase 9A)

- `scripts/auth_overlay_lib.py`
- `scripts/generate_authorization_overlay.py`
- `scripts/evaluate_authorized_trace.py`
- `scripts/plot_authorization_overlay_figures.py`
- `scripts/make_authorization_overlay_table.py`
- `tests/test_authorization_overlay.py`
- `docs/phase9_authorization_overlay_log.md`
