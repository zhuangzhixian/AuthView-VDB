# Phase 3C: Global Committed vs Slot-Aligned Committed Evaluation

## Summary

Phase 3C extends `scripts/bench_auth_paths.py` with a fifth path **`auth_slot_aligned`**, enabling direct comparison of global committed-auth and slot-aligned committed-auth ZK overhead on the same synthetic workloads.

**Branch:** `phase3-slot-aligned-eval`

**Not modified:** Rust proof logic, PyO3 API signatures, CSV column schema.

---

## Compared Paths

| Path | API |
|------|-----|
| `baseline` | `py_set_based_with_merkle` |
| `auth_all_visible` | `py_set_based_auth_all_visible_with_merkle` |
| `auth_policy` | `py_set_based_auth_with_merkle` |
| `auth_committed` | `py_set_based_auth_committed_with_merkle` |
| `auth_slot_aligned` | `py_set_based_auth_slot_aligned_with_merkle` |

---

## Modified / New Files

| File | Change |
|------|--------|
| `scripts/bench_auth_paths.py` | Fifth path, slot-aligned witness builder, extended stdout summary |
| `tests/test_auth_overhead_script.py` | 5-path checks, slot vs global gate comparison |
| `artifacts/auth_zk_slot_aligned_metrics.csv` | Default Phase 3C output |
| `docs/phase3_slot_aligned_eval_log.md` | This log |

---

## Workload Grid (default light config)

| Parameter | Values |
|-----------|--------|
| `repeat` | 1 |
| `num_vectors` | 400 |
| `dim` | 64 |
| `n_list` | 8 |
| `n_probe` | {2, 4} |
| `slot_per_list` | {32, 64} |
| `top_k` | 5 |

**Rows:** 4 workloads × 5 paths = **20** CSV rows.

### Paper-ready config (recommended)

| Parameter | Values |
|-----------|--------|
| `repeat` | 3 |
| `n_probe` | {2, 4} |
| `slot_per_list` | {32, 64, 128} |
| `top_k` | 5 |

**Rows:** 6 workloads × 5 paths × 3 repeats = **90** rows.

---

## CSV Schema (unchanged)

Same 16 columns as Phase 2D/2E:

`path`, `repeat_id`, `num_vectors`, `dim`, `n_list`, `n_probe`, `slot_per_list`, `top_k`, `N_sel`, `visible_ratio`, `auth_tree_depth`, `build_time`, `prove_time`, `verify_time`, `proof_size`, `memory`, `gates`

### `auth_tree_depth` semantics by path

| Path | Recorded value |
|------|----------------|
| baseline, auth_all_visible, auth_policy, auth_committed | `tree_depth(next_pow2(N_sel))` — global flat tree |
| auth_slot_aligned | `depth_top + depth_slot` where `depth_top = tree_depth_padded(n_list)`, `depth_slot = tree_depth_padded(slot_per_list)` |

No new columns added.

---

## Witness / Wire Format Notes

- Slot-aligned PyO3 input **expands** the shared top-level Merkle path into per-probe-row arrays `[n_probe][depth_top]`. Circuit semantics verify **one top opening per probe row** (shared `list_auth_root` fan-out).
- If multiple probe rows hit the **same IVF list**, the benchmark currently supplies duplicate top-path rows; future work can deduplicate repeated list openings on the wire.
- Evaluation uses **synthetic snapshots** (random IVF-PQ learn + partial-visible labels); not production dataset traces.

---

## Observed Trend (default light run, seed=42)

Run command:

```bash
python scripts/bench_auth_paths.py \
  --repeat 1 \
  --n-probe-list 2,4 \
  --slot-per-list-list 32,64 \
  --top-k-list 5 \
  --output artifacts/auth_zk_slot_aligned_metrics.csv
```

Stdout summary columns: `c/b` (committed/baseline gates), `s/c` (slot/global gates), `s/p_t` (slot/global prove_time).

**Measured gates (repeat_id=0, seed=42):**

| n_probe | slot | N_sel | baseline | committed | slot_aligned | s/c | s/p_t |
|---------|------|-------|----------|-----------|--------------|-----|-------|
| 2 | 32 | 64 | 10,032 | 11,062 | 10,979 | 0.992 | 0.970 |
| 2 | 64 | 128 | 10,459 | 12,706 | 12,530 | 0.986 | 1.042 |
| 4 | 32 | 128 | 17,863 | 20,110 | 19,758 | 0.982 | 0.969 |
| 4 | 64 | 256 | 18,720 | 23,583 | 22,861 | 0.969 | 0.999 |

Slot-aligned gates are **1–3% lower** than global committed across all four default workloads. Prove time tracks similarly (ratio ≈ 0.97–1.04). The largest absolute committed overhead appears at `n_probe=4, slot=64` (23,583 vs 22,861 gates).

Small workloads (`n_probe=2`) show smaller absolute gap but same direction; fixed circuit overhead prevents dramatic ratio swings at low `N_sel`.

---

## Limitations

- Synthetic data only; no real embedding distribution.
- `auth_tree_depth` column mixes semantics across paths (documented above, not comparable across path types).
- Slot-aligned gate count includes list_id binding + per-row top verify even when lists repeat.
- Single repeat in default config; use `repeat=3` for paper tables.

---

## Tests

`tests/test_auth_overhead_script.py`:

1. CSV contains `auth_slot_aligned`
2. Each workload has 5 paths
3. Slot-aligned metrics positive
4. Both committed paths run successfully
5. Typical workload (`n_probe=4`, `slot=32`, `n_list=8`): slot-aligned gates ≤ global committed
6. CSV schema unchanged (`CSV_FIELDS`)

---

## Recommended Paper-Ready Run

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
  --output artifacts/auth_zk_slot_aligned_metrics.csv
```

Report median gates / prove_time across repeats per (workload, path). Include `s/c` ratio table and opening-cost ideal estimate from `estimate_slot_aligned_opening_cost` vs `estimate_global_opening_cost`.
