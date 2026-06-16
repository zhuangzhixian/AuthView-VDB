# Phase 2E: Committed-Auth Scaling Evaluation

Lightweight scaling study extending Phase 2D overhead snapshot. Measures how
committed-auth ZK cost grows with `N_sel`, `n_probe`, `slot_per_list`, and
`auth_tree_depth`. No circuit or API changes — measurement only.

**Branch:** `phase2-auth-scaling-eval`

---

## 1. Purpose

Observe committed-auth overhead as selection geometry scales:

$$
N_{sel} = n_{probe} \times slot\_per\_list
$$

$$
auth\_tree\_depth = tree\_depth(next\_pow2(N_{sel}))
$$

Committed path adds per-slot Merkle verification proportional to
`N_sel × auth_tree_depth`. This study quantifies that growth to motivate
Phase 3 slot-aligned commitment.

---

## 2. Modified / new files

| File | Change |
|------|--------|
| `scripts/bench_auth_paths.py` | Parameter grid scan (`--n-probe-list`, `--slot-per-list-list`, `--top-k-list`) |
| `tests/test_auth_overhead_script.py` | Scaling smoke + `N_sel` / depth / gate-order checks |
| `artifacts/auth_zk_scaling_metrics.csv` | Paper-ready scaling output |
| `docs/phase2_scaling_eval_log.md` | This log |

**Not modified:** Rust proof logic, PyO3 API signatures.

---

## 3. Parameter grid

### Default light config (CI / quick run)

| Parameter | Values |
|-----------|--------|
| `repeat` | 1 |
| `num_vectors` | 400 |
| `dim` | 64 |
| `n_list` | 8 |
| `n_probe` | {2, 4} |
| `slot_per_list` | {32, 64} |
| `top_k` | 5 |

**Workloads:** 2 × 2 = **4** grid points × 4 paths = **16** CSV rows per repeat.

### Fuller config (documented for paper runs)

| Parameter | Values |
|-----------|--------|
| `repeat` | 3 |
| `n_probe` | {2, 4} |
| `slot_per_list` | {32, 64, 128} |
| `top_k` | 5 |

**Workloads:** 2 × 3 = **6** grid points × 4 paths × 3 repeats = **72** rows.

Slot capacity is enforced by padding/truncating V3DB slot buffers after IVF
index construction (benchmark-only; no circuit change).

---

## 4. CSV schema

Output: `artifacts/auth_zk_scaling_metrics.csv` (CSV only).

Same columns as Phase 2D snapshot:

| Column | Description |
|--------|-------------|
| `path` | `baseline` / `auth_all_visible` / `auth_policy` / `auth_committed` |
| `repeat_id` | Repetition index |
| `num_vectors`, `dim`, `n_list` | Fixed IVF index parameters |
| `n_probe`, `slot_per_list`, `top_k` | Grid variables |
| `N_sel` | `n_probe × slot_per_list` |
| `visible_ratio` | Policy-visible fraction among valid slots |
| `auth_tree_depth` | `tree_depth(next_pow2(N_sel))` |
| `build_time`, `prove_time`, `verify_time`, `proof_size`, `memory`, `gates` | Rust metrics |

One row per `(workload, path, repeat_id)`.

---

## 5. Run commands

```bash
source "$HOME/.cargo/env"
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB

maturin develop --release

python scripts/bench_auth_paths.py \
  --repeat 1 \
  --n-probe-list 2,4 \
  --slot-per-list-list 32,64 \
  --top-k-list 5 \
  --output artifacts/auth_zk_scaling_metrics.csv

PYTHONPATH=. pytest tests/test_auth_overhead_script.py -v
```

Stdout prints a compact scaling table: gates by `(n_probe, slot, N_sel, depth)`.

---

## 6. Observed trend summary

Latest run (`repeat=1`, `top_k=5`, 400 vectors, dim=64):

| n_probe | slot | N_sel | depth | baseline gates | policy gates | committed gates | c/b ratio | committed prove (s) |
|---------|------|-------|-------|----------------|--------------|-----------------|-----------|-------------------|
| 2 | 32 | 64 | 6 | 10,032 | 10,442 | 11,062 | 1.103 | 0.380 |
| 2 | 64 | 128 | 7 | 10,459 | 11,278 | 12,706 | 1.215 | 0.399 |
| 4 | 32 | 128 | 7 | 17,863 | 18,683 | 20,110 | 1.126 | 0.711 |
| 4 | 64 | 256 | 8 | 18,720 | 20,358 | 23,583 | 1.260 | 0.772 |

**Trends observed:**

1. **Baseline gates** grow with `N_sel` (more slots → larger set-based circuit), from 10k (N_sel=64) to 19k (N_sel=256).
2. **Policy overhead** is ~400–1,600 gates above baseline depending on `N_sel`.
3. **Committed overhead** is ~620–3,225 gates above policy; scales with both `N_sel` and `auth_tree_depth`.
4. **Depth step effect:** doubling `N_sel` from 128→256 at n_probe=4 increases committed gates by ~17% (20,110→23,583) when depth 7→8.
5. **Prove time:** committed/baseline ratio ~1.03–1.10×; gate growth outpaces prove-time growth on this small grid.

Gate ordering holds on all grid points: `committed ≥ policy ≥ baseline`.

---

## 7. Limitations

- Synthetic IVF-PQ only; no SIFT / production data.
- Slot resize via pad/truncate may not match real cluster size distributions.
- `repeat=1` default — timings are indicative, not statistically robust.
- Global auth tree only (no slot-aligned layout).
- `top_k` has minimal circuit impact but included for completeness.

---

## 8. Motivation for slot-aligned auth commitment (Phase 3)

Scaling data shows committed-auth gate cost dominated by **per-slot Merkle paths**
over a global tree of size `next_pow2(N_sel)`. As `n_probe` or `slot_per_list`
grows, cost grows as **O(N_sel × log N_sel)**.

Slot-aligned commitment would:

1. Use **per-cluster auth subtrees** aligned with IVF list layout.
2. Verify only **probed lists** at query time.
3. Share Merkle path prefixes among slots in the same cluster.
4. Decouple auth witness size from total index slots not touched by the query.

Phase 2E quantifies the baseline global-tree cost that Phase 3 should reduce.
