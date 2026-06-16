# Phase 2D: Auth ZK Path Overhead Evaluation Snapshot

Lightweight benchmark comparing four set-based Merkle proof paths on the same
synthetic IVF-PQ workload. No circuit or API changes — measurement only.

**Branch:** `phase2-auth-overhead-eval`

---

## 1. Purpose

Quantify additive overhead of AuthView authorization layers relative to V3DB
baseline on a reproducible synthetic index:

| Path | API |
|------|-----|
| V3DB baseline | `py_set_based_with_merkle` |
| Auth all-visible | `py_set_based_auth_all_visible_with_merkle` |
| Auth policy-only | `py_set_based_auth_with_merkle` |
| Auth committed | `py_set_based_auth_committed_with_merkle` |

---

## 2. New files

| File | Role |
|------|------|
| `scripts/bench_auth_paths.py` | Benchmark driver + optional stdout summary |
| `tests/test_auth_overhead_script.py` | Script smoke + gate ordering checks |
| `artifacts/auth_zk_path_metrics.csv` | Generated metrics (not committed if large) |
| `docs/phase2_overhead_eval_log.md` | This log |

**Not modified:** Rust proof logic, PyO3 API signatures.

---

## 3. Workload settings

Default snapshot parameters (match ZK integration tests):

| Parameter | Default |
|-----------|---------|
| `num_vectors` | 400 |
| `dim` | 64 |
| `n_list` | 8 |
| `n_probe` | 4 |
| `slot_per_list` | power-of-two cluster capacity (from `id_groups`) |
| `top_k` | 5 |
| `N_sel` | `n_probe × slot_per_list` |
| `visible_ratio` | fraction of **valid** slots policy-visible (partial-visible labels: 2 invisible) |
| `auth_tree_depth` | `tree_depth(next_pow2(N_sel))` |
| `repeat` | **1** for CI / quick snapshot (`--repeat 3` for fuller snapshot) |
| `seed` | 42 (+ repeat_id offset per repetition) |

Witness construction reuses `tests/test_auth_zk_all_visible._build_merkle_proof_inputs`
and partial-visible label setup from `build_partial_visible_labels`.

---

## 4. CSV schema

Output: `artifacts/auth_zk_path_metrics.csv` (CSV only, no JSON).

| Column | Type | Description |
|--------|------|-------------|
| `path` | str | `baseline`, `auth_all_visible`, `auth_policy`, `auth_committed` |
| `repeat_id` | int | 0 … repeat−1 |
| `num_vectors` | int | IVF training set size |
| `dim` | int | vector dimension |
| `n_list` | int | IVF list count |
| `n_probe` | int | probed lists |
| `slot_per_list` | int | fixed-shape capacity per list |
| `top_k` | int | public top-k |
| `N_sel` | int | `n_probe × slot_per_list` |
| `visible_ratio` | float | policy-visible / valid slots |
| `auth_tree_depth` | int | global auth Merkle depth (committed path) |
| `build_time` | float | circuit build seconds |
| `prove_time` | float | prove seconds |
| `verify_time` | float | verify seconds |
| `proof_size` | int | proof bytes |
| `memory` | int | peak memory (bytes, from Rust metrics) |
| `gates` | int | circuit gate count |

One row per `(path, repeat_id)` run.

---

## 5. Run commands

```bash
source "$HOME/.cargo/env"
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB

maturin develop --release

python scripts/bench_auth_paths.py --repeat 1 --output artifacts/auth_zk_path_metrics.csv

PYTHONPATH=. pytest tests/test_auth_overhead_script.py -v
```

Optional fuller snapshot: `--repeat 3`.

---

## 6. Observed result summary

Default snapshot (`--repeat 1`, 400 vectors, dim=64, n_list=8, n_probe=4,
slot_per_list=64, N_sel=256, auth_tree_depth=8, visible_ratio≈0.991):

| path | gates | prove_time (s) | proof_size | verify_time (s) |
|------|-------|----------------|------------|-----------------|
| baseline | 18,720 | 0.666 | 142,035 | 0.0050 |
| auth_all_visible | 18,744 | 0.674 | 143,159 | 0.0050 |
| auth_policy | 20,358 | 0.680 | 145,224 | 0.0050 |
| auth_committed | 23,583 | 0.691 | 144,944 | 0.0051 |

Gate ordering: `committed (23,583) > policy (20,358) > all_visible (18,744) > baseline (18,720)`.

Ratios vs baseline: prove_time **1.037×**, proof_size **1.020×** (committed-auth).

Committed-auth adds ~3,225 gates over policy-only (~16% gate increase), dominated
by per-slot Merkle verification (`N_sel × auth_tree_depth` hash steps).

---

## 7. Limitations

- **Synthetic only** — no SIFT / production datasets.
- **Single workload size** — not a scaling study.
- **Partial-visible labels** — policy/committed paths use 2 forced-invisible cids; all-visible path ignores labels in-circuit.
- **Global auth tree** — every slot carries full Merkle path witness (`auth_tree_depth` levels × `N_sel` slots).
- **repeat=1 default** — timings are indicative, not statistically robust.
- **Build time included in Rust metrics** — first run may amortize allocator / JIT effects.

---

## 8. Why this motivates slot-aligned auth commitment

Committed-auth adds per-slot Merkle verification on top of policy gadgets. With
global tree depth \(O(\log(N_{sel}))\) and \(N_{sel} = n_{probe} \times n\) slots,
gate and prove cost grow roughly linearly in slot count × depth.

Slot-aligned commitment (Phase 3) would:

1. Bind auth labels per IVF cluster / slot index instead of one global tree.
2. Reduce witness size when paths share prefixes within a cluster.
3. Allow smaller per-query auth subtrees when only probed lists matter.

This snapshot establishes the **committed vs baseline** ratio before optimizing
layout.
