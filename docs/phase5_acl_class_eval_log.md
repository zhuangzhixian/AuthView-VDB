# Phase 5C: ACL-class Compression Evaluation

## Evaluation Goal

Measure **ACL-class compression** benefit by comparing two committed authorization ZK paths on identical workloads:

| Path | Policy evals | Per-slot auth structure |
|------|--------------|-------------------------|
| `auth_committed` | Once per selected slot (`N_sel`) | Object-level auth label Merkle opening |
| `auth_acl_class` | Once per ACL class row (`N_acl_max`) | Object-to-class binding opening + class table |

Output CSV supports **N_acl / N_sel** ratio plots for paper figures.

## Compared Paths

- **auth_committed** — object-level committed AuthView (Phase 2C)
- **auth_acl_class** — ACL-class compressed path (Phase 5B-3)

Both use the same V3DB IVF-PQ buffers, distances, and visibility semantics. Object-level labels for `auth_committed` are **expanded from ACL class structure** (not the reverse).

## Workload Grid

### Default (lightweight, repeat=1)

| Parameter | Value |
|-----------|-------|
| repeat | 1 |
| num_vectors | 400 |
| dim | 64 |
| n_list | 8 |
| n_probe | 4 |
| slot_per_list | 64 |
| top_k | 5 |
| N_acl | 1, 2, 4, 8, 16, 32, 64 (filtered to ≤ N_sel and ≤ valid cid count) |

### Paper-ready (suggested)

| Parameter | Value |
|-----------|-------|
| repeat | 3 |
| n_probe | 2, 4 |
| slot_per_list | 64, 128 |
| N_acl | 1, 2, 4, 8, 16, 32, 64, 128 |
| top_k | 5 |

Current repository run uses **repeat=1**; paper-ready runs should set `--repeat 3` explicitly.

## Tight N_acl_max = N_acl

This evaluation sets **`N_acl_max = N_acl`** (tight class table, no dummy padding rows beyond the used classes). In fixed-capacity deployment, circuit cost scales with **`N_acl_max`**, not the live `N_acl`. Document this when interpreting results.

## Scripts

```bash
python scripts/bench_acl_class_paths.py \
  --repeat 1 \
  --n-probe-list 4 \
  --slot-per-list-list 64 \
  --n-acl-list 1,2,4,8,16,32,64 \
  --top-k-list 5 \
  --output artifacts/auth_zk_acl_class_metrics.csv

python scripts/summarize_acl_class_metrics.py \
  --input artifacts/auth_zk_acl_class_metrics.csv \
  --output artifacts/auth_zk_acl_class_summary.csv
```

## Raw CSV Schema (`artifacts/auth_zk_acl_class_metrics.csv`)

| Column | Description |
|--------|-------------|
| path | `auth_committed` or `auth_acl_class` |
| repeat_id | 0-based repeat index |
| num_vectors, dim, n_list, n_probe, slot_per_list, top_k | Workload shape |
| N_sel | `n_probe × slot_per_list` |
| N_acl | Unique ACL classes in this row |
| N_acl_max | Fixed class table size (= N_acl in this eval) |
| acl_ratio | `N_acl / N_sel` |
| visible_ratio | Fraction of valid slots visible under policy |
| build_time, prove_time, verify_time, proof_size, memory, gates | ZK metrics |

Each `(workload, N_acl, repeat_id)` produces **two rows** (one per path).

## Summary CSV Schema (`artifacts/auth_zk_acl_class_summary.csv`)

Aggregates by `(workload, N_acl, path)` with medians over repeats:

- `median_gates`, `median_prove_time`, `median_verify_time`, `median_proof_size`, `median_build_time`
- For `auth_acl_class` rows only:
  - `acl_vs_committed_gates`
  - `acl_vs_committed_prove_time`
  - `acl_vs_committed_proof_size`

## Plotting N_acl / N_sel

1. Load `artifacts/auth_zk_acl_class_summary.csv`.
2. Filter `path == auth_acl_class`.
3. X-axis: `acl_ratio` (or `N_acl`).
4. Y-axis: `acl_vs_committed_gates` (or median gates / prove_time).
5. Optional: separate lines per `(n_probe, slot_per_list)`.

Example (matplotlib):

```python
import pandas as pd
df = pd.read_csv("artifacts/auth_zk_acl_class_summary.csv")
acl = df[df.path == "auth_acl_class"]
acl.plot(x="acl_ratio", y="acl_vs_committed_gates", kind="line", marker="o")
```

## Expected Trend

1. **N_acl << N_sel**: `auth_acl_class` gates/prove_time **below** `auth_committed` — policy-once savings dominate.
2. **N_acl ≈ N_sel** (degenerate): ACL path may be **more expensive** — extra class table + binding structure without policy savings.
3. Ratio curve should be **monotonically informative**, not a single point.

## Observed Trend (repeat=1, n_probe=4, slot=64, N_sel=256)

| N_acl | committed gates | acl_class gates | acl/committed gates | prove_time ratio |
|-------|-----------------|-----------------|---------------------|------------------|
| 1 | 23583 | 22210 | 0.942 | 0.917 |
| 2 | 23583 | 22402 | 0.950 | 0.981 |
| 4 | 23583 | 22787 | 0.966 | 1.064 |
| 8 | 23583 | 23562 | 0.999 | 0.925 |
| 16 | 23583 | 25125 | 1.065 | 1.016 |
| 32 | 23583 | 28275 | 1.199 | 1.018 |
| 64 | 23583 | 34621 | 1.468 | 1.883 |

- **N_acl=1**: ~5.8% gate reduction vs committed.
- **N_acl=8**: roughly break-even on gates.
- **N_acl≥16**: ACL path more expensive (degenerate / overhead-dominated).

## Compression Trade-off (Not a Bug)

ACL-class compression saves **policy gadget** invocations (`N_sel → N_acl_max`) but adds:

- ACL class Merkle openings (`N_acl_max`)
- Object-to-class binding openings (per slot, still `N_sel`)

When `N_acl ≈ N_sel`, overhead can exceed savings. This is the expected **compression trade-off**.

## Limitations

- Synthetic IVF-PQ only; no real dataset embeddings.
- `repeat=1` in default run; use `--repeat 3` for paper medians.
- Tight `N_acl_max = N_acl`; fixed padding capacity not swept.
- Visibility mix: class 0 invisible when `N_acl ≥ 2`; not a full policy sweep.
- No modification to Rust proof logic or PyO3 API in this phase.

## Paper-ready Run

```bash
source "$HOME/.cargo/env"
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB
maturin develop --release

python scripts/bench_acl_class_paths.py \
  --repeat 3 \
  --n-probe-list 2,4 \
  --slot-per-list-list 64,128 \
  --n-acl-list 1,2,4,8,16,32,64,128 \
  --top-k-list 5 \
  --output artifacts/auth_zk_acl_class_metrics.csv

python scripts/summarize_acl_class_metrics.py \
  --input artifacts/auth_zk_acl_class_metrics.csv \
  --output artifacts/auth_zk_acl_class_summary.csv
```

## Next: Phase 6 Visibility-gated Scoring

1. Wire visibility-gated distance scoring into end-to-end retrieval API (beyond proof-carrying demo).
2. Evaluate recall/precision under partial visibility with ACL-class vs object-level views.
3. Optional: integrate `N_acl_max` padding sweep into benchmark for deployment-shaped cost models.
