# Phase 0 Environment Notes

Recorded during V3DB code mapping on branch `phase0-v3db-code-map`.
These notes describe what is needed to run demos; **no dependencies were
installed during Phase 0 documentation work.**

---

## Toolchain requirements

| Component | Source | Version / setting |
|-----------|--------|-------------------|
| Rust | `rust-toolchain.toml` | **nightly** channel; components: `rustfmt`, `clippy` |
| Rust crate | `Cargo.toml` | `zk-IVF-PQ` 0.1.0, edition 2021 |
| Plonky2 | `Cargo.toml` | 1.1.0 |
| pyo3 | `Cargo.toml` | 0.25.0 |
| maturin | `pyproject.toml` | >=1.9, <2.0 |
| Python | `pyproject.toml` | >=3.8 |

### Python dependencies (implicit, from imports)

- `numpy`
- `faiss` (k-means / index building)
- `sklearn` (via `ivf_pq/util/kmeans.py`)
- `tqdm` (ZK training progress)
- Optional: `matplotlib` (bench summary plots), `duckdb` (MS MARCO)

---

## Current environment status (mapping session)

| Check | Result |
|-------|--------|
| `cargo` / `rustc` | **Not found** in PATH |
| `maturin` | **Not found** in PATH |
| `python3` | 3.10.12 — available |
| `import zk_IVF_PQ` | **ModuleNotFoundError** — extension not built |
| `data/siftsmall/` | **Missing** — dataset not present locally |

---

## Recommended setup (when ready to reproduce)

```bash
# 1. Install Rust nightly (matches rust-toolchain.toml)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup component add rustfmt clippy --toolchain nightly

# 2. Python env + maturin
pip install maturin numpy faiss-cpu scikit-learn tqdm

# 3. Build extension
cd /home/zhixian/AuthView-VDB
maturin develop --release

# 4. Download SIFT small dataset into data/siftsmall/
#    (siftsmall_base.fvecs, siftsmall_query.fvecs,
#     siftsmall_groundtruth.ivecs, siftsmall_learn.fvecs)
```

---

## Recommended demo commands (lightest first)

Run in order; stop if a step fails due to missing deps or data.

| Priority | Command | What it validates |
|:--------:|---------|-------------------|
| 1 | `cargo build --release` | Rust compilation only |
| 2 | `python tests/rust_part.py` | `single_hash` pyo3 binding |
| 3 | `python tests/pipeline.py` | Plain IVF-PQ (no Rust extension needed) |
| 4 | `python tests/zk.py` | ZK verify path (`py_ivf_pq_verify_proof`) |
| 5 | `python tests/merkle_zk.py` | Full Merkle + set-based proof |
| 6 | `python bench_free_bench/ivf_pq_verify.py` | Synthetic proof micro-bench (no dataset) |

**Avoid in Phase 0:** `scripts/bench_suite.sh`, `scripts/acc_bench.sh`,
`scripts/ms_macro_eval.sh` — these are heavy and require full datasets.

---

## CI reference

`.github/workflows/CI.yml` defines the upstream expected build/test flow.
Consult it for the canonical dependency install and test sequence.

---

## Baseline metrics to capture (after reproduction)

When the environment is ready, record in `artifacts/v3db_reproduce_metrics.csv`:

- proving time, verification time, proof size
- peak memory, gate count
- parameters: `n_list`, `n_probe`, `M`, `K`, `top_k`, `cluster_bound`
- which entry point was used (`tests/zk.py` vs `tests/merkle_zk.py`)

See [phase0_plan.md](phase0_plan.md) for full deliverable checklist.
