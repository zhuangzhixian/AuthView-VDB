# V3DB Baseline Reproduction Log

Phase 0B environment setup and minimal reproduction on branch `phase0-v3db-reproduce`.
Recorded: 2026-06-15.

---

## Environment summary

| Item | Value |
|------|-------|
| OS | Linux 6.8.0-124-generic (x86_64) |
| Repository | `/home/zhixian/AuthView-VDB` |
| Python venv | `.venv/` (local, gitignored) |
| Rust install method | `rustup` to `$HOME/.cargo` (no sudo) |
| Dataset | `data/siftsmall/` **not available** (TEXMEX download timed out) |

### Toolchain versions

| Tool | Version |
|------|---------|
| Python | 3.10.12 |
| pip | 26.1.2 |
| rustc | 1.98.0-nightly (3daae5e42 2026-06-14) |
| cargo | 1.98.0-nightly (fe63976b2 2026-06-11) |
| Rust channel | nightly (from `rust-toolchain.toml`) |
| maturin | 1.14.0 |
| zk-IVF-PQ (Python) | 0.1.0 (editable install via maturin) |
| Plonky2 | 1.1.0 (from `Cargo.toml`) |
| numpy | 2.2.6 |
| faiss-cpu | 1.14.3 |
| scikit-learn | 1.7.2 |
| duckdb | 1.5.3 (installed for `vec_data_load/sift.py`) |

---

## Build commands attempted

| Step | Command | Status | Notes |
|------|---------|--------|-------|
| 1 | `rustc --version` / `cargo --version` | **PASS** | After sourcing `$HOME/.cargo/env` |
| 2 | `cargo build --release` | **PASS** | ~62 s; 138 warnings, no errors |
| 3 | `maturin develop --release` | **PASS** | ~11 s total; wheel installed into `.venv` |
| 4 | `python3 -c "import zk_IVF_PQ"` | **PASS** | Module loads from venv site-packages |

### Build environment setup performed

```bash
# Rust (one-time)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
  --default-toolchain nightly --component rustfmt --component clippy
source "$HOME/.cargo/env"

# Python venv + deps
python3 -m venv .venv
source .venv/bin/activate
pip install maturin numpy scikit-learn tqdm faiss-cpu duckdb

# Build
cargo build --release
maturin develop --release
```

Always activate before running demos:

```bash
source "$HOME/.cargo/env"
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB   # required for vec_data_load / ivf_pq imports
```

---

## Demo commands attempted

| Priority | Command | Status | Elapsed | Notes |
|:--------:|---------|--------|---------|-------|
| — | `python tests/rust_part.py` | **PASS** | ~0.06 s | `single_hash` smoke test |
| — | `py_set_based_gate(...)` via Python | **PASS** | ~40 s | Returned gate count 1,192,997 |
| 4 | `python bench_free_bench/ivf_pq_verify.py --N 256 --n_list 32 --n_probe 4` | **PARTIAL** | ~5.5 s | Circuit built and ran; verification returned `False` (witness/partition mismatch) |
| — | `python ivf_pq/merkle_zk.py` (module `__main__`) | **PASS** | ~13 s | Full Merkle + set-based proof on random int64 data |
| — | `python ivf_pq/zk.py` (`__main__`) | **FAIL** | ~1 s | `TypeError`: codebooks float32 passed to Rust int64 API |
| 1 | `python tests/pipeline.py` | **SKIP** | — | Requires `data/siftsmall/` + `PYTHONPATH=.` |
| 2 | `python tests/zk.py` | **SKIP** | — | Requires `data/siftsmall/` |
| 3 | `python tests/merkle_zk.py` | **SKIP** | — | Requires `data/siftsmall/` |

### Successful Merkle ZK proof (synthetic data)

Command: `PYTHONPATH=. python ivf_pq/merkle_zk.py`

Parameters (from module `__main__`): `N=10000`, `D=128`, `n_list=32`, default `n_probe=8`, `proof=True`.

Rust `py_set_based_with_merkle` returned:

| Metric | Value |
|--------|-------|
| build_time (s) | 6.253 |
| prove_time (s) | 2.301 |
| verify_time (s) | 0.006 |
| proof_size (bytes) | 195,220 |
| peak_memory (bytes) | 5,383,872,512 |
| gate_count | 89,496 |

Top-k indices printed successfully (16 shown).

### bench_free_bench/ivf_pq_verify.py failure detail

```
error: Partition containing Wire(...) was set twice with different values:
  13835058055282159173 != 4611686018427383365
ivf pq verify
False
```

Likely cause: synthetic random witness in the micro-bench script does not satisfy
circuit constraints (distance/LUT consistency). This is a bench-script witness
issue, not a build failure.

---

## Dataset requirements (for SIFT-based demos)

Place under `data/siftsmall/` (TEXMEX format):

| File | Format |
|------|--------|
| `siftsmall_base.fvecs` | Base vectors |
| `siftsmall_query.fvecs` | Query vectors |
| `siftsmall_groundtruth.ivecs` | Ground-truth neighbors |
| `siftsmall_learn.fvecs` | Learn set (optional for loader) |

Source: http://corpus-texmex.irisa.fr/siftsmall/

Download attempt on 2026-06-15 timed out (curl exit 28); directory remains empty.

---

## Artifacts not committed

The following were created locally and must **not** be committed:

- `.venv/`
- `target/` (Rust build output)
- `data/` (gitignored)
- Python egg-info / `.so` under site-packages

---

## Next required actions

1. **Download SIFT small** into `data/siftsmall/` (manual or retry with longer curl timeout).
2. **Run SIFT demos** with `PYTHONPATH=.`:
   - `python tests/pipeline.py`
   - `python tests/zk.py`
   - `python tests/merkle_zk.py`
3. **Investigate** `bench_free_bench/ivf_pq_verify.py` witness construction if used as regression check (optional; do not modify core source without cause).
4. **Record SIFT-based metrics** in `artifacts/v3db_reproduce_metrics.csv` after dataset is available.
5. Add `source .venv/bin/activate && export PYTHONPATH=.` to local workflow notes or a thin wrapper script (future docs only; no source changes in Phase 0B).

---

## Related documents

- [v3db_code_map.md](v3db_code_map.md)
- [phase0_environment_notes.md](phase0_environment_notes.md)
- [phase0_plan.md](phase0_plan.md)
