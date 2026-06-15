# AuthView-VDB

Independent research prototype for **proof-carrying vector search over
committed authorization views**.

## Status

This repository begins from the **V3DB baseline** (tag: `v3db-import-baseline`).
The current code implements V3DB-style verifiable IVF-PQ search over committed
snapshots. **Authorization-view proof features are planned extensions** and are
**not implemented** in this baseline.

## Research goal

Extend V3DB-style verifiable IVF-PQ search so that a service can prove its
returned top-k equals the result of a declared ANN retrieval program executed
over the **current user's committed authorization view**—not merely that each
returned object is individually authorized.

See [docs/research_scope.md](docs/research_scope.md) for the research problem
and [docs/phase0_plan.md](docs/phase0_plan.md) for the next engineering phase.

## Inherited from V3DB

The baseline code, build flow, and experiments below come from V3DB. For
attribution and citation, see [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md).

Implementation details are provided in the V3DB
[technical note](Technical_Details_of_V3DB.pdf).

### Build

Build and install the Python extension:

```bash
maturin develop --release
```

Rust-only build: `cargo build --release`

### Experiment 1: Retrieval Utility Evaluation

#### Classic ANN (SIFT1M / GIST1M)

```bash
bash scripts/acc_bench.sh
```

Results are cached under `data/acc_bench/`.

#### IR (MS MARCO passage retrieval, dev)

```bash
python -m bench.ms_macro_eval \
  --num-runs 1 \
  --n-list 8192 \
  --n-probe 64 \
  --M 8 \
  --K 256 \
  --cluster-bound 2048 \
  --top-k 1000 \
  --out-dir data/exp1/ms_macro_high_acc

python -m bench.ms_macro_eval \
  --num-runs 1 \
  --n-list 2048 \
  --n-probe 16 \
  --M 8 \
  --K 256 \
  --cluster-bound 8192 \
  --top-k 1000 \
  --out-dir data/exp1/ms_macro_zk_fast

python -m bench.ms_macro_result data/exp1/ms_macro_high_acc data/exp1/ms_macro_zk_fast
```

### Experiment 2: Proof Cost Evaluation

```bash
bash scripts/bench_suite.sh
```

### Experiment 3: Configuration Trade-offs

```bash
bash scripts/optimal_config.sh
bash scripts/optimal_mem_gate_only_ann_ir.sh
```

## Repository layout

| Path | Role |
|------|------|
| `src/` | Rust ZK circuits and proof logic (Plonky2) |
| `ivf_pq/` | Python IVF-PQ index building and pipelines |
| `tests/`, `bench/`, `bench_free_bench/` | Tests and benchmarks |
| `scripts/` | Experiment shell scripts |
| `docs/` | AuthView-VDB research and phase plans |
