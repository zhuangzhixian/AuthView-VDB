# Phase 0 Plan: V3DB Code Mapping

Phase 0 establishes that the imported V3DB baseline is a usable foundation and
produces a code map for future authorization-view integration. **Phase 0 is
read-only with respect to core implementation**: no changes to proof logic,
indexing, benchmarks, or build scripts.

## Objectives

1. Confirm the imported baseline builds and can run a minimal proof demo.
2. Map V3DB modules for index building, commitment, query semantics, and
   verification.
3. Identify integration points for authorization-view semantics.
4. Record baseline metrics for later comparison.

## Prerequisites check

- [ ] Confirm upstream license and attribution (see
      [ACKNOWLEDGEMENTS.md](../ACKNOWLEDGEMENTS.md)).
- [ ] Record dependency versions: Plonky2 1.1.0, pyo3 0.25.0 (from
      `Cargo.toml` / `pyproject.toml`).
- [ ] Verify Rust toolchain via `rust-toolchain.toml`.
- [ ] Install Python extension: `maturin develop --release`.

## Module mapping tasks

### 1. Index building and shaping

| Concern | Starting paths |
|---------|----------------|
| IVF-PQ layout, rebalancing, padding | `ivf_pq/layout.py`, `ivf_pq/rebalance.py`, `ivf_pq/pipeline.py` |
| Python orchestration | `ivf_pq/main.py`, `ivf_pq/standard.py`, `ivf_pq/baseline.py` |
| Data loading | `vec_data_load/`, `tests/data_load.py` |

**Future auth integration notes:** slot records, chunk-id fields, static ACL
labels, and fixed-shape list capacity are the likely extension points.

### 2. Snapshot commitment

| Concern | Starting paths |
|---------|----------------|
| Merkle commitment circuits | `src/merkle_commit/`, `src/merkle_ver/` |
| Standalone / set-based commitment | `src/merkle_ver/standalone_commitment.rs`, `src/merkle_ver/set_based*.rs` |
| Commitment evaluation | `src/commit_eval/` |
| Python Merkle helpers | `ivf_pq/merkle_zk.py`, `tests/merkle_zk.py` |

**Future auth integration notes:** separate or slot-aligned `root_auth`,
checkpoint tuple binding, content/auth root consistency checks.

### 3. Query semantics: centroid distance and probe selection

| Concern | Starting paths |
|---------|----------------|
| IVF-PQ proof (centroid + probe) | `src/ivf_pq/`, `src/ivf_pq_verify/` |
| Circuit variants | `src/circuit_ivf_pq/`, `src/merkle_ver/ivf_pq_merkle.rs` |
| Distance gadgets | `src/utils/dis_gadgets.rs`, `src/utils/nn_gadgets.rs` |

**Future auth integration notes:** probe selection and list coverage proofs
should remain unchanged; auth binds at candidate-slot level.

### 4. ADC / PQ scoring

| Concern | Starting paths |
|---------|----------------|
| PQ flat proofs | `src/pq_flat/`, `src/pq_flat_verify/`, `src/pq_flat_com/` |
| Lookup gadgets | `src/utils/lookup.rs`, `src/pq_flat/gadgets.rs` |
| IVF-flat variants | `src/ivf_flat/`, `src/ivf_flat_verify/` |

**Future auth integration notes:** visibility-gated scoring wraps PQ distance
outputs; valid-bit masking pattern in V3DB is a template for visibility mask.

### 5. Top-k selection and verification

| Concern | Starting paths |
|---------|----------------|
| Top-k / sorting gadgets | `src/utils/set_gadgets.rs`, `src/brute_force/` |
| Full IVF-PQ verify path | `src/ivf_pq_verify/proof.rs` |
| Multiset equality / inclusion | `src/merkle_ver/circuit_based*.rs`, `src/utils/common_gadgets.rs` |
| Boundary checks | trace through `ivf_pq_verify` and `merkle_ver` proof modules |

**Future auth integration notes:** primary modification target for authorized
top-k; document exact sort-key and boundary-check conventions before changing.

### 6. Proof generation and verifier entry points

| Concern | Starting paths |
|---------|----------------|
| Python API surface | `src/lib.rs` (pyo3 exports) |
| End-to-end pipelines | `tests/pipeline.py`, `tests/zk.py`, `tests/zk_ver.py` |
| Benchmark drivers | `bench/`, `bench_free_bench/`, `scripts/bench_suite.sh` |

### 7. Gate count and performance baselines

| Concern | Starting paths |
|---------|----------------|
| Gate estimation | `scripts/gate_count.sh`, `bench/gate_count.py` |
| Proof cost suite | `scripts/bench_suite.sh`, `bench/bench_suite.py` |
| Accuracy benchmarks | `scripts/acc_bench.sh`, `tests/acc_bench.py` |

## Minimal reproduction target

Run at least one end-to-end proof generation and verification path. Suggested
starting points (choose the lightest that succeeds in your environment):

1. `cargo build --release`
2. `maturin develop --release`
3. `python tests/pipeline.py` or a targeted script under `tests/`

Record for the baseline:

- proving time
- verification time
- proof size
- peak memory
- gate count (if available)
- parameter settings (`n_list`, `n_probe`, `M`, `K`, `top_k`, etc.)

## Deliverables

| Artifact | Description |
|----------|-------------|
| `docs/v3db_code_map.md` | Module-by-module map with call flows and data structures |
| `artifacts/v3db_reproduce_metrics.csv` | Baseline timing/size/memory measurements |
| Modification-point checklist | Where auth visibility, checkpoint binding, and authorized top-k would attach |

## Exit criteria

Phase 0 is complete when:

1. At least one V3DB proof can be generated and verified reproducibly.
2. `docs/v3db_code_map.md` identifies locations for candidate scoring, valid-bit
   masking, and final top-k selection.
3. A short checklist maps each planned auth concept (visibility mask, checkpoint
   binding, slot-aligned auth) to concrete files/functions—without modifying
   those files yet.

## Explicit non-goals (Phase 0)

- Implement authorization-view proofs or plaintext auth reference semantics.
- Modify Rust circuits, Python index builders, or benchmark scripts.
- Rename crates, packages, or top-level directories.
- Commit local reference notes or PDFs kept outside version control.

## Suggested timeline

| Step | Duration | Output |
|------|----------|--------|
| Environment + build verification | 1–2 days | build log, dependency notes |
| Module tracing | 3–5 days | `docs/v3db_code_map.md` draft |
| Minimal proof demo + metrics | 1–2 days | `artifacts/v3db_reproduce_metrics.csv` |
| Integration-point checklist | 1 day | auth extension map in code map doc |
