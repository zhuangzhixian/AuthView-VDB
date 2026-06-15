# V3DB Code Map

Phase 0 reference for the imported V3DB baseline (tag `v3db-import-baseline`).
This document maps modules, call paths, and future AuthView-VDB integration points.
**No authorization-view features are implemented in the current codebase.**

---

## 1. Repository structure

| Path | Role | IVF-PQ | ZK proof | Benchmark | Python API |
|------|------|:------:|:--------:|:---------:|:----------:|
| `src/` | Rust `cdylib` (Plonky2 circuits, prove/verify) | ✓ | ✓ | — | via `lib.rs` |
| `ivf_pq/` | Python index build, query, Merkle helpers | ✓ | bridge | — | ✓ |
| `tests/` | End-to-end demos and accuracy smoke tests | ✓ | ✓ | partial | ✓ |
| `bench/` | Cached experiment orchestration (SIFT/GIST/MS MARCO) | ✓ | ✓ | ✓ | ✓ |
| `bench_free_bench/` | Synthetic micro-benchmarks for individual proof paths | — | ✓ | ✓ | ✓ |
| `scripts/` | Shell wrappers around `bench/` and `tests/` | ✓ | ✓ | ✓ | — |
| `vec_data_load/` | Dataset loaders (SIFT, MS MARCO, BUPT-CBFace) | ✓ | — | ✓ | ✓ |
| `data/` | Datasets and cached results (gitignored) | ✓ | ✓ | ✓ | — |
| `docs/` | AuthView-VDB research and phase plans | — | — | — | — |
| `Cargo.toml`, `pyproject.toml`, `rust-toolchain.toml` | Build and dependency config | — | — | — | ✓ |
| `.github/workflows/CI.yml` | CI pipeline | — | — | ✓ | — |
| `AGENTS.md` | Contributor guide | — | — | — | — |

### Package identity (unchanged from V3DB import)

- Rust crate: `zk-IVF-PQ` (`Cargo.toml`)
- Python module: `zk_IVF_PQ.zk_IVF_PQ` (maturin / pyo3)
- Core Python package: `ivf_pq/`

---

## 2. Architecture overview

V3DB implements verifiable IVF-PQ search in three tiers:

```
Python (ivf_pq/)          Rust (src/)
─────────────────         ─────────────────────────────────────────
index build    ────────►  (witness preparation only)
query + witness           ivf_pq / ivf_pq_verify     prover / verifier (witness-sorted)
                          circuit_ivf_pq             full in-circuit pipeline
                          merkle_ver/*               Merkle + set-based / circuit-based
                          merkle_commit              standalone Merkle tree proofs
                          brute_force, pq_flat*,     simpler baselines
                          ivf_flat*
```

**Production-style path (Merkle + set-based):** Python `ivf_pq/merkle_zk.py` builds
fixed-shape slot records and Merkle roots, then calls `py_set_based_with_merkle`.

**Lighter verify path (no Merkle):** Python `ivf_pq/zk.py` calls `py_ivf_pq_verify_proof`
with pre-merged candidate buffers.

---

## 3. Core pipeline: files and functions

### 3.1 Index building / IVF-PQ construction

| Step | Python | Notes |
|------|--------|-------|
| Layout reorder (`mod8`) | `ivf_pq/layout.py`: `apply_layout`, `build_modulo_permutation` | Optional dimension permutation before k-means |
| Coarse IVF k-means | `ivf_pq/util/kmeans.py`: `faiss_kmeans_with_ids` | FAISS k-means → `(centers, id_groups, labels)` |
| Cluster rebalancing / padding | `ivf_pq/rebalance.py`: `rebalance_clusters` | Caps cluster size under `cluster_bound`; used by ZK path |
| Residual PQ codebook training | `ivf_pq_learn` in `pipeline.py`, `standard.py`, `zk.py` | Per-subspace k-means over residuals |
| Fixed capacity (power-of-two) | `ivf_pq/zk.py`: `upperbound`; `merkle_zk.py`: `_build_cluster_capacity` | Determines slot count `n` per inverted list |

Three parallel `ivf_pq_learn` implementations:

| File | Output types | Used by |
|------|-------------|---------|
| `ivf_pq/pipeline.py` | int32 centers/codebooks | `tests/pipeline.py` (plain ANN demo) |
| `ivf_pq/standard.py` | float32 | `tests/standard.py` (non-ZK baseline) |
| `ivf_pq/zk.py` | int64 + optional rebalance | `tests/zk.py`, `merkle_zk.py` (ZK paths) |

### 3.2 Centroid distance computation

| Layer | File | Function |
|-------|------|----------|
| Python (native) | `ivf_pq/pipeline.py`, `zk.py`, `merkle_zk.py` | L2: `(center - query)²` summed over dims |
| Rust gadget | `src/utils/dis_gadgets.rs` | `l2`, `distance` |
| Rust NN proof | `src/utils/nn_gadgets.rs` | `static_nn_gadget` — proves witness `(cluster_idx, dist)` multiset matches computed distances |
| In-circuit sort | `src/circuit_ivf_pq/gadgets.rs`, `src/merkle_ver/circuit_based.rs` | Bubble sort over all centroid distances |

### 3.3 Probe selection (n_probe list selection)

| Layer | File | Function |
|-------|------|----------|
| Python | `ivf_pq_query` / `zk_ivf_pq_query` in all query modules | `argsort(dist2)[:n_probe]` |
| Rust (witness path) | `src/utils/nn_gadgets.rs` | `static_nn_gadget` — external sorted list verified |
| Rust (in-circuit) | `src/circuit_ivf_pq/gadgets.rs` | Bubble sort; first `n_probe` indices |
| Rust (set-based) | `src/merkle_ver/set_based.rs` | Probe indices from `cluster_idx_dis[i][0]` |

### 3.4 Inverted list / slot representation

Fixed-shape slots per selected cluster `(n_probe, n, ·)`:

| Field | Python construction | Rust leaf format |
|-------|--------------------|-----------------|
| `cluster_idx` | selected probe list | public in `merkle_cluster_gadget` |
| slot index `j` | `0..capacity-1` | leaf field |
| `valid` bit | `valids[probe][j]` — 1 if real vector, 0 if padding | `valids` |
| `item` (vector id) | `itemss[probe][j]` | `items` |
| PQ codes `vpqs` | `quant_vecs[vec_id]` | `vpqss[probe][j][m]` |

Key files:

- Python slot packing: `ivf_pq/merkle_zk.py` (`vpqss`, `valids`, `itemss`, `_compute_cluster_root`)
- Rust Merkle leaf: `src/merkle_ver/ivf_pq_merkle.rs` (`merkle_cluster_gadget`, `merkle_cluster_i64`)
- Rust IVF-level root: `merkle_ivf_gadget` — leaves `(i, c_i, root_i)`
- Codebook commitment: `commit_codebook_gadget` / `commit_codebook_i64`

**Note:** `ivf_pq/zk.py` uses an alternate pre-merged representation
(`extend_filtered_vecs`, `vecs_cluster_hot`) instead of per-probe slot arrays.

### 3.5 PQ code / codebook / LUT / ADC scoring

| Step | File | Function |
|------|------|----------|
| LUT build (ADC) | `src/pq_flat/gadgets.rs` | `codebooks_query_gadget` — `(M,K)` table of subspace L2 distances |
| Residual query | `src/ivf_pq/gadgets.rs` | `vec_sub_gadget` — `query - cluster_center` |
| PQ distance from codes | `src/pq_flat/gadgets.rs` | `lut_code_gadget` — sum LUT lookups by PQ indices |
| One-hot ADC (circuit path) | `src/circuit_ivf_pq/gadgets.rs` | `dot_prod_gadget` |
| Set-based ADC verify | `src/merkle_ver/set_based.rs` | `vpqss_dis` summed; `vpqss_set ⊆ lut_set` via `set_belong_gedget` |
| Native LUT precompute | `src/ivf_pq_verify/proof.rs` | `luts_gen_i64`, `dis_cal` |

Python ADC (native reference): `merkle_zk.py` lines building `curr_dis` from
`code_books[m, code_indices]` and `delta_query`.

### 3.6 Candidate enumeration

| Representation | Shape | File |
|----------------|-------|------|
| Per-probe slots | `(n_probe, n, M)` | `merkle_zk.py`, `merkle_ver/set_based.rs` |
| Pre-merged buffer | `(max_sz, M)` + cluster one-hot `(max_sz, n_probe)` | `ivf_pq/zk.py`, `src/ivf_pq/gadgets.rs` |
| In-circuit one-hot | `(n_probe, n, M, K)` | `src/circuit_ivf_pq/gadgets.rs` |

Candidate count is fixed: `N_sel = n_probe × n` where `n` is per-list capacity
(power of two ≥ max cluster size after rebalancing).

### 3.7 Valid-bit masking / padding handling

Invalid (padding) slots are demoted with a large distance sentinel:

| Path | Sentinel | File | Pattern |
|------|----------|------|---------|
| Set-based Merkle | `2^62 - 1` | `src/merkle_ver/set_based.rs` | `vld * dis + (1-vld) * max` |
| Circuit IVF-PQ | `2^63 - 1` | `src/circuit_ivf_pq/gadgets.rs` | `hot[i][j]` masks distance |
| IVF-PQ verify | `u32::MAX` | `src/ivf_pq/gadgets.rs` | `hor_sum * dis + (1-hor_sum) * MAX` |
| Python reference | `max_dis = (1<<62)-1` | `ivf_pq/merkle_zk.py` | applied when `valids == 0` |

Rebalancing ensures real vectors fit within `cluster_bound`; remaining slots are
padding with `valid=0`.

### 3.8 Final top-k selection

V3DB avoids in-circuit sorting for the main Merkle path:

| Path | Mechanism | File |
|------|-----------|------|
| Set-based (primary) | Witness provides sorted `(item, masked_dis)`; circuit checks multiset equality + non-decreasing order; top-k item IDs are public inputs | `src/merkle_ver/set_based.rs`: `set_equal_gadget`, `comp_gadget`, `register_public_input` |
| Circuit-based | In-circuit bubble sort over distances + item permutation | `src/circuit_ivf_pq/gadgets.rs`, `src/merkle_ver/circuit_based.rs` |
| IVF-PQ verify (no Merkle) | Pre-sorted witness in merged buffer | `src/ivf_pq_verify/gadgets.rs` |
| Brute-force baseline | In-circuit top-k | `src/brute_force/gadgets.rs`: `sort_brute_force_gadget` |

Public top-k outputs: `ordered_vpqss_item_dis[i][0]` for `i < top_k` in set-based path.

### 3.9 Snapshot commitment / Merkle commitment

Commitment hierarchy (V3DB):

```
root_mk  ← Merkle over (cluster_idx, centroid, cluster_merkle_root)
root_cb  ← hash of flattened PQ codebooks
com = (root_mk, root_cb)
```

| Component | File | Key functions |
|-----------|------|---------------|
| Poseidon hash / Merkle tree | `src/hash_gadgets.rs` | `hash_u64`, `merkle_tree_gadget`, `merkle_back_gadget`, `fs_oracle` |
| Cluster leaf commitment | `src/merkle_ver/ivf_pq_merkle.rs` | `merkle_cluster_gadget`, `merkle_cluster_i64` |
| IVF + codebook roots | same | `merkle_ivf_gadget`, `commit_codebook_gadget` |
| Full commitment verify | `src/merkle_ver/standalone_commitment.rs` | `standalone_commitment_gadget`, `commitment_relevant_gen` |
| Standalone Merkle bench | `src/merkle_commit/` | `merkle_commit_gadget`, `merkle_commit_proof` |
| Python root builder | `ivf_pq/merkle_zk.py` | `_compute_cluster_root`; `tests/zk_ver.py`: `merkle_build` |

### 3.10 Proof generation and verification

| Module | Entry function | Python binding | Description |
|--------|---------------|----------------|-------------|
| `ivf_pq/proof.rs` | `ivf_pq_proof` | `py_ivf_pq_proof` | Prover: witness-sorted merged candidates |
| `ivf_pq_verify/proof.rs` | `ivf_pq_verify_proof` | `py_ivf_pq_verify_proof` | Verifier: + LUT set membership |
| `circuit_ivf_pq/proof.rs` | `circuit_ivf_pq_proof` | `py_circuit_ivf_pq_proof` | Full in-circuit pipeline |
| `merkle_ver/set_based_proof.rs` | `set_based_ivf_pq_proof` | `py_set_based_with_merkle` / `_without_merkle` | **Primary production path** |
| `merkle_ver/circuit_based_proof.rs` | `circuit_based_ivf_pq_proof` | `py_circuit_based_with_merkle` / `_without_merkle` | Circuit + optional Merkle |
| `merkle_ver/standalone_commitment.rs` | `standalone_commitment_proof` | `py_standalone_commitment` | Commitment-only proof |
| `merkle_commit/proof.rs` | `merkle_commit_proof` | `py_merkle_commit_proof` | Generic Merkle tree |
| `ivf_flat_verify/proof.rs` | `ivf_flat_verify_proof` | `py_ivf_flat_verify_proof` | IVF-flat + top-k verify |
| `pq_flat_verify/proof.rs` | `pq_flat_verify_proof` | `py_pq_flat_verify_proof` | PQ-flat + LUT verify |
| `brute_force/proof.rs` | `brute_force_proof`, `sort_brute_force_proof` | `py_brute_force_proof`, `py_sort_brute_force_proof` | Exhaustive baselines |

Shared utilities:

- `src/utils/set_gadgets.rs`: `set_equal_gadget`, `set_belong_gedget` (multiset checks)
- `src/utils/metrics.rs`: `metrics_eval` (timing, memory, gate count)
- `src/prelude.rs`: Plonky2 builder helpers

All proof entry points are registered in `src/lib.rs` → `zk_IVF_PQ` pymodule.

---

## 4. End-to-end execution paths

### 4.1 Minimal plain ANN (no ZK, no Rust extension)

```
vec_data_load/sift.py:SIFT
  → ivf_pq/pipeline.py:ivf_pq_learn
  → ivf_pq/pipeline.py:ivf_pq_query
  → compare with gt_vecs (IoU)
```

**Entry:** `python tests/pipeline.py`  
**Requires:** `data/siftsmall/` (SIFT vectors), numpy, faiss, sklearn

### 4.2 Minimal ZK verify (no Merkle, lighter Rust path)

```
SIFT → ivf_pq/zk.py:ivf_pq_learn
     → ivf_pq/zk.py:zk_ivf_pq_query
         → builds sorted_idx_dis, extend_filtered_vecs, vecs_cluster_hot
         → py_ivf_pq_verify_proof (Rust ivf_pq_verify)
```

**Entry:** `python tests/zk.py`  
**Requires:** maturin-built `zk_IVF_PQ`, `data/siftsmall/`

### 4.3 Full Merkle ZK path (recommended V3DB demo)

```
SIFT → ivf_pq/merkle_zk.py:ivf_pq_learn (from zk.py)
     → ivf_pq/merkle_zk.py:zk_ivf_pq_query(proof=True)
         → build vpqss/valids/itemss per slot
         → compute ivf_roots (all clusters)
         → py_set_based_with_merkle (Rust set_based_ivf_pq_proof)
```

**Entry:** `python tests/merkle_zk.py`  
**Requires:** maturin-built `zk_IVF_PQ`, rescaling helpers from `ivf_pq/__init__.py`

### 4.4 Early verify demo (partial pipeline)

```
SIFT → ivf_pq/pipeline.py:ivf_pq_learn
     → tests/zk_ver.py:zk_ivf_pq_query (local)
         → verify_ids_sorted_by_distance (Rust NN gadget)
         → manual candidate scoring (no full proof in early version)
```

**Entry:** `python tests/zk_ver.py`

### 4.5 Synthetic Rust micro-benchmark (no dataset)

```
bench_free_bench/ivf_pq_verify.py → py_ivf_pq_verify_proof (random data)
bench_free_bench/set_based_gate.py → py_set_based_gate (gate count only)
```

**Entry:** `python bench_free_bench/ivf_pq_verify.py`  
Useful when datasets are unavailable.

### 4.6 Performance benchmark suite

```
scripts/bench_suite.sh
  → maturin develop --release
  → python -m bench.bench_suite
  → caches under data/bench_result/
```

---

## 5. Benchmark and experiment scripts

| Script | Invokes | Output dir |
|--------|---------|------------|
| `scripts/bench_suite.sh` | `bench.bench_suite` | `data/bench_result/` |
| `scripts/acc_bench.sh` | `tests.acc_bench` | `data/acc_bench/` |
| `scripts/ms_macro_eval.sh` | `bench.ms_macro_eval` | `data/exp1/` |
| `scripts/optimal_config.sh` | `bench.optimal_config` | `data/optimal_config/` |
| `scripts/gate_count.sh` | `bench/gate_count.py` | stdout |
| `scripts/default_bench.sh` | `bench_free_bench/*` | stdout |
| `scripts/merkle_scale1m.sh` | set-based @ N=1M | — |

Key bench modules: `bench/set_based.py`, `bench/circuit_based.py`,
`bench/commitment_eval.py`, `bench/acc_bench.py`, `bench/ms_macro_eval.py`.

---

## 6. Data paths

| Dataset | Expected path | Used by |
|---------|--------------|---------|
| SIFT small | `data/siftsmall/` | Most `tests/*` demos |
| SIFT 1M | `data/sift/` | `acc_bench`, `faiss_opq_bench` |
| GIST 1M | `data/gist/` | `acc_bench` |
| MS MARCO | `data/msmacro/` | `msmacro_*`, `bench/ms_macro_*` |
| BUPT-CBFace | `data/BUPT-CBFace-{12,50}/` | `bench/bio_metric.py` |

The `data/` directory is gitignored. Demos fail without downloaded datasets.

---

## 7. Future AuthView-VDB integration points

Analysis only — **not implemented**.

### 7.1 Authorization state record

| Location | Rationale |
|----------|-----------|
| `ivf_pq/merkle_zk.py` slot construction loop | Extend leaf record beyond `(cluster_idx, j, valid, item, vpqs)` with auth fields (tenant, project, clearance, ACL class, epoch) |
| `src/merkle_ver/ivf_pq_merkle.rs` `merkle_cluster_gadget` | Mirror extended leaf hash in circuit |
| New `rec_auth_{i,j}` structure | Parallel to content slot; bound via `cid` |

### 7.2 root_auth / checkpoint binding

| Location | Rationale |
|----------|-----------|
| `src/merkle_ver/standalone_commitment.rs` | Currently binds `root_mk + root_cb`; extend public inputs with `root_auth`, `policyID`, checkpoint `σ` |
| `src/merkle_ver/set_based.rs` public inputs | Add `CP_σ` tuple to prover/verifier interface |
| `src/lib.rs` pyo3 wrappers | Propagate new public inputs to Python callers |
| `ivf_pq/merkle_zk.py` | Compute and pass `root_auth` alongside `ivf_roots` |

### 7.3 Candidate visibility computation

| Location | Rationale |
|----------|-----------|
| New auth policy gadget (future `src/auth/` or `utils/`) | Implement `v_x = P(γ_U, λ_x, σ)` |
| `src/merkle_ver/set_based.rs` Step 3 (vpqss_item_dis loop) | After opening auth record, compute visibility bit per slot |
| `ivf_pq/merkle_zk.py` query path | Plaintext reference for visibility before ZK integration |

### 7.4 Visibility mask

| Location | Rationale |
|----------|-----------|
| `src/merkle_ver/set_based.rs` lines 92–96 | **Primary template**: existing `valids` mask pattern `vld * dis + (1-vld) * max` extends naturally to `valid * visibility * dis + ...` |
| `src/ivf_pq/gadgets.rs` `hor_sum` masking | Same pattern in merged-candidate path |
| `src/circuit_ivf_pq/gadgets.rs` `hot[i][j]` | In-circuit variant |

### 7.5 Authorized masked distance

| Location | Rationale |
|----------|-----------|
| `src/merkle_ver/set_based.rs` | Replace or extend `vpqss_item_dis` computation: `D̂ = valid · (v · d̃ + (1-v) · d_max) + (1-valid) · d_max` |
| `src/merkle_ver/set_based.rs` `set_equal_gadget` input | Sorted witness must use masked distances |
| `ivf_pq/merkle_zk.py` native scoring loop | Plaintext reference for authorized distances |

### 7.6 Authorized top-k

| Location | Rationale |
|----------|-----------|
| `src/merkle_ver/set_based.rs` lines 99–120 | Top-k public inputs and sort-order checks must use authorized sort keys |
| `src/merkle_ver/circuit_based.rs` | In-circuit sort path if retained |
| `src/ivf_pq_verify/gadgets.rs` | Lighter verify path top-k |

### 7.7 cid / slot alignment checks

| Location | Rationale |
|----------|-----------|
| `src/merkle_ver/ivf_pq_merkle.rs` | Add `cid` to content leaf; separate auth leaf with matching `cid` |
| `src/merkle_ver/standalone_commitment.rs` | Verify `cid_content == cid_auth` when opening paired records |
| `ivf_pq/merkle_zk.py` | Populate `cid` in slot records during index build |

### 7.8 Slot-aligned auth commitment

| Location | Rationale |
|----------|-----------|
| `ivf_pq/merkle_zk.py` `_compute_cluster_root` | Add parallel `_compute_cluster_auth_root` per list |
| `src/merkle_ver/ivf_pq_merkle.rs` | New `merkle_cluster_auth_gadget` with same `(cluster_idx, j)` indexing |
| `src/merkle_ver/standalone_commitment.rs` | Batch-open auth subtree when selected list opens |
| ACL-class compression (future) | Dynamic auth state keyed by ACL class rather than per-cid; reduces Merkle openings |

### Integration priority (suggested)

1. Plaintext auth reference in Python (`merkle_zk.py` scoring loop)
2. Extend slot record + Merkle leaf format
3. Visibility mask in `set_based.rs` distance computation
4. Authorized top-k via existing `set_equal_gadget` path
5. Separate `root_auth` + checkpoint public inputs
6. Slot-aligned auth commitment optimization

---

## 8. Module quick-reference

### Rust `src/` modules

| Module | Purpose |
|--------|---------|
| `ivf_pq`, `ivf_pq_verify` | Witness-sorted IVF-PQ prover/verifier |
| `circuit_ivf_pq` | Full in-circuit IVF-PQ |
| `merkle_ver/` | Merkle-augmented IVF-PQ (set-based, circuit-based, standalone) |
| `merkle_commit` | Generic Merkle commitment proofs |
| `ivf_flat`, `ivf_flat_verify` | IVF without PQ |
| `pq_flat`, `pq_flat_verify`, `pq_flat_com` | PQ without IVF |
| `brute_force` | Exhaustive search baseline |
| `commit_eval` | FRI vs Merkle commitment benchmarks |
| `utils/` | Distance, NN, set, lookup, metrics gadgets |
| `hash_gadgets.rs` | Poseidon hash and Merkle tree |

### Python `ivf_pq/` modules

| Module | Purpose |
|--------|---------|
| `pipeline.py` | Plain int32 IVF-PQ |
| `standard.py` | Float32 baseline |
| `zk.py` | ZK-oriented int64 + `py_ivf_pq_verify_proof` |
| `merkle_zk.py` | Merkle + `py_set_based_with_merkle` |
| `rebalance.py` | Fixed-shape cluster sizing |
| `layout.py` | Dimension reorder |
| `baseline.py` | FAISS IVFPQ wrapper |

---

## 9. Related documents

- [research_scope.md](research_scope.md) — AuthView-VDB research problem
- [phase0_plan.md](phase0_plan.md) — Phase 0 tasks and deliverables
- [phase0_environment_notes.md](phase0_environment_notes.md) — toolchain and runtime prerequisites
