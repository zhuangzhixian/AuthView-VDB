# Phase 8A: Public Benchmark Dataset Inventory

**Phase:** 8A  
**Status:** Dataset audit and V3DB pipeline alignment (no download, no index build, no proof)  
**Companion:** [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md), [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md), [phase8_dataset_storage_plan.md](phase8_dataset_storage_plan.md)

**Artifact:** `artifacts/public_benchmark_inventory.md` (machine-generated; do not commit large data or local inventory to git)

---

## 1. Phase 8A goals

| Goal | This phase | Deferred |
|------|------------|----------|
| Inventory local SIFT1M / GIST1M / MS MARCO files | Yes | — |
| Align AuthView public eval with V3DB benchmark configs | Yes | — |
| Estimate storage and directory layout | Yes | — |
| Download datasets | No | Phase 8B |
| Build IVF-PQ indexes | No | Phase 8B / D1-A |
| Run proof or acc_bench | No | D1-B onward |
| Modify Rust/PyO3 | No | — |

Phase 8A establishes **what we have**, **what V3DB expects**, and **where to put data** before Stage D1 (public dataset utility + sampled ZK).

---

## 2. V3DB pipeline alignment summary

AuthView inherits V3DB’s public benchmark entry points. AuthView Stage D1 should reuse the same index shapes and data paths so RQ1 utility numbers are comparable to the V3DB-shaped baseline.

### 2.1 SIFT1M / GIST1M — `scripts/acc_bench.sh`

| Item | Value |
|------|-------|
| Entry script | `bash scripts/acc_bench.sh` |
| Python module | `python -m tests.acc_bench` (also `bench/acc_bench.py`) |
| Data loader | `vec_data_load/sift.py` — expects folder named after prefix |
| Expected paths | `data/sift/` (SIFT1M), `data/gist/` (GIST1M) |
| Required files per folder | `{prefix}_base.fvecs`, `{prefix}_query.fvecs`, `{prefix}_groundtruth.ivecs` |
| Common IVF-PQ params | `M=8`, `K=256`, `top_k=100`, `--report-ks 10,50`, `--scale-n 65536` |
| Result cache | `data/acc_bench/` |

**Configuration profiles (Experiment 1 / Classic ANN):**

| Profile | SIFT1M | GIST1M |
|---------|--------|--------|
| **high-acc** | `n_list=8192`, `n_probe=64`, `cluster_bound=256` | same |
| **zk-opt** | `n_list=1024`, `n_probe=8`, `cluster_bound=2048` | `n_list=512`, `n_probe=4`, `cluster_bound=4096` |

Notes from `scripts/acc_bench.sh`:

- `top_k=100` is fixed because bundled ground truth is top-100 only.
- `recall@500` still works via `--report-ks` (legacy hit-style semantics).

### 2.2 MS MARCO passage/dev — `bench.ms_macro_eval`

| Item | Value |
|------|-------|
| Entry | `python -m bench.ms_macro_eval` (see `README.md`, `scripts/ms_macro_eval.sh`) |
| Loader | `vec_data_load/ms_macro_load.py` |
| Expected paths | `data/msmacro/collection.duckdb`, `data/msmacro/queries.dev.duckdb`, `data/msmacro/qrels.dev.tsv` |
| Optional cache | `data/msmacro/cache/` (embeddings) |
| Result cache | `data/exp1/ms_macro_high_acc`, `data/exp1/ms_macro_zk_fast` |
| Aggregation | `python -m bench.ms_macro_result` |

**Configuration profiles:**

| Profile | Parameters |
|---------|------------|
| **high-acc** | `n_list=8192`, `n_probe=64`, `M=8`, `K=256`, `cluster_bound=2048`, `top_k=1000` |
| **zk-fast** | `n_list=2048`, `n_probe=16`, `M=8`, `K=256`, `cluster_bound=8192`, `top_k=1000` |

MS MARCO dev set: ~6,980 queries with qrels (V3DB uses dev split; not train/eval full sets).

### 2.3 AuthView D1 mapping

| V3DB step | AuthView D1 extension (planned) |
|-----------|----------------------------------|
| Plaintext IVF-PQ utility (`acc_bench`) | D1-B unrestricted utility |
| Same index + content-only ZK path | D1-D V3DB-shaped baseline |
| — | D1-C authorized reference + ACL overlay |
| Sampled ZK on subset | D1-E (100–500 queries per dataset) |

---

## 3. Local scan results (2026-06-18)

**Scanner:** `PYTHONPATH=. python scripts/inspect_public_benchmark_data.py --output artifacts/public_benchmark_inventory.md`

**Roots scanned:**

- `/home/zhixian/AuthView-VDB/data` — empty (no benchmark files)

**Roots skipped (not present on this machine):**

- `/home/zhixian/data`, `/home/zhixian/datasets`, `/data`, `/data1`, `/data2`, `/mnt/data`

**Files discovered:** 0

Full per-file listing: see [artifacts/public_benchmark_inventory.md](../artifacts/public_benchmark_inventory.md).

---

## 4. Dataset readiness status

| Dataset | Status | Required files | Notes |
|---------|--------|----------------|-------|
| **SIFT1M** | **missing** | `sift_base.fvecs`, `sift_query.fvecs`, `sift_groundtruth.ivecs` | V3DB expects `data/sift/` |
| **GIST1M** | **missing** | `gist_base.fvecs`, `gist_query.fvecs`, `gist_groundtruth.ivecs` | V3DB expects `data/gist/` |
| **MS MARCO** | **missing** | `collection.duckdb`, `queries.dev.duckdb`, `qrels.dev.tsv` | V3DB expects `data/msmacro/` |

No **partial** installations were found on this host.

---

## 5. Next steps

### 5.1 All datasets missing → prepare download (Phase 8B)

| Dataset | Source | Target layout |
|---------|--------|---------------|
| SIFT1M | [TEXMEX / ANN benchmarks](http://corpus-texmex.irisa.fr/) | `data/public/sift1m/` → symlink or copy to `data/sift/` for V3DB compat |
| GIST1M | TEXMEX GIST1M | `data/public/gist1m/` → `data/gist/` |
| MS MARCO | MS MARCO passage collection + dev queries/qrels; build DuckDB via `vec_data_load/ms_macro.py` | `data/public/msmarco/` → `data/msmacro/` |

After download:

1. Re-run `scripts/inspect_public_benchmark_data.py` — expect **ready** for each dataset.
2. Wire dataset loader paths in D1 pipeline (Python only; no Rust changes required for load).
3. Run V3DB-shaped sanity check: `bash scripts/acc_bench.sh` (SIFT/GIST) and `bench.ms_macro_eval` (MS MARCO) before AuthView ACL overlay experiments.

### 5.2 If partial (future hosts)

- Identify missing roles from inventory markdown “Missing roles” column.
- Complete the trio in a single directory (SIFT/GIST) or under `data/msmacro/` (MS MARCO).
- Re-scan until status = **ready**.

### 5.3 If ready (future)

- Proceed to **D1-A** index build with documented V3DB shapes above.
- Do **not** run full ZK on all queries; follow [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md) sampling guidance.

---

## 6. Phase 8A deliverables

| File | Purpose |
|------|---------|
| `scripts/inspect_public_benchmark_data.py` | Read-only filesystem scanner |
| `artifacts/public_benchmark_inventory.md` | Generated inventory (local) |
| `tests/test_public_benchmark_inventory.py` | Mock-based unit tests (7 passed) |
| `docs/phase8_dataset_storage_plan.md` | Storage sizing and layout |
| `docs/phase8_public_benchmark_inventory.md` | This document |

**Tests:** `PYTHONPATH=. pytest tests/test_public_benchmark_inventory.py -v` → **7/7 passed**
