# Phase 8B: SIFT1M / GIST1M Acquisition

**Phase:** 8B  
**Scope:** TEXMEX download preparation, directory layout, V3DB symlinks, loader sanity — **not** MS MARCO (Phase 8D)  
**Companion:** [phase8_public_benchmark_inventory.md](phase8_public_benchmark_inventory.md), [phase8_dataset_storage_plan.md](phase8_dataset_storage_plan.md)

---

## 1. Phase 8B goals

| Goal | This phase | Deferred |
|------|------------|----------|
| Standardize `data/public/sift1m/` and `data/public/gist1m/` | Yes | — |
| V3DB-compatible symlinks `data/sift`, `data/gist` | Yes | — |
| Download helper with resume + manual fallback | Yes | — |
| Loader sanity (fvecs/ivecs dim, sample read) | Yes | — |
| MS MARCO DuckDB + embeddings | No | Phase 8D |
| IVF-PQ index build | No | Phase 8C |
| ZK proof | No | D1-E |

Phase 8B makes SIFT1M/GIST1M **locally available and loader-verified** before Stage D1 utility experiments.

---

## 2. Why SIFT1M / GIST1M first

1. **V3DB alignment:** Experiment 1 (`scripts/acc_bench.sh`) already targets these datasets with documented IVF-PQ shapes.
2. **Low friction:** Single tarball or a few `.fvecs` files; no embedding pipeline.
3. **Coverage:** SIFT1M (128D, 1M base, 10k queries) and GIST1M (960D, 1M base, 1k queries) span low- and high-dimensional ANN stress.
4. **MS MARCO complexity:** Requires passage collection, embedding cache, and DuckDB build (~50–100 GB) — tracked separately as **pending**.

---

## 3. Data source and format

**Source:** [TEXMEX / IRISA ANN benchmarks](http://corpus-texmex.irisa.fr/)

| Dataset | Base | Queries | Ground truth | Optional |
|---------|------|---------|--------------|----------|
| SIFT1M | 1M × 128D float32 | 10k | top-100 ivecs | learn (100k) |
| GIST1M | 1M × 960D float32 | 1k | top-100 ivecs | learn (500k) |

**Format:** `.fvecs` / `.ivecs` — each vector stored as `(dim: int32)(payload: dim × float32 or int32)`.

**V3DB loader:** `vec_data_load/sift.py` expects folder name = prefix (`sift` or `gist`) with `{prefix}_base.fvecs`, etc.

---

## 4. Directory structure

```
data/
├── public/
│   ├── sift1m/
│   │   ├── sift_base.fvecs
│   │   ├── sift_query.fvecs
│   │   ├── sift_groundtruth.ivecs
│   │   └── sift_learn.fvecs          # optional
│   └── gist1m/
│       ├── gist_base.fvecs
│       ├── gist_query.fvecs
│       ├── gist_groundtruth.ivecs
│       └── gist_learn.fvecs          # optional
├── sift  -> public/sift1m            # V3DB compat (relative symlink)
└── gist  -> public/gist1m
```

The entire `data/` tree is gitignored (`/data/` in `.gitignore`). Do **not** commit fvecs archives or extracted files.

---

## 5. V3DB-compatible symlink scheme

From repository root, after files are **ready**:

```bash
ln -s public/sift1m data/sift
ln -s public/gist1m data/gist
```

Or use the preparation script:

```bash
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset all \
  --data-root data/public \
  --check-only \
  --link-v3db
```

Symlinks are created only when all required fvecs/ivecs files exist. Existing non-symlink paths are not overwritten.

---

## 6. Download / manual preparation

### 6.1 Dry run (default — prints steps only)

```bash
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset all \
  --data-root data/public
```

### 6.2 Check existing files (no download)

```bash
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset all \
  --data-root data/public \
  --check-only
```

Report: `artifacts/texmex_prepare_report.md`

### 6.3 Automated download (explicit opt-in)

```bash
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset all \
  --data-root data/public \
  --download \
  --link-v3db
```

Downloads use resume-friendly HTTP Range requests. On network failure, the script prints manual `wget` commands and leaves partial files intact.

### 6.4 Manual download (recommended if server network is slow)

**SIFT1M:**

```bash
mkdir -p data/public/sift1m
wget -c http://corpus-texmex.irisa.fr/sift/sift.tar.gz -O data/public/sift1m/sift.tar.gz
tar -xzf data/public/sift1m/sift.tar.gz -C data/public/sift1m
```

Or per-file:

```bash
cd data/public/sift1m
wget -c http://corpus-texmex.irisa.fr/sift/sift_base.fvecs
wget -c http://corpus-texmex.irisa.fr/sift/sift_query.fvecs
wget -c http://corpus-texmex.irisa.fr/sift/sift_groundtruth.ivecs
wget -c http://corpus-texmex.irisa.fr/sift/sift_learn.fvecs   # optional
```

**GIST1M:**

```bash
mkdir -p data/public/gist1m
wget -c http://corpus-texmex.irisa.fr/gist/gist.tar.gz -O data/public/gist1m/gist.tar.gz
tar -xzf data/public/gist1m/gist.tar.gz -C data/public/gist1m
```

Per-file URLs mirror the SIFT pattern under `http://corpus-texmex.irisa.fr/gist/`.

After manual placement, re-run `--check-only` (and `--link-v3db` if ready).

---

## 7. Loader sanity check

After files are present:

```bash
PYTHONPATH=. python scripts/check_fvecs_dataset.py \
  --dataset sift1m \
  --data-root data/public

PYTHONPATH=. python scripts/check_fvecs_dataset.py \
  --dataset gist1m \
  --data-root data/public
```

Checks (without loading full 1M vectors):

- Required files exist
- Base/query dimension = 128 (SIFT) or 960 (GIST)
- Base and query dims match
- Ground-truth ivecs readable; sample neighbor count reported

Report: `artifacts/fvecs_dataset_check.md`

Quick loader integration test (loads full files — use only after sanity check passes):

```python
from vec_data_load.sift import SIFT
s = SIFT("data/sift")
print(s.base_vecs.shape, s.query_vecs.shape, s.gt_vecs.shape)
```

---

## 8. Phase 8C — utility pipeline (next)

Once both datasets report **ready** + checker **ok**:

1. Confirm V3DB symlinks: `data/sift`, `data/gist`
2. Run V3DB-shaped plaintext utility baseline:
   ```bash
   bash scripts/acc_bench.sh
   ```
3. Begin AuthView D1-B/C: authorized reference vs unrestricted on same IVF-PQ index (see [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md))
4. Sample ZK proofs (D1-E) — not full-query enumeration

Index parameters (from V3DB):

| Profile | SIFT1M | GIST1M |
|---------|--------|--------|
| high-acc | n_list=8192, n_probe=64 | same |
| zk-opt | n_list=1024, n_probe=8, cluster_bound=2048 | n_list=512, n_probe=4, cluster_bound=4096 |

Common: `M=8`, `K=256`, `top_k=100`.

---

## 9. MS MARCO status (pending — Phase 8D)

| Item | Status |
|------|--------|
| Dataset | **pending** |
| Required files | `collection.duckdb`, `queries.dev.duckdb`, `qrels.dev.tsv` under `data/msmacro/` |
| Blocker | DuckDB embedding preparation (~50–100 GB) |
| Next phase | **Phase 8D** — MS MARCO acquisition + `bench.ms_macro_eval` alignment |

Do not block SIFT/GIST D1 work on MS MARCO completion.

---

## 10. Phase 8B deliverables

| File | Purpose |
|------|---------|
| `scripts/prepare_texmex_datasets.py` | Download prep, normalize, V3DB symlinks |
| `scripts/check_fvecs_dataset.py` | Read-only fvecs/ivecs sanity |
| `docs/phase8_sift_gist_acquisition.md` | This document |
| `artifacts/texmex_prepare_report.md` | Generated prepare report |
| `artifacts/fvecs_dataset_check.md` | Generated loader check (after data present) |
| `tests/test_texmex_dataset_preparation.py` | Mock prepare tests |
| `tests/test_fvecs_dataset_checker.py` | Mock checker tests |

**Tests:**

```bash
PYTHONPATH=. pytest tests/test_texmex_dataset_preparation.py tests/test_fvecs_dataset_checker.py -v
```
