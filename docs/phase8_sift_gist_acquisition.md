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
| Download helper with FTP primary + HTTP fallback | Yes | — |
| Auto-normalize nested TEXMEX extract layout | Yes | — |
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

| Dataset | Primary tarball (FTP) | Fallback tarball (HTTP) |
|---------|---------------------|-------------------------|
| SIFT1M | `ftp://ftp.irisa.fr/local/texmex/corpus/sift.tar.gz` | `http://corpus-texmex.irisa.fr/sift/sift.tar.gz` |
| GIST1M | `ftp://ftp.irisa.fr/local/texmex/corpus/gist.tar.gz` | `http://corpus-texmex.irisa.fr/gist/gist.tar.gz` |

**Network note (this server):** FTP primary URLs are **verified working**. HTTP tarball URLs **timeout** on this host and are kept only as fallback / manual reference. Per-file HTTP URLs remain documented for manual recovery.

| Dataset | Base | Queries | Ground truth | Optional |
|---------|------|---------|--------------|----------|
| SIFT1M | 1M × 128D float32 | 10k | top-100 ivecs | learn (100k) |
| GIST1M | 1M × 960D float32 | 1k | top-100 ivecs | learn (500k) |

**Format:** `.fvecs` / `.ivecs` — each vector stored as `(dim: int32)(payload: dim × float32 or int32)`.

**V3DB loader:** `vec_data_load/sift.py` expects folder name = prefix (`sift` or `gist`) with `{prefix}_base.fvecs`, etc. at the **dataset root** (via symlink is OK).

---

## 4. Verified directory structure (this server)

After IRISA FTP download + `prepare_texmex_datasets.py --check-only --link-v3db`:

```
data/
├── public/
│   ├── sift1m/
│   │   ├── sift_base.fvecs          -> ./sift/sift_base.fvecs      (root canonical symlink)
│   │   ├── sift_query.fvecs         -> ./sift/sift_query.fvecs
│   │   ├── sift_groundtruth.ivecs   -> ./sift/sift_groundtruth.ivecs
│   │   ├── sift_learn.fvecs         -> ./sift/sift_learn.fvecs     (optional)
│   │   └── sift/                    (nested raw extract from tarball)
│   │       ├── sift_base.fvecs
│   │       ├── sift_query.fvecs
│   │       ├── sift_groundtruth.ivecs
│   │       └── sift_learn.fvecs
│   └── gist1m/
│       ├── gist_base.fvecs          -> ./gist/gist_base.fvecs
│       ├── gist_query.fvecs         -> ./gist/gist_query.fvecs
│       ├── gist_groundtruth.ivecs   -> ./gist/gist_groundtruth.ivecs
│       ├── gist_learn.fvecs         -> ./gist/gist_learn.fvecs     (optional)
│       └── gist/
│           └── ...
├── sift  -> public/sift1m            (V3DB compat, relative symlink)
└── gist  -> public/gist1m
```

The script searches up to **max-depth 4** under each dataset directory and creates root-level relative symlinks when files live in nested folders (typical TEXMEX tar extract layout).

---

## 5. V3DB-compatible symlink scheme

When datasets are **ready**, with `--link-v3db`:

```bash
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset all \
  --data-root data/public \
  --check-only \
  --link-v3db
```

Creates (relative symlinks from `data/`):

- `data/sift` → `public/sift1m`
- `data/gist` → `public/gist1m`

Behavior:

- Wrong existing symlinks are **safely updated**
- Existing **directories** at `data/sift` or `data/gist` are **not deleted** (warning only)

Manual equivalent:

```bash
ln -sfn public/sift1m data/sift
ln -sfn public/gist1m data/gist
```

---

## 6. Download / manual preparation

### 6.1 Dry run (default — prints steps only)

```bash
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset all \
  --data-root data/public
```

Terminal output shows **primary FTP** and **fallback HTTP** URLs.

### 6.2 Check + normalize + V3DB symlinks (no download)

```bash
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset all \
  --data-root data/public \
  --check-only \
  --link-v3db
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

Tries **FTP primary** first, then **HTTP fallback**. On failure prints explicit errors and manual `wget` commands (does not corrupt partial extracts).

### 6.4 Manual download (recommended on this server)

**SIFT1M (FTP):**

```bash
mkdir -p data/public/sift1m
wget -c ftp://ftp.irisa.fr/local/texmex/corpus/sift.tar.gz -O data/public/sift1m/sift.tar.gz
tar -xzf data/public/sift1m/sift.tar.gz -C data/public/sift1m
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset sift1m --data-root data/public --check-only --link-v3db
```

**GIST1M (FTP):**

```bash
mkdir -p data/public/gist1m
wget -c ftp://ftp.irisa.fr/local/texmex/corpus/gist.tar.gz -O data/public/gist1m/gist.tar.gz
tar -xzf data/public/gist1m/gist.tar.gz -C data/public/gist1m
PYTHONPATH=. python scripts/prepare_texmex_datasets.py \
  --dataset gist1m --data-root data/public --check-only --link-v3db
```

HTTP fallback (may timeout on this server):

```bash
wget -c http://corpus-texmex.irisa.fr/sift/sift.tar.gz -O data/public/sift1m/sift.tar.gz
wget -c http://corpus-texmex.irisa.fr/gist/gist.tar.gz -O data/public/gist1m/gist.tar.gz
```

---

## 7. Loader sanity check

```bash
PYTHONPATH=. python scripts/check_fvecs_dataset.py \
  --dataset sift1m \
  --data-root data/public

PYTHONPATH=. python scripts/check_fvecs_dataset.py \
  --dataset gist1m \
  --data-root data/public
```

Checks (without loading full 1M vectors):

- Required files exist at dataset root (symlinks OK)
- Base/query dimension = 128 (SIFT) or 960 (GIST)
- Base and query dims match
- Ground-truth ivecs readable

Report: `artifacts/fvecs_dataset_check.md`

Quick loader integration test (loads full files — use only after sanity check passes):

```python
from vec_data_load.sift import SIFT
s = SIFT("data/sift")
print(s.base_vecs.shape, s.query_vecs.shape, s.gt_vecs.shape)
```

---

## 8. Git hygiene — do not commit

| Path | Reason |
|------|--------|
| `data/public/` | Large fvecs / tarballs |
| `data/sift`, `data/gist` | Symlinks to local data |
| `artifacts/texmex_prepare_report.md` | Machine-local inventory |
| `artifacts/fvecs_dataset_check.md` | Machine-local check output |
| `artifacts/public_benchmark_inventory.md` | Phase 8A local scan |

`data/` is gitignored via `/data/` in `.gitignore`. Optionally add machine-local artifacts to `.git/info/exclude`.

Safe to commit: scripts, tests, and this documentation only.

---

## 9. Phase 8C — utility pipeline (next)

Once both datasets report **ready** + checker **ok**:

1. Confirm V3DB symlinks: `data/sift`, `data/gist`
2. Run V3DB-shaped plaintext utility baseline:
   ```bash
   bash scripts/acc_bench.sh
   ```
3. Begin AuthView D1-B/C: authorized reference vs unrestricted on same IVF-PQ index
4. Sample ZK proofs (D1-E) — not full-query enumeration

---

## 10. MS MARCO status (pending — Phase 8D)

| Item | Status |
|------|--------|
| Dataset | **pending** |
| Required files | `collection.duckdb`, `queries.dev.duckdb`, `qrels.dev.tsv` under `data/msmacro/` |
| Blocker | DuckDB embedding preparation (~50–100 GB) |
| Next phase | **Phase 8D** |

---

## 11. Phase 8B deliverables

| File | Purpose |
|------|---------|
| `scripts/prepare_texmex_datasets.py` | FTP download, normalize, V3DB symlinks |
| `scripts/check_fvecs_dataset.py` | Read-only fvecs/ivecs sanity |
| `docs/phase8_sift_gist_acquisition.md` | This document |
| `tests/test_texmex_dataset_preparation.py` | Mock prepare tests |

**Tests:**

```bash
PYTHONPATH=. pytest tests/test_texmex_dataset_preparation.py -v
```
