# Phase 8A: Dataset Storage Plan

**Phase:** 8A  
**Scope:** SIFT1M, GIST1M, MS MARCO (passage/dev) — **not** SIFT100M  
**Companion:** [phase8_public_benchmark_inventory.md](phase8_public_benchmark_inventory.md), [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md)

This document sizes disk requirements and recommends directory layout before Phase 8B download and D1 experiments.

---

## 1. SIFT1M

| Component | Size estimate |
|-----------|---------------|
| Base vectors | 1M × 128 dim × 4 B ≈ **512 MB** (`sift_base.fvecs`) |
| Queries | 10k × 128 × 4 B ≈ **5 MB** |
| Ground truth | top-100 neighbors × 10k queries ≈ **4 MB** |
| Learn set (optional) | 100k × 128 × 4 B ≈ **51 MB** |
| Archive (`sift.tar.gz`) | ~**500 MB** compressed |

**Total raw data:** ~0.6 GB  
**Recommended reserve:** **1–2 GB** (extracted fvecs + small DuckDB if converted)

**V3DB loader path:** `data/sift/sift_{base,query,groundtruth}.fvecs`

---

## 2. GIST1M

| Component | Size estimate |
|-----------|---------------|
| Base vectors | 1M × 960 dim × 4 B ≈ **3.84 GB** (`gist_base.fvecs`) |
| Queries | 1k × 960 × 4 B ≈ **3.7 MB** |
| Ground truth | top-100 × 1k ≈ **0.4 MB** |
| Learn set (optional) | 500k × 960 × 4 B ≈ **1.9 GB** |
| Archive (`gist.tar.gz`) | ~**2.7 GB** compressed |

**Total raw data:** ~4 GB (base only) to ~6 GB (with learn)  
**Recommended reserve:** **10–20 GB** (base + learn + IVF-PQ index artifacts under `data/acc_bench/` or future `data/public/gist1m/index/`)

**V3DB loader path:** `data/gist/gist_{base,query,groundtruth}.fvecs`

GIST1M is the highest per-vector footprint among D1 ANN sets; plan disk before download.

---

## 3. MS MARCO (passage / dev)

| Component | Size estimate |
|-----------|---------------|
| Passage collection | ~8.8M passages (text) |
| Raw TSV (if kept) | ~**2–4 GB** |
| `collection.duckdb` | ~**5–15 GB** (depends on embedding cache inside DB) |
| Dev queries DuckDB | ~**10–50 MB** |
| `qrels.dev.tsv` | ~**1 MB** |
| Embedding cache (`data/msmacro/cache/`) | model-dependent; **768-d float32** × 8.8M ≈ **26 GB** minimum |
| IVF-PQ index + bench outputs | additional **10–30 GB** |

**Recommended reserve:** **50–100 GB** for collection + embeddings + indexes + experiment caches

**V3DB expected files:**

```
data/msmacro/collection.duckdb
data/msmacro/queries.dev.duckdb
data/msmacro/qrels.dev.tsv
data/msmacro/cache/          # optional but typical after first embed
```

Dev split: **6,980 queries** with qrels (V3DB README / `ms_macro_load.py` defaults).

Building DuckDB from TSV is a one-time cost; prefer keeping DuckDB + cache on fast local SSD.

---

## 4. Recommended directory structure

Use a **public** namespace for downloaded artifacts, with **compatibility symlinks** to V3DB paths:

```
data/
├── public/
│   ├── sift1m/
│   │   ├── sift_base.fvecs
│   │   ├── sift_query.fvecs
│   │   ├── sift_groundtruth.ivecs
│   │   └── sift_learn.fvecs          # optional
│   ├── gist1m/
│   │   ├── gist_base.fvecs
│   │   ├── gist_query.fvecs
│   │   └── gist_groundtruth.ivecs
│   └── msmarco/
│       ├── collection.duckdb
│       ├── queries.dev.duckdb
│       ├── qrels.dev.tsv
│       └── cache/
├── sift/          -> public/sift1m/   # symlink for V3DB acc_bench
├── gist/          -> public/gist1m/
└── msmacro/       -> public/msmarco/
```

Experiment outputs (already V3DB-shaped):

```
data/acc_bench/              # SIFT/GIST acc_bench results
data/exp1/ms_macro_high_acc/ # MS MARCO high-acc
data/exp1/ms_macro_zk_fast/  # MS MARCO zk-fast
```

---

## 5. Aggregate disk budget (D1 only)

| Dataset | Minimum (raw) | Recommended (raw + index + bench) |
|---------|---------------|-----------------------------------|
| SIFT1M | ~0.6 GB | 1–2 GB |
| GIST1M | ~4 GB | 10–20 GB |
| MS MARCO | ~30 GB (embeddings) | 50–100 GB |
| **Total (all three)** | ~35 GB | **~60–120 GB** |

Add headroom for AuthView D1 CSV/logs and sampled ZK artifacts (~1–5 GB).

**Not in scope:** SIFT10M / SIFT100M (explicitly excluded per project plan).

---

## 6. Git and artifact hygiene

The repository `.gitignore` already excludes `data/`. Additionally:

### 6.1 Suggested `.git/info/exclude` entries (local only)

These keep machine-specific paths out of `git status` without changing tracked `.gitignore`:

```
/data/
/artifacts/public_benchmark_inventory.md
```

Add only on machines where the inventory artifact should stay local.

### 6.2 Do not commit

- Large `.fvecs`, `.ivecs`, `.tar.gz`, `.duckdb` files
- Embedding caches under `data/msmacro/cache/`
- Generated `artifacts/public_benchmark_inventory.md` if it reflects local paths (optional exclude above)
- Bench result directories under `data/acc_bench/`, `data/exp1/`

### 6.3 Safe to commit (Phase 8A)

- `scripts/inspect_public_benchmark_data.py`
- `tests/test_public_benchmark_inventory.py`
- `docs/phase8_public_benchmark_inventory.md`
- `docs/phase8_dataset_storage_plan.md`

---

## 7. Re-scan after download

```bash
PYTHONPATH=. python scripts/inspect_public_benchmark_data.py \
  --output artifacts/public_benchmark_inventory.md
```

Expect all three datasets **ready** before starting D1-A index builds.
