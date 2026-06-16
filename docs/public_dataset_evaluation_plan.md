# Public Dataset Evaluation Plan

**Phase:** 6C  
**Scope:** RQ1 (retrieval utility) + RQ7 (large-scale scalability)  
**Companion:** [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md), [paper_figure_table_inventory.md](paper_figure_table_inventory.md)

**Principle:** Public datasets validate **retrieval utility** and **workload realism**. Full ZK proof for every query at 10M–100M scale is generally **infeasible**; we use **representative proof sampling** plus plaintext/cost-model coverage at scale.

---

## 1. Goals

| Goal | RQ | Measurement type |
|------|-----|------------------|
| Show authorized reference ≈ unrestricted ANN quality | RQ1 | **REF** (plaintext) |
| Show V3DB-shaped baseline utility matches on same index | RQ1 | **REF** |
| Validate ACL overlay + selectivity control on real embeddings | RQ1, RQ7 | **REF** + policy generator |
| Sample ZK proofs on realistic `(q, policy, index)` tuples | RQ2, RQ7 | **ZK** (sampled) |
| Study candidate visibility / purity / N_vis at scale | RQ4, RQ7 | **REF** + **COST** |
| Motivate enterprise scenario (multi-tenant, role-based access) | All | Workload design |

---

## 2. Stage D1 — Medium public benchmarks

**Datasets:** SIFT1M · GIST1M · MS MARCO (passage embedding subset)

| Dataset | Vectors | Dim | Queries | Notes |
|---------|---------|-----|---------|-------|
| SIFT1M | 1M | 128 | 10k (learn) | Standard ANN benchmark; `.fvecs`/`.bvecs` |
| GIST1M | 1M | 960 | 1k | Higher dim; stress PQ |
| MS MARCO | variable | 768 typical | dev queries | Text embedding; enterprise RAG motivation |

### D1 experiments

| Exp | Description | Output |
|-----|-------------|--------|
| **D1-A Index build** | IVF-PQ index per dataset (fixed shape: nlist, M, nbits documented) | Index stats JSON/log (not paper CSV in repo policy — use log files) |
| **D1-B Unrestricted utility** | Plaintext IVF-PQ search: Recall@1/10/100, Hit@10, MRR@10, NDCG@10 | `artifacts/public_d1_utility_<dataset>.csv` (future) |
| **D1-C Authorized reference** | Same index + ACL overlay; `auth_reference` authorized top-k | Same metrics vs D1-B |
| **D1-D V3DB-shaped path** | Content-only candidate set identical; verify ranking alignment | Consistency check (should match unrestricted on visible subset) |
| **D1-E Sampled ZK proofs** | e.g. 50–200 queries × 2–3 selectivity levels × 2 paths (`auth_committed`, `auth_acl_class`) | `artifacts/public_d1_zk_sample_<dataset>.csv` (future) |

### D1 fixed-shape preprocessing impact

Document explicitly:

- IVF list count, `n_probe`, `slot_per_list`, PQ parameters
- How fixed-shape `Cand(q,S,θ)` differs from native FAISS dynamic probe
- Impact on recall (expect small gap vs native if parameters matched)

### D1 feasibility: full proof samples

| Dataset | Full ZK all queries? | Recommended |
|---------|----------------------|-------------|
| SIFT1M | No (10k queries × proof cost) | Sample 100–500 queries stratified by selectivity |
| GIST1M | No | Sample 50–200 |
| MS MARCO | No | Sample 100–300 dev queries |

---

## 3. Stage D2 — Large-scale index shaping

**Datasets:** SIFT10M · SIFT100M (or Deep1B subset if storage permits)

| Goal | Full ZK | Approach |
|------|---------|----------|
| Index construction time / size | N/A | Plaintext IVF-PQ build metrics |
| Candidate distribution under ACL | No | Measure `N_vis`, `N_sel`, purity on sampled queries |
| Layout planning (merged-k, signatures) | No | **COST** model at scale (Phase 6B reference on sampled policy) |
| Representative ZK proofs | **Sampled only** | e.g. 20–50 queries after D2 index build |

**Do not require** full proof enumeration at 10M–100M unless hardware budget explicitly allows.

### D2 outputs (planned)

| Artifact | Content |
|----------|---------|
| Index metadata log | nlist, total slots, build time, RAM |
| Query sample stats | N_vis/N_sel histogram, impure ratio, N_acl |
| ZK sample CSV | gates/prove/size for sampled (q, path) |

---

## 4. Access policy generation

Enterprise-style overlays on public datasets (objects = vectors / documents):

### 4.1 OrgAccess-like department/role model

| Parameter | Description |
|-----------|-------------|
| `num_departments` | Top-level tenant shards |
| `num_roles` | Clearance levels per department |
| `objects_per_role` | Expected membership multiplicity |

Generation:

1. Assign each object to 1–k roles (Zipf skew over role popularity)
2. Query carries single active role `r`
3. Visibility: `visible(obj) ⟺ r ∈ sig(obj)`

Aligns with repaired layout model ([phase6_proof_planning_layout_audit.md](phase6_proof_planning_layout_audit.md)).

### 4.2 Role-combination signatures

- `num_signatures` templates (bitsets over roles)
- Objects draw signature templates with Zipf skew
- Enables merged-k layout evaluation at scale

### 4.3 Selectivity and overlap control

| Knob | Effect |
|------|--------|
| Role frequency Zipf α | Controls global selectivity distribution |
| Signature concentration | Controls purity / impure region ratio |
| Department isolation | Low overlap vs high overlap regimes |

Target selectivity bands for paper: **~0.1, ~0.25, ~0.5, ~0.75** (match layout figure slice).

### 4.4 Skew / Zipf distribution

- Object→signature: Zipf(s=1.2–2.0)
- Query role: uniform or workload-weighted
- Report effective selectivity per query set (do not assume nominal only)

---

## 5. Metrics (by experiment type)

### 5.1 Retrieval utility (D1)

| Metric | Definition |
|--------|------------|
| Recall@K | K ∈ {1, 10, 100} vs ground truth |
| Hit@10 | Any relevant in top-10 |
| MRR@10 | Mean reciprocal rank |
| NDCG@10 | Graded relevance if available (MARCO); binary for SIFT/GIST |

Compare:

- Unrestricted IVF-PQ
- Authorized reference (masked top-k)
- Gap should be **zero** when policy excludes only truly invisible neighbors (sanity); non-zero gap indicates post-filter would differ (A1 motivation)

### 5.2 Proof overhead (D1 sampled ZK)

Prove time, verify time, proof size, memory, gates — same schema as `auth_zk_paper_ready_metrics.csv`.

### 5.3 Structure metrics (D1/D2 at scale)

| Metric | Use |
|--------|-----|
| `N_vis/N_sel` | Effective selectivity per query |
| `N_acl/N_sel` | ACL-class compression headroom |
| `impure_valid_ratio` | Proof planning difficulty |
| `pure_visible_region_ratio` | Region purity |
| `SA_commit`, `PA_plan` | Layout cost model (COST) |

### 5.4 Attack detection (sanity)

On sampled workloads: run plaintext attack fixtures (A1 post-filter contrast) where selectivity creates ranking gap.

---

## 6. Practical execution notes

### 6.1 Data download and storage

| Dataset | Source | Est. size | Path |
|---------|--------|-----------|------|
| SIFT1M | ANN benchmarks / Texmex | ~500 MB | `data/sift/` |
| GIST1M | Texmex | ~3 GB | `data/gist/` |
| MS MARCO | Microsoft / BEIR-style exports | embeddings ~GB | `data/marco/` |
| SIFT10M+ | BigANN | 10–100+ GB | `data/bigann/` (server) |

Existing hint: [v3db_reproduction_log.md](v3db_reproduction_log.md) references `data/siftsmall/` for smoke tests.

**Do not commit** large binaries; document download scripts in `scripts/data/`.

### 6.2 Preprocessing scripts (to create in future phase)

| Script | Purpose |
|--------|---------|
| `scripts/data/download_sift1m.sh` | Fetch + verify checksum |
| `scripts/preprocess_ivfpq_public.py` | Build fixed-shape index, export meta |
| `scripts/overlay_acl_policy.py` | Attach signatures / roles to object ids |
| `scripts/bench_public_utility.py` | D1-B/C metrics |
| `scripts/bench_public_zk_sample.py` | D1-E sampled proofs |

### 6.3 Reproducibility

- Pin: faiss/cuVS version, IVF params, PQ (M, nbits), seed for ACL overlay
- Log hardware: CPU model, RAM, Rust/Plonky2 version
- Store **median of 3** repeats for ZK samples

### 6.4 Expected runtime (order-of-magnitude)

| Task | Local workstation | Server |
|------|-------------------|--------|
| SIFT1M index build | 5–30 min | 5–15 min |
| SIFT1M full 10k query utility (plaintext) | 10–60 min | faster with GPU |
| Single `auth_committed` proof (N_sel=256) | ~0.4–1 s | similar |
| 500 sampled ZK proofs | ~5–15 min | batch |
| SIFT10M index build | hours | 1–3 h |
| SIFT100M index | impractical local | server / subset |

### 6.5 Local vs server

| Experiment | Local | Server |
|------------|-------|--------|
| D1 SIFT1M utility | ✅ | ✅ |
| D1 GIST1M utility | ✅ (RAM) | ✅ |
| D1 MARCO utility | ✅ if embeddings cached | ✅ |
| D1 ZK sample (≤500) | ✅ | ✅ |
| D2 SIFT10M index + stats | ⚠️ tight | ✅ recommended |
| D2 SIFT100M | ❌ | ✅ subset + sample |
| D2 ZK sample | ✅ | ✅ |

---

## 7. Phased timeline (recommended)

| Phase | Deliverable | Depends on |
|-------|-------------|------------|
| **D1.0** | SIFT1M download + index + unrestricted recall | Data scripts |
| **D1.1** | ACL overlay + authorized reference utility | D1.0 |
| **D1.2** | 200-query ZK sample (`auth_committed`, `auth_acl_class`) | D1.1 |
| **D1.3** | GIST1M + MARCO repeat D1.0–1.2 | D1.2 |
| **D2.0** | SIFT10M index + visibility/purity stats | Server |
| **D2.1** | 50-query ZK sample on SIFT10M | D2.0 |
| **Paper** | Table 5 + Fig 6 from D1 aggregates | D1.3 |

---

## 8. Claim boundaries for public data section

**Can claim:**

- Authorized reference retrieval quality on public benchmarks (REF)
- Sampled ZK overhead on real embedding distributions (ZK, sampled)
- Selectivity/purity statistics at 10M scale (REF/COST)
- ACL overlay realism (OrgAccess-like)

**Cannot claim:**

- Full ZK proof for every query at 10M/100M scale
- QPS competitive with Veda/EffVeda
- ZK gate reduction from proof-planning cost model curves
- Production multi-tenant deployment without freshness protocol (A11)

---

## 9. Integration with existing artifacts

| Existing | Public dataset use |
|----------|-------------------|
| `auth_zk_paper_ready_summary.csv` | Synthetic baseline; cite as “controlled microbenchmark” |
| `proof_planning_layout_*_repaired.csv` | Methodology validation; optional COST overlay on D2 samples |
| `auth_attack_matrix.csv` | Security unchanged; optional A1 demo on public selectivity |

---

## 10. Next actions (P0)

1. Add `scripts/data/download_sift1m.sh` + README (no large binary commit)  
2. Build SIFT1M IVF-PQ index with documented fixed shape  
3. Implement ACL signature overlay generator (reuse Phase 6B workload logic conceptually)  
4. Run D1-B/C utility → populate Table 5 / Fig 6  
5. Run D1-E 200-query ZK sample → extend Table 2 with “SIFT1M sample” row  
