# Paper Evaluation Blueprint

**Phase:** 6C  
**Paper title (working):** Proof-carrying authorized vector retrieval over committed access views  
**Venue target:** VLDB / SIGMOD / ICDE (systems + security)  
**Status:** Planning document — no new experiments in this phase

**Related:** [contribution_map_and_top_tier_gap.md](contribution_map_and_top_tier_gap.md), [top_tier_readiness_plan.md](top_tier_readiness_plan.md), [paper_figure_table_inventory.md](paper_figure_table_inventory.md), [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md)

---

## 1. Evaluation philosophy

AuthView evaluation must answer three distinct questions that prior work splits across two papers:

| Prior work | What it evaluates | AuthView gap |
|------------|-------------------|--------------|
| **V3DB** (Qiu et al., 2026) | Utility + proof cost of **content-only** verifiable IVF-PQ over committed snapshots | No authorization view, no visibility mask, no `root_auth` |
| **Veda** (Han et al., 2026) | Index construction, SA/QA, purity, QPS/recall under **trusted** access-aware indexing | No ZK proof; server trusted; optimizes execution not proof obligation |

AuthView is **neither** a V3DB extension **nor** a Veda extension. The core claim is:

> A malicious server can be forced to prove that returned top-k equals authorized masked top-k over the full declared candidate set `Cand(q,S,θ)` under committed access view `V(U,σ)`.

Evaluation therefore combines:

1. **Retrieval utility** (does authorized retrieval preserve ANN quality?)
2. **Real ZK proof overhead** (gates, prove/verify time, proof size, memory)
3. **Authorization optimizations** (ACL-class, slot-aligned, ablations)
4. **Access-aware proof planning** (plaintext cost model — **not** implemented ZK gate reduction)
5. **Security / attack matrix**
6. **Configuration trade-offs** (V3DB-style scaling curves)
7. **Public dataset scalability** (D1 utility + D2 representative proof sampling)

---

## 2. What we borrow from V3DB evaluation

| V3DB element | AuthView adaptation |
|--------------|---------------------|
| Fixed-shape IVF-PQ pipeline (centroid → probe → ADC → top-k) | Same geometry; add visibility mask + auth commitment |
| Proof cost breakdown (prove / verify / size / gates) | Same metrics; compare **6 paths** not 1 |
| Configuration trade-offs vs `n_probe`, slot capacity, `N_sel` | Reuse grid from `auth_zk_paper_ready_summary.csv` |
| Utility metrics on public ANN data | **Missing** — planned in RQ1 / Stage D1 |
| Baseline = content-only verifiable retrieval | Label `baseline` / `py_set_based_with_merkle` as **V3DB-shaped content-only baseline** |

**Do not claim:** “We extend V3DB with auth.” V3DB is the **content-only lower bound** on proof structure.

---

## 3. What we borrow from Veda evaluation

| Veda element | AuthView adaptation |
|--------------|---------------------|
| SA / QA (storage / query amplification) | Repurposed as **SA_commit / PA_plan** in **proof-planning cost model** (Phase 6B) |
| Pure vs impure regions | **Proof planning** regions (pure-visible / pure-invisible / impure), not index execution |
| Parameter impact (merge factor, block size) | **Merged-k design knob** (`main_merged_k_knob.pdf`) |
| Multi-dataset workload variation | Planned: SIFT1M, GIST1M, MS MARCO + ACL overlay |
| QPS / recall curves | RQ1 utility only (plaintext + reference); **no QPS claim for ZK path** |

**Do not claim:** Veda baseline comparison, QPS speedup, or “Veda + ZK.” Cite Veda as **motivation** for access-structure-aware cost.

---

## 4. What is different because AuthView proves committed access-view semantics

| Dimension | V3DB | Veda | AuthView |
|-----------|------|------|----------|
| Trust model | Malicious prover | Trusted server | Malicious prover |
| Committed object | Content snapshot | Index layout (trusted) | Content + **auth state** (`root_auth`) |
| Query output | Top-k by distance | Access-filtered ANN results | **Authorized masked top-k** + π |
| Coverage | Full `Cand(q,S,θ)` | Server-chosen scan | Full `Cand` with visibility mask |
| Primary cost axis | Gates vs baseline | SA/QA vs global | Gates vs baseline **+** structure (`N_acl`, merged-k, purity) |
| Security eval | Snapshot binding | N/A (trusted) | Attack matrix + ZK rejection |

---

## 5. Research questions (RQ blueprint)

### RQ1 — Retrieval utility

**Question:** Does AuthView preserve retrieval quality under authorized-view semantics?

| Item | Specification |
|------|---------------|
| **Compare** | Plaintext IVF-PQ (unrestricted) · V3DB-shaped IVF-PQ (content-only, same index) · AuthView authorized reference (`auth_reference/reference.py`) |
| **Datasets** | SIFT1M, GIST1M, MS MARCO (see [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md)) |
| **Metrics** | Recall@1/10/100, Hit@10, MRR@10, NDCG@10 |
| **Workload** | Fixed query sets per dataset; sweep selectivity via ACL overlay (role/signature policies) |
| **Claim boundary** | Utility measured on **reference / plaintext** path; ZK path must match reference (tested on micro/sampled workloads) |

**Evidence today:** Micro-fixture correctness (`tests/test_auth_reference.py`); **no public-dataset utility CSV**.

**Paper placement:** §Evaluation “Retrieval utility” + Table “Dataset setup” + Figure “Recall vs selectivity.”

---

### RQ2 — Proof overhead

**Question:** What is the ZK cost of authorization-aware proof paths vs V3DB-shaped baseline?

| Item | Specification |
|------|---------------|
| **Paths** | `baseline` (V3DB original) · `auth_all_visible` · `auth_policy` · `auth_committed` · `auth_slot_aligned` · `auth_acl_class` |
| **Metrics** | Prove time, verify time, proof size, peak memory, gate count |
| **Repeats** | 3 (paper-ready); 5 optional for camera-ready |
| **Workloads** | Synthetic grid: `N_sel` ∈ {64,128,256,512}, `n_probe` ∈ {2,4}, `slot_per_list` ∈ {32,64,128} |
| **Output** | Overhead table (main text) + grouped bar or line figure |

**Evidence today:**

- `artifacts/auth_zk_paper_ready_summary.csv` — 5 paths, repeat=3, 6 workloads ✅
- `artifacts/auth_zk_acl_class_summary.csv` — ACL vs committed, repeat=1 ⚠️

**Paper placement:** §Evaluation “Proof overhead” — **Table 2** + **Figure 3**.

---

### RQ3 — Authorization optimization ablation

**Question:** Which commitment layout and ACL compression settings reduce proof cost?

| Ablation | Compare | Metrics |
|----------|---------|---------|
| Global committed vs slot-aligned | `auth_committed` vs `auth_slot_aligned` | Gates, prove time, opening count model |
| ACL-class compression | `auth_committed` vs `auth_acl_class` | Gates vs `N_acl/N_sel` |
| Policy-only vs committed | `auth_policy` vs `auth_committed` | Isolates Merkle + binding cost |
| All-visible vs policy | `auth_all_visible` vs `auth_policy` | Isolates visibility gadget |

**Sweep parameters:** `N_acl` ∈ {1,2,4,8,16,32,64}, `N_sel`, `visible_ratio`.

**Evidence today:** Slot-aligned ~2–5% gate reduction (paper-ready CSV); ACL-class trend at repeat=1.

**Paper placement:** §Evaluation “Ablations” — **Figure 4** (N_acl/N_sel) + **Table 4**.

---

### RQ4 — Access-aware proof planning (cost model)

**Question:** How does physical layout (merged-k, ACL-signature, global) trade storage amplification (SA) for proof amplification (PA)?

| Item | Specification |
|------|---------------|
| **Model** | Repaired access-signature layout model (Phase 6B-2.10); sanity 10/10 |
| **Data** | `artifacts/proof_planning_layout_summary_repaired.csv`, `proof_planning_layout_metrics_repaired.csv` |
| **Knob** | Merged-k ∈ {1,2,4,8,16,64} |
| **Metrics** | `SA_commit`, `PA_plan`, `plan_vs_masked_cost`, impure_valid_ratio, component costs |
| **Figures** | `main_merged_k_knob.pdf`, `main_cost_breakdown_clean.pdf`, optional `main_impure_fallback_clean.pdf` |
| **Slice** | Query role closest to effective selectivity 0.5 (role 4, eff_sel ≈ 0.54) |

**Claim boundary (mandatory in caption and text):**

> Plaintext work-unit cost model. **Not measured ZK gate reduction.** Static circuit shape does not reduce gates unless circuit or witness layout changes (future work: region purity gadget).

**Evidence today:** Model + figures ✅; no ZK integration.

**Paper placement:** §Evaluation “Structure-aware proof cost” — **Figure 5** (three subfigures in LaTeX).

---

### RQ5 — Security / attack evaluation

**Question:** Does AuthView resist realistic prover attacks under pinned verifier context?

| Attack ID | Scenario | Layer |
|-----------|----------|-------|
| A1 | Post-filter insufficiency (authorized ≠ post-filter top-k) | Plaintext |
| A2/A2b | Unauthorized label forgery | ZK (`auth_committed`, `auth_slot_aligned`) |
| A3 | Auth Merkle path substitution | ZK |
| A4 | Visibility / label field forgery | ZK |
| A5 | Wrong `root_auth` / root mixing | ZK |
| A6 | Cross-list graft | ZK (slot-aligned) |
| A7/A8 | Wrong intra/top slot-aligned path | ZK |
| A9 | Top-k / order manipulation | Circuit (partial API injection) |
| A10 | Candidate omission / authorized exclusion | Circuit + plaintext |
| A11 | Stale root / freshness | Protocol — **out of scope** |
| A12 | User-context mismatch vs Merkle | ZK |

**Evidence today:** `docs/attack_matrix_eval.md`, `artifacts/auth_attack_matrix.csv`, `tests/test_auth_attack_matrix.py` (11 tests) ✅

**Paper placement:** §Evaluation “Security” — **Table 3** (attack matrix) + optional workflow figure.

---

### RQ6 — Scalability and configuration trade-offs

**Question:** How do proof cost and memory scale with ANN and auth configuration?

| Parameter | Range | Metrics |
|-----------|-------|---------|
| `N_sel` = n_probe × slot | 64 – 512+ | Gates, prove time, proof size |
| `n_probe` | 2, 4, 8 | Same |
| `slot_per_list` | 32, 64, 128 | Same |
| `top_k` | 5, 10, 20 | Same |
| `N_acl` | 1 – 64 | ACL-class path only |
| `N_vis/N_sel` (visible ratio) | 0.05 – 1.0 | Policy + planning overlays |

**Style:** V3DB-like line plots — X = configuration knob, Y = median gates / prove time.

**Evidence today:** RQ6 partially covered by paper-ready CSV (synthetic 400×64). Extended grids **missing**.

**Paper placement:** §Evaluation “Scaling” — **Figure 6** + appendix sensitivity tables.

---

### RQ7 — Public large-scale dataset scalability

**Question:** Do results hold on public benchmarks at index scale beyond micro-synthetic?

| Stage | Scale | Full ZK | Plaintext / cost model |
|-------|-------|---------|------------------------|
| **D1** | SIFT1M, GIST1M, MS MARCO | Representative sampled queries (feasible subset) | Full utility + layout/policy generation |
| **D2** | SIFT10M / SIFT100M | **Sampled** proof instances only | Index shaping, candidate distribution, ACL overlay |

**Clarification rule:** Every figure/table must label whether data is **real ZK measurement**, **plaintext reference**, or **cost model**.

**Evidence today:** ❌ No public dataset artifacts.

**Paper placement:** §Evaluation “Large-scale experiments” + [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md).

---

## 6. RQ-to-section mapping (recommended paper outline)

| Section | RQs | Primary artifacts |
|---------|-----|---------------------|
| §5.1 Experimental setup | All | Dataset table, hardware, parameters |
| §5.2 Retrieval utility | RQ1 | Public dataset metrics (planned) |
| §5.3 Proof overhead | RQ2 | `auth_zk_paper_ready_summary.csv` |
| §5.4 Authorization ablations | RQ3 | ACL-class CSV + slot-aligned ratios |
| §5.5 Structure-aware proof cost | RQ4 | Layout repaired CSV + `main_*` figures |
| §5.6 Security evaluation | RQ5 | Attack matrix table |
| §5.7 Scaling | RQ6 | Scaling CSV / extended bench |
| §5.8 Large-scale public data | RQ7 | D1/D2 plan outputs |
| §5.9 Limitations | All | Synthetic gaps, public γ_U, cost model vs ZK |

---

## 7. Measurement protocol (shared)

| Setting | Value |
|---------|-------|
| Random seed | Fixed per experiment (document in artifact README) |
| Repeats | 3 minimum (5 for camera-ready overhead) |
| Hardware | Document CPU, RAM, single-thread prove unless noted |
| Median reporting | Primary; show IQR or std in appendix |
| Path naming in paper | “Content-only baseline (V3DB-shaped)” not “V3DB” alone |

---

## 8. Current readiness by RQ

| RQ | Status | Blocker |
|----|--------|---------|
| RQ1 Utility | ❌ Missing | Public dataset pipeline |
| RQ2 Overhead | ✅ Strong | Paper table/figure not drafted |
| RQ3 Ablation | ⚠️ Partial | ACL repeat=3; unified ablation table |
| RQ4 Proof planning | ✅ Cost model | Label as cost model; no ZK |
| RQ5 Security | ✅ Strong | Paper prose for A9/A10/A11 limits |
| RQ6 Scaling | ⚠️ Partial | Synthetic only; extend knobs |
| RQ7 Public scale | ❌ Missing | D1/D2 execution |

---

## 9. Evaluation narrative (one paragraph for paper §5 intro)

> We evaluate AuthView along seven research questions. **RQ1** measures whether authorized-view retrieval preserves ANN utility on public benchmarks. **RQ2–3** quantify ZK proof overhead and authorization optimizations against a V3DB-shaped content-only baseline—not as an extension of V3DB, but as a contrasting verification object. **RQ4** uses a plaintext proof-planning cost model inspired by access-aware indexing literature (Veda) to expose layout trade-offs (merged-k, purity); we explicitly do not claim ZK gate reduction from this model. **RQ5** reports an attack matrix with ZK-level rejection tests. **RQ6–7** study configuration scaling and public dataset feasibility, with full proofs on sampled large-scale queries where complete enumeration is infeasible.

---

## 10. Cross-references

| Document | Role |
|----------|------|
| [paper_figure_table_inventory.md](paper_figure_table_inventory.md) | Figure/table checklist with P0/P1/P2 |
| [public_dataset_evaluation_plan.md](public_dataset_evaluation_plan.md) | RQ1 + RQ7 execution plan |
| [phase6_proof_planning_paper_figures_log.md](phase6_proof_planning_paper_figures_log.md) | RQ4 figure spec |
| [attack_matrix_eval.md](attack_matrix_eval.md) | RQ5 detail |
| [phase5_acl_class_eval_log.md](phase5_acl_class_eval_log.md) | RQ3 ACL protocol |
