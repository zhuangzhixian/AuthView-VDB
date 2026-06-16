# Contribution Map and Top-Tier Gap Analysis

**Phase:** 6A-2 companion (documentation only)  
**Audience:** Internal planning for VLDB / SIGMOD / ICDE submission  
**Status:** Synthesizes Phase 0–6A-2 artifact state as of design freeze

**Related:** [research_positioning_reset.md](research_positioning_reset.md), [top_tier_readiness_plan.md](top_tier_readiness_plan.md), [remaining_work_gap_analysis.md](remaining_work_gap_analysis.md), [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md)

---

## 1. Paper Positioning

### What this paper is

**Core problem (one sentence):**

> *Proof-carrying authorized vector retrieval over committed authorization/access views on a shared physical index.*

The verifier receives public top-k cids plus a zero-knowledge proof π that the ranking equals authorized masked top-k over the **full** declared candidate set `Cand(q,S,θ)` — not post-filter, not a server-chosen subset, not content-only retrieval.

Formal target:

$$
R = \mathcal{A}_{auth}(q, S, V(U,\sigma); \theta)
= \mathrm{TopK}_k\bigl(\{(x, \hat d_x) \mid x \in \mathrm{Cand}(q,S,\theta)\}\bigr)
$$

where $\hat d_x$ incorporates visibility from committed labels at checkpoint $\sigma$, bound to public `root_auth` in checkpoint tuple $CP_\sigma$.

### What this paper is **not**

| ❌ Do not claim | Why |
|-----------------|-----|
| **V3DB extension** | Different verification object: V3DB proves content retrieval only; no $V(U,\sigma)$, no committed auth state, no masked authorized top-k |
| **Veda extension** | Different trust model and output: Veda assumes trusted server, optimizes QPS/recall/SA/QA; we assume malicious server and produce ZK proof of authorized retrieval |
| “V3DB + auth plugin” | Authorization-view retrieval is the **problem**; V3DB-style proof is a **content-only baseline** |
| “First access-controlled vector DB” | Filtered ANN and Veda already address trusted access-aware retrieval; our novelty is **verifiable** authorized retrieval |

### V3DB placement

| Role | Placement |
|------|-----------|
| **Related work** | Representative verifiable vector database / proof-carrying ANN over committed snapshots (Qiu et al.) |
| **Experimental baseline** | `py_set_based_with_merkle` — “content-only verifiable baseline (V3DB-style)” |
| **Inherited reference geometry** | Fixed-shape IVF-PQ: $N_{sel} = n_{probe} \times slot$, ADC/PQ pipeline, set-based top-k witness |
| **Explicit gap** | No authorization view, no visibility mask, no `root_auth`, no retrieval soundness under $V(U,\sigma)$ |

Label in tables: **content-only verifiable baseline** — not “our system without auth.”

### Veda / EffVeda placement

| Role | Placement |
|------|-----------|
| **Related work + motivation** | Trusted access-aware vector retrieval via pure/impure index regions, copy/merge, SA/QA trade-off, coordinated query planning (Han et al., 2026) |
| **Conceptual inspiration** | Pure vs impure **blocks**, storage/query amplification framing, access-structure locality |
| **Not a dependency** | We do not build Veda indexes, compare QPS/recall against Veda, or extend Veda APIs |
| **Key distinction** | Veda pure/impure = **index execution** (what to scan); AuthView pure/impure = **proof planning** (what to prove and at what cost) |

**Paper sentence:**

> Access-aware indexing (Veda, EffVeda) motivates structure-aware proof cost, but our system proves correct authorized top-k under malicious security over committed access views — a different problem class from trusted access-aware ANN.

### Positioning diagram

```
                    Verifiable vector search
                              │
              ┌───────────────┴───────────────┐
              │                               │
     Content snapshot only              Authorization view
     (V3DB, vSQL, …)                   (this work)
              │                               │
     R = TopK(d_x) on Cand              R = TopK(̂d_x) on Cand
     no V(U,σ)                          V(U,σ) + root_auth + π

     Trusted access-aware ANN           Proof-carrying authorized retrieval
     (Veda, EffVeda, filtered ANN)     (this work)
              │                               │
     Optimize SA/QA, recall            Prove masked top-k correctness
     server trusted                     server may be malicious
```

---

## 2. Achieved Contributions

Each row: **contribution name** | **status** | **evidence** | **paper placement** | **remaining gap**

### 2.1 Problem and semantics

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **Committed access view retrieval semantics** | done | `docs/formal_statement.md`, `docs/security_properties.md`, `docs/research_positioning_reset.md` | Main (§2–3 problem formulation) | Paper prose not written; some formal doc banners still say “planned” |
| **Plaintext authorized reference oracle** | done | `auth_reference/reference.py`, `post_filter.py`, `attacks.py`; `tests/test_auth_reference.py` (8 tests) | Main (correctness reference) | No large-scale semantic eval; post-filter contrast is micro-fixture |
| **Post-filter vs authorized distinction** | done | `build_post_filter_contrast_candidates()`; attack A1 in `tests/test_auth_attack_matrix.py` | Main (motivation) + eval | Need ≥1 non-toy quantitative workload comparison |

### 2.2 Proof kernel (ZK)

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **ZK auth-static baseline (policy + mask + coverage)** | done | `auth_committed` path; `py_set_based_auth_committed_with_merkle`; `tests/test_auth_zk_committed.py`; `tests/test_auth_zk_partial_visible.py` | Main (baseline auth proof) | Eval at single auth-tree depth; no corpus-scale index-wide `root_auth` demo |
| **Committed auth state binding (`root_auth`)** | done | `src/merkle_ver/auth_policy_gadget.rs`, `auth_mask_gadget.rs`; `tests/test_auth_commitment.py` | Main (mechanism) | — |
| **Policy-only path (non-committed labels)** | done | `py_set_based_auth_with_merkle`; regression baseline | Appendix / ablation | Not paper-facing guarantee |
| **V3DB content-only reproduction** | done | `py_set_based_with_merkle`; `artifacts/v3db_reproduce_metrics.csv`; `docs/v3db_reproduction_log.md` | Eval baseline only | Must not be framed as contribution |

### 2.3 Commitment layouts

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **Global / probe-local flat auth commitment** | done | Phase 2C; `tests/test_auth_commitment.py` | Appendix (layout variant) | Production-scale opening count figure optional |
| **Slot-aligned two-level auth commitment** | done | Phase 3B; `tests/test_auth_slot_aligned_commitment.py`, `tests/test_auth_zk_slot_aligned.py` | Appendix | ~2–3% gate reduction in `auth_zk_paper_ready_summary.csv`; too weak alone |
| **cid-keyed vs slot-aligned comparison** | partial | Both paths implemented; overhead CSV compares `auth_slot_aligned` vs `auth_committed` | Appendix | No dedicated opening-count analysis at production $N_{list}$ |

### 2.4 Security evaluation

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **Attack matrix (≥8 scenarios)** | done | `docs/attack_matrix_eval.md`; `tests/test_auth_attack_matrix.py` (11 tests); `artifacts/auth_attack_matrix.csv` | Main (RQ1 security) | A9/A10 partially covered (circuit/API limits); A11 freshness out of scope; need paper attack table prose |
| **ZK-level forgery rejection** | done | A2–A8, A12 via real PyO3 API on committed + slot-aligned paths | Main (security eval) | — |
| **Plaintext semantic attacks** | done | A1 post-filter, A10 coverage at reference layer | Main | — |

### 2.5 ACL-class compression (Phase 5)

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **ACL-class plaintext reference** | done | `auth_reference/acl_class_commitment.py`; `tests/test_acl_class_reference.py` (13), `tests/test_acl_class_commitment.py` (16) | Main (algorithm) | — |
| **ACL-class ZK proof path** | done | `set_based_auth_ivf_pq_gadget_committed_acl_class`; `py_set_based_auth_acl_class_with_merkle`; `tests/test_auth_zk_acl_class.py` (11) | Main (algorithm + system) | Distance term still × $N_{sel}$; wins only when $N_{acl} \ll N_{sel}$ |
| **ACL-class N_acl/N_sel evaluation** | partial | `scripts/bench_acl_class_paths.py`; `artifacts/auth_zk_acl_class_summary.csv` (repeat=1); `docs/phase5_acl_class_eval_log.md` | Main (eval figure) | **repeat=3 paper-ready run pending**; figure not yet in paper draft |
| **N_acl/N_sel trend validated** | done | N_acl=1 → ~0.94× gates vs committed; N_acl≥16 → overhead-dominated | Main (eval discussion) | Extend grid: more slot/n_probe combos |

### 2.6 Overhead and scaling eval

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **Multi-path overhead CSV (repeat=3)** | done | `artifacts/auth_zk_paper_ready_summary.csv` (30 rows, 6 workloads × 5 paths) | Main (RQ2–3) | Paper tables/figures not drafted |
| **Policy vs committed vs slot ablation** | done | Same CSV: baseline, auth_policy, auth_committed, auth_slot_aligned | Main (ablation) | Add auth_acl_class to unified ablation table |
| **Scaling vs N_sel, n_probe** | done | N_sel ∈ {64, 128, 256, 512} in paper-ready CSV | Main (RQ3) | Real dataset overlay missing |

### 2.7 Phase 6 design (not yet implemented)

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **Visibility-gated scoring design** | done (design) | `docs/phase6_visibility_gated_design.md`, `docs/phase6_visibility_gated_test_plan.md` | Main (optimization semantics) | No plaintext oracle; no ZK path |
| **Access-aware proof planning design** | done (design) | `docs/phase6_access_aware_proof_planning.md`, `docs/phase6_access_aware_proof_plan_test_plan.md` | Main (preferred optimization direction) | No implementation; no cost-model figure |
| **PA/SA discussion framework** | done (design) | §F in phase6_access_aware_proof_planning.md | Discussion / eval framing | No measured PA curve |

### 2.8 Positioning and planning docs

| Contribution | Status | Evidence | Paper | Gap |
|--------------|--------|----------|-------|-----|
| **Research positioning reset** | done | `docs/research_positioning_reset.md` | Internal → paper §1–2 | Convert to paper prose |
| **Top-tier readiness plan** | done | `docs/top_tier_readiness_plan.md` | Internal | — |
| **Paper outline draft** | partial | `docs/paper_outline_draft.md`, `docs/evaluation_plan_paper_tables.md` | — | No full draft |

---

## 3. Planned Contributions

| Contribution | Status | Target phase | Paper placement | Depends on |
|--------------|--------|--------------|-----------------|------------|
| **Access-aware proof planning plaintext reference** | planned | 6B-1 | Main (algorithm) | Phase 6A-2 design |
| **Pure-visible / pure-invisible / impure region construction** | planned | 6B-1 | Main (mechanism) | ACL-class + IVF list structure |
| **N_vis/N_sel cost-model figure** | planned | 6B-2 | Main (eval) | Proof planning reference |
| **Pure/impure ratio vs ideal PA figure** | planned | 6B-2 | Main (eval) | Proof planning reference |
| **PA/SA discussion with preliminary numbers** | planned | 6B-2 + paper | Discussion | Cost model counter |
| **Realistic ACL distribution generator** | planned | 6B-2 / eval | Eval (workload) | Tenant/project/clearance models |
| **Paper system architecture diagram** | planned | Paper sprint | Main (§4 system) | Stable API surface |
| **RQ table + eval section prose** | planned | Paper sprint | Main (§5–6) | Figures from 6B-2 |
| **Component ZK region purity gadget** | optional | 6B-3 | Enhancement / appendix | 6B-1/2 break-even |
| **Full planned ZK path in V3DB proof loop** | optional | post-6B-3 | Future work if marginal | Region gadget + planner |

---

## 4. Main vs Secondary Contributions

### Main contributions (paper thesis)

1. **Problem:** Committed authorization-view retrieval — formal semantics distinguishing authorized top-k from post-filter and from content-only verifiable retrieval (V3DB class).

2. **Mechanism:** Proof construction over committed authorization state — policy visibility, masked distance, full candidate coverage, pinned checkpoint tuple $CP_\sigma$.

3. **Algorithm — ACL-class compression:** Policy-once per ACL class with candidate↔class binding proof; $N_{acl}/N_{sel}$ cost structure (**implemented**).

4. **Algorithm — access-aware proof planning (conditional on 6B-1):** Pure-visible / pure-invisible / impure regions with top-k equivalence to masked baseline; structure-aware proof cost beyond global $N_{vis}/N_{sel}$.

5. **Security:** Attack-informed evaluation demonstrating ZK rejection of label forgery, path substitution, cross-list graft, and user-context mismatch.

6. **Evaluation:** Overhead vs content-only baseline; scaling vs $N_{sel}$; ACL-class ratio curve; (planned) proof-planning purity curve.

### Secondary / appendix

| Item | Rationale |
|------|-----------|
| Slot-aligned Merkle layout | ~2–3% gate reduction; engineering optimization |
| cid-keyed vs slot-aligned comparison | Layout trade-off; not the thesis |
| Policy-only vs all-visible ablation paths | Isolates gadget cost components |
| Selected synthetic overhead details | Supports RQ2–3; not standalone novelty |
| V3DB reproduction infrastructure | Baseline only |

### Discussion / future work

| Item | When to mention |
|------|-----------------|
| Dynamic freshness / transparency log | A11 out of scope; checkpoint registry |
| Private user context ($\gamma_U$ hidden from verifier) | Different crypto stack |
| Pure/impure ZK region gadget (if not implemented) | Phase 6B-3 conditional |
| Full SA/PA curve with storage model | Needs commitment layout + block model |
| Index-wide global auth tree at corpus scale | Production engineering |
| Real public benchmarks (SIFT + ACL overlay) | Strengthen eval if time permits |
| Visible-subset dynamic compaction | After region purity gadget |

---

## 5. Top-Tier Readiness Assessment (VLDB / SIGMOD / ICDE)

### 5.1 Problem novelty

| Criterion | Score | Notes |
|-----------|-------|-------|
| New verification question vs V3DB | **Strong** | Committed auth view + masked top-k is formally distinct |
| Distinct from Veda / filtered ANN | **Strong** | Malicious security + proof obligation |
| Enterprise motivation | **Moderate** | Scenario documented; needs attack-driven numbers in paper |
| Related work depth | **Weak** | Outline only; Veda/V3DB positioning docs exist but no survey prose |

**Verdict:** Adequate for workshop / arXiv; **needs paper §1–2 + related work section** for main conference.

### 5.2 Algorithmic / system contribution

| Criterion | Score | Notes |
|-----------|-------|-------|
| New retrieval objective + ZK realization | **Strong** | auth_committed kernel complete |
| ACL-class compression | **Strong** | Implemented + initial N_acl/N_sel curve |
| Access-aware proof planning | **Moderate (design only)** | Highest-value remaining algorithm work |
| Non-trivial system prototype | **Strong** | 6 PyO3 proof paths, 80+ auth-related tests |

**Verdict:** **One strong algorithm + kernel** today; **second strong contribution** (proof planning) still missing implementation.

### 5.3 Proof / security strength

| Criterion | Score | Notes |
|-----------|-------|-------|
| Formal security properties | **Strong** | formal_statement + security_properties |
| Attack matrix | **Strong** | 12 scenarios documented; 9+ with ZK or plaintext tests |
| Known limitations explicit | **Strong** | A11 freshness, public $\gamma_U$, fixed-shape Cand |
| ZK coverage gaps | **Moderate** | A9/A10 injection not at API boundary |

**Verdict:** **Acceptable for systems venue** if attack table appears in paper with honest limitations.

### 5.4 Experimental completeness

| RQ | Requirement | Status |
|----|-------------|--------|
| RQ1 Security | Attack matrix + ZK outcomes | ✅ documented + tested |
| RQ2 Overhead | vs content-only baseline | ✅ paper-ready CSV (repeat=3) |
| RQ3 Scaling | vs $N_{sel}$, n_probe | ✅ 6 workloads |
| RQ4 Structure-aware cost | N_acl/N_sel, N_vis/N_sel, purity ratios | **Partial** — N_acl ✅ (repeat=1); N_vis/purity ❌ |
| RQ5 Semantic gap | Post-filter vs authorized quantified | **Weak** — toy fixture only |

**Verdict:** **Insufficient** for strong main-conference submission without N_vis/purity figures and richer semantic eval.

### 5.5 Artifact maturity

| Criterion | Status |
|-----------|--------|
| Reproducible build (cargo + maturin) | ✅ |
| Benchmark scripts + CSV artifacts | ✅ |
| Test suite (80+ auth tests) | ✅ |
| Artifact instructions for reviewers | ❌ |
| Real dataset evaluation | ❌ |

**Verdict:** **Good kernel artifact**; not yet a full reproducibility package.

### 5.6 Related work positioning

| Risk | Mitigation |
|------|------------|
| Viewed as V3DB extension | Positioning reset doc; never use “extend V3DB” in title/abstract |
| Viewed as Veda extension | Explicit trust-model table; cite as motivation only |
| Viewed as crypto add-on | Lead with new query semantics + ACL-class algorithm + eval curves |
| “Incremental Merkle tweak” | Subordinate slot-aligned to appendix; headline ACL + proof planning |

**Verdict:** Positioning **documented**; **paper prose is the remaining risk**.

### 5.7 Overall readiness snapshot

```
Dimension                    Current              Top-tier need
──────────────────────────────────────────────────────────────
Problem framing              Strong (docs)        Paper §1–2 written
Proof kernel                 Strong               —
ACL-class algorithm + eval   Strong (repeat=1)    repeat=3 + figure
Proof planning               Design only          6B-1/2 implementation
Attack evaluation            Strong               Paper table
N_vis/N_sel + purity curves  Missing              P0 blocker
Post-filter quant eval       Toy only             P1
Paper draft                  Outline              Full 8–10 pages
Real / larger data           None                 P1 optional strengthen
Artifact package             Partial              P1
```

**Go/no-go for VLDB/SIGMOD/ICDE main track:** **No-go today.** Estimated **~4/8** checklist items complete ([top_tier_readiness_plan.md](top_tier_readiness_plan.md) §8). Critical path: **6B-1 → 6B-2 → paper architecture + RQ table**.

---

## 6. What Is Still Missing (by Priority)

### P0 — Paper blockers

| Item | Why | Deliverable |
|------|-----|-------------|
| **Access-aware proof planning plaintext reference** | Second algorithm contribution beyond ACL-class; enables structure-aware cost story | `auth_reference/proof_planning_reference.py` + PP-*/COV-* tests |
| **N_vis/N_sel + pure/impure cost-model figure** | Headline eval curve reviewers expect alongside N_acl/N_sel | Plaintext counter + benchmark sweep (6B-2) |
| **Paper architecture diagram + RQ table** | Converts kernel into systems paper narrative | §4–5 draft: objects, proof paths, 5 RQs |

### P1 — Strongly recommended

| Item | Why | Deliverable |
|------|-----|-------------|
| **Realistic workload / ACL distribution generator** | Motivate enterprise ACL clustering; richer than uniform random labels | Tenant/project shard generator with controlled purity |
| **repeat=3 for ACL-class benchmark** | Statistical credibility for N_acl/N_sel figure | Re-run `bench_acl_class_paths.py --repeat 3` |
| **PA definition and preliminary discussion** | Connect to Veda SA/QA literature without claiming Veda baseline | §PA in eval + ideal vs planned cost from 6B-2 |
| **Post-filter vs authorized quantitative comparison** | RQ5; motivates problem beyond toy A1 | Workload with measurable recall/ranking gap |
| **Full paper draft (intro, related work, eval prose)** | Planning docs ≠ submission | 8–10 page draft |
| **Artifact instructions** | Reviewer reproducibility | README artifact section |

### P2 — Enhancement / future work

| Item | Why | Deliverable |
|------|-----|-------------|
| **Component ZK region purity gadget** | Only if 6B-2 shows break-even | Phase 6B-3 optional |
| **Dynamic freshness / transparency log** | Addresses A11; protocol layer | Design + discussion |
| **Private user context** | Hide $\gamma_U$ from verifier | Future work section |
| **Real public benchmark overlay (SIFT, etc.)** | Strengthen eval credibility | Synthetic ACL on public ANN data |
| **Full SA/PA measured curves** | Paper discussion depth | Needs storage commitment model |

---

## 7. Next Three Recommended Tasks

### Task 1 — Phase 6B-1: Access-aware proof planning reference (P0)

**Goal:** Plaintext oracle proving `Plan(q,U,σ)` top-k ≡ masked baseline.

**Deliverables:**

- `auth_reference/proof_planning_reference.py`
  - `build_proof_plan(...)` — classify IVF lists / ACL blocks as pure_visible / pure_invisible / impure
  - `run_authorized_reference_planned(...)` — execute plan semantics
  - `compare_planned_vs_masked_reference(...)` — equivalence assertion
  - Metrics: `N_vis/N_sel`, `pure_ratio`, `impure_ratio`, `N_dist_visible`, estimated `C_plan`
- `tests/test_proof_planning_reference.py` — PP-*, PV-*, PI-*, IM-*, COV-* from [phase6_access_aware_proof_plan_test_plan.md](phase6_access_aware_proof_plan_test_plan.md)

**Success criterion:** All reference fixtures pass top-k equivalence; purity misclassification tests fail loudly (authorized exclusion detection).

### Task 2 — Phase 6B-2: Proof-planning cost model benchmark (P0)

**Goal:** Generate the two missing headline figure families without Rust changes.

**Deliverables:**

- Plaintext cost counter implementing $C_{\mathrm{masked}}$, $C_{\mathrm{acl}}$, $C_{\mathrm{plan}}$
- Sweep: visible ratio, ACL clustering, region granularity (IVF list vs ACL class)
- Outputs for paper: **N_vis/N_sel vs ideal cost** and **pure/impure ratio vs ideal PA**
- Document run recipe in eval log (no new CSV requirement in this planning phase — generate when running benchmark)

**Success criterion:** Monotonicity properties from test plan (CM-*) hold; break-even region identifiable for ACL vs planning vs masked.

### Task 3 — Paper system architecture + RQ table (P0)

**Goal:** Convert existing kernel into submission-ready narrative skeleton.

**Deliverables:**

- System diagram: shared index → committed auth state → proof paths (baseline, committed, ACL-class, planned)
- RQ table mapping to existing/pending evidence:

| RQ | Question | Evidence today | Pending |
|----|----------|----------------|---------|
| RQ1 | Does ZK auth retrieval resist attacks? | Attack matrix ✅ | Paper table |
| RQ2 | What is proof overhead vs content-only? | paper_ready CSV ✅ | Figure |
| RQ3 | How does cost scale with $N_{sel}$? | paper_ready CSV ✅ | Figure |
| RQ4 | How does structure ($N_{acl}$, purity) affect cost? | N_acl partial; N_vis ❌ | 6B-2 |
| RQ5 | How wrong is post-filter? | A1 toy | Realistic workload |

- Related work subsection stubs: V3DB (baseline class), Veda (motivation), filtered ANN (different row), ZK access control

**Success criterion:** Author can write remaining sections without re-deciding scope.

---

## 8. Contribution Ladder (Visual Summary)

```
Phase 0–4   Proof kernel + semantics + attacks + positioning
     │
Phase 5     ACL-class compression ──────────────► N_acl/N_sel ✅ (main)
     │
Phase 6A    Visibility-gated scoring (semantic floor)
     │
Phase 6A-2  Access-aware proof planning (design) ─► N_vis/N_sel + purity ❌ (main, pending)
     │
Phase 6B-1  Plaintext proof planning reference ───► P0 next
Phase 6B-2  Cost model + figures ───────────────────► P0 next
Phase 6B-3  Region purity ZK gadget (optional) ─────► P2
     │
Paper       Architecture + RQ + draft prose ────────► P0 parallel
```

---

## 9. Cross-Reference Index

| Document | Role in contribution map |
|----------|-------------------------|
| [research_positioning_reset.md](research_positioning_reset.md) | V3DB/Veda positioning source of truth |
| [top_tier_readiness_plan.md](top_tier_readiness_plan.md) | Venue bar + go/no-go checklist |
| [remaining_work_gap_analysis.md](remaining_work_gap_analysis.md) | Historical gap inventory (partially superseded by this doc) |
| [attack_matrix_eval.md](attack_matrix_eval.md) | RQ1 evidence |
| [phase5_acl_class_proof_log.md](phase5_acl_class_proof_log.md) | ACL-class ZK mechanism |
| [phase5_acl_class_eval_log.md](phase5_acl_class_eval_log.md) | N_acl/N_sel eval protocol |
| [phase6_visibility_gated_design.md](phase6_visibility_gated_design.md) | Candidate-level semantic floor |
| [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md) | Preferred optimization direction |
| [phase6_visibility_gated_decision.md](phase6_visibility_gated_decision.md) | 6A→6A-2 decision freeze |

**Artifacts (existing, do not regenerate in this phase):**

- `artifacts/auth_zk_paper_ready_summary.csv` — 5 paths, repeat=3, 6 workloads
- `artifacts/auth_zk_acl_class_summary.csv` — ACL vs committed, repeat=1, 7 N_acl values
- `artifacts/auth_attack_matrix.csv` — attack registry outcomes

**External reference (not in git):**

- Han et al., 2026 — Veda/EffVeda (project root PDF; motivation for SA/QA and pure/impure indexing)

---

## 10. One-Paragraph Status Summary (Internal)

> AuthView-VDB has a **credible proof kernel** for committed authorization-view retrieval: formal semantics, plaintext oracle, ZK committed + ACL-class paths, attack matrix, and initial overhead/ACL-ratio evaluation. The work is **not** a V3DB or Veda extension. Top-tier readiness requires **implementing access-aware proof planning (6B-1/2)** for N_vis/purity figures, **hardening ACL eval (repeat=3)**, and **writing the paper** with explicit V3DB-as-baseline and Veda-as-motivation positioning. Slot-aligned layout and V3DB reproduction remain appendix/baseline infrastructure.
