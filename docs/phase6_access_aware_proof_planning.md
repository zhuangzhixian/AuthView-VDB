# Phase 6A-2: Access-Structure-Aware Proof Planning

**Phase:** 6A-2 (design documentation only — no implementation)  
**Branch:** `phase6-access-aware-proof-planning`  
**Status:** extends [phase6_visibility_gated_design.md](phase6_visibility_gated_design.md) with block/class-aware proof planning

This document upgrades Phase 6 from **candidate-level visibility gating** to **access-structure-aware proof planning**, informed by access-aware indexing (Veda / EffVeda) but scoped to **proof-carrying retrieval over committed authorization views**—not a Veda extension.

**Related:** [phase6_visibility_gated_decision.md](phase6_visibility_gated_decision.md), [phase6_access_aware_proof_plan_test_plan.md](phase6_access_aware_proof_plan_test_plan.md), [research_positioning_reset.md](research_positioning_reset.md), [next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md)

---

## A. Motivation from Access-Aware Indexing

### What access-aware indexing shows

Recent access-aware vector indexing work (including **Veda**, **EffVeda**, and related systems) demonstrates that **authorization constraints are not a post-processing filter**—they reshape:

- **Index layout** — separate or duplicated structures for different access classes.
- **Candidate purity** — whether a probed region contains only authorized, only unauthorized, or mixed objects.
- **Query planning** — which regions to search, merge, or skip under a user context.

When most of the physical index is invisible to user `U` at checkpoint `σ`, execution-aware systems avoid touching impure or irrelevant regions and coordinate **storage amplification (SA)** vs **query amplification (QA)** trade-offs.

### Core Veda / EffVeda ideas (relevant as motivation)

| Concept | Indexing meaning (trusted server) |
|---------|-----------------------------------|
| **Pure index region** | All vectors in region share the same visibility outcome for the query context |
| **Impure region** | Mixed visibility; requires per-object checks or finer subdivision |
| **Copy / merge** | Duplicate or combine index blocks to improve purity at SA cost |
| **SA / QA trade-off** | More storage (or metadata) to reduce query work |
| **Coordinated search** | Planner chooses region order and merge strategy per query |

These ideas explain **why** enterprise corpora often exhibit low effective `N_vis/N_sel` **and** spatial locality of visibility (tenant blocks, project shards, document classes).

### How AuthView-VDB differs from Veda (explicit)

| Dimension | Veda / EffVeda (typical) | AuthView-VDB (this work) |
|-----------|--------------------------|---------------------------|
| **Trust model** | Server trusted; optimize QPS, recall, storage | Server **may be malicious**; client verifies proof |
| **Objective** | Fast ANN under access constraints | **Correct authorized top-k** over full declared `Cand` |
| **Pure / impure** | **Index execution** concept (what to scan) | **Proof planning** concept (what to prove and at what cost) |
| **Output** | Approximate neighbors | Public `R` + ZK proof π |
| **Commitment** | Optional / external | **Committed** content + auth roots at `σ` |
| **Failure mode** | Recall loss, latency | **Authorized exclusion**, snapshot mix, visibility forgery |

**Paper placement:** cite Veda/EffVeda as **related work and motivation** for structure-aware cost—not as a dependency, baseline, or extension target.

> We study proof-carrying authorized vector retrieval over committed access views; access-aware indexing informs **proof plan design**, not index construction.

---

## B. From Candidate-Level Gating to Block/Class-Aware Proof Planning

Phase 6A defined per-candidate gating (`g_x = valid_x · v_x`). Phase 6A-2 partitions the **same fixed candidate set** into **proof regions** whose type determines proof obligations.

A **region** is a contiguous or logically grouped subset of reference candidate slots (e.g., IVF list, slot range, ACL-class bucket, tenant shard) with a declared purity class.

### Region type 1: Pure-visible (`pure_visible`)

**Definition:** For user `U` and checkpoint `σ`, every valid candidate slot `x` in region `R` satisfies `v_x = 1`.

**Proof target:**

$$
\text{region\_pure\_visible}(R) = 1
$$

**Optimization (ideal):**

- No per-slot policy evaluation inside `R` (policy satisfied once at region boundary).
- ADC / distance + top-k contribution for all valid slots in `R`.
- Optional: single region-level visibility certificate derived from committed ACL-class or label aggregate.

**Risks:**

- Prover must **not** self-declare purity; `region_pure_visible` must be **derivable** from committed authorization state + public `γ_U`.
- False pure-visible → skip policy on a slot with `v_x = 0` → invisible object could enter ranking incorrectly (less critical) or inconsistent mask (detectable).
- False pure-visible with wrong bound → **authorized exclusion** if a visible slot is treated as outside pure region and demoted.

---

### Region type 2: Pure-invisible (`pure_invisible`)

**Definition:** Every valid slot in `R` satisfies `v_x = 0`.

**Proof target:**

$$
\text{region\_pure\_invisible}(R) = 1
$$

**Optimization (ideal):**

- No per-slot policy inside `R`.
- No ADC constraints for slots in `R`; assign `hat_d_x = d_max` for all `x ∈ R`.
- Largest gate savings when `|R|` is large and purity is sound.

**Risks (critical):**

- Declaring a region pure-invisible when it contains **any** visible close candidate causes **authorized exclusion**—the dominant soundness failure.
- Must prove purity from committed state, not prover witness bit.

---

### Region type 3: Impure (`impure`)

**Definition:** Region contains both visible and invisible valid slots (or purity cannot be proved at region granularity).

**Proof target:** No region-level purity; fall back to:

- Per-slot masked-distance path (`auth_committed`), or
- Per-ACL-class path (`auth_acl_class`) when class table applies, or
- Future visible-subset compaction within `R` only.

**Optimization:** Limited to ACL-class policy-once **within** the impure region; full per-slot policy if object-level labels.

**Role:** Correctness backstop; always available when planner cannot certify purity.

---

### Relationship to Phase 5 ACL-class

| Layer | Granularity | Optimizes |
|-------|-------------|-----------|
| ACL-class (Phase 5) | Dynamic auth **class** | Policy eval count (`N_acl` vs `N_sel`) |
| Proof region (Phase 6A-2) | **Spatial / structural** block | Policy + distance batching |
| Candidate gate (Phase 6A) | Single slot | Minimal semantic unit |

Regions may align with **ACL classes**, **IVF lists**, **tenant/project shards**, or **slot-aligned blocks**—planner chooses granularity subject to sound purity proofs.

---

## C. Proof Planning Semantics

### Unified proof plan

For query `q`, user context `γ_U`, and checkpoint `σ`, a **proof plan** is:

$$
\mathrm{Plan}(q, U, \sigma) = \{ \mathrm{Region}_1, \ldots, \mathrm{Region}_m \}
$$

Each region record contains:

| Field | Description |
|-------|-------------|
| `region_id` | Stable identifier within plan |
| `region_type` | `pure_visible` \| `pure_invisible` \| `impure` |
| `slots` | Set of reference candidate slot indices `(probe, slot)` covered |
| `content_root` | Merkle root binding content slots (inherited from `root_content`) |
| `auth_root` | `root_auth`, `root_acl_class`, and/or binding root relevant to region |
| `proof_relation` | What must be proved (purity lemma, per-slot fallback, distance bundle) |

### Execution sketch (semantic, not implementation)

```
for each Region R in Plan(q, U, sigma):
  prove R.slots ⊆ Cand(q, S, theta)                    // coverage
  prove R.auth openings consistent with CP_sigma       // checkpoint binding

  if R.region_type == pure_invisible:
    prove forall x in R: v_x = 0
    assign hat_d_x = d_max for all x in R

  elif R.region_type == pure_visible:
    prove forall x in R: v_x = 1
    prove d_x = ADC(q, x) for x in R
    hat_d_x = d_x

  else:  // impure
    for x in R: v_x from committed auth; hat_d_x = masked baseline

combine all (cid_x, hat_d_x); TopK_k; set equality vs baseline
```

### Hard requirements

1. **Full coverage:** Every slot in the reference grid `Cand(q,S,θ)` appears in exactly one region:

   $$
   \bigcup_i R_i.\text{slots} = Cand, \quad R_i \cap R_j = \emptyset \text{ for } i \neq j
   $$

2. **Provable region typing:** `region_type` is a **theorem** from committed auth + `P`, not a free prover label.

3. **Top-k equivalence:**

   $$
   R_{\mathrm{plan}} = R_{\mathrm{masked}}
   $$

   where `R_masked` is the Phase 0–5C masked-distance baseline.

4. **Pinned checkpoint:** All region auth openings use the same `CP_σ`.

---

## D. Soundness Requirements

| ID | Property | Statement |
|----|----------|-----------|
| **S1** | Region coverage | Each reference slot covered exactly once |
| **S2** | Region purity soundness | `pure_visible` / `pure_invisible` flags implied by committed auth, not witness |
| **S3** | No unauthorized inclusion | Invisible slot cannot receive `hat_d_x < d_max` unless policy passes |
| **S4** | No authorized exclusion | Visible slot cannot be in a falsely pure-invisible region or falsely demoted |
| **S5** | Impure fallback | Impure regions reproduce per-slot / per-class masked semantics |
| **S6** | Top-k equivalence | Plan output equals masked-distance baseline on all fixtures |
| **S7** | Checkpoint / root binding | No mixing `root_auth` or `σ` across regions |

### Authorized exclusion (S4) — central attack

If region `R` is declared `pure_invisible` but contains visible candidate `x` with small true distance, assigning `hat_d_x = d_max` removes `x` from top-k incorrectly.

**Mitigation:** region purity proof must be **complete** over all slots in `R` (e.g., bound to ACL-class visibility at region granularity + binding coverage).

### Comparison to Phase 6A candidate gating

Candidate-level `g_x` is the **finest** partition (each slot its own impure region of size 1). Proof planning **coarsens** the partition when purity is provable, enabling batched proof obligations.

---

## E. Cost Model

### Baseline masked path (implemented)

$$
C_{\mathrm{masked}} \approx N_{sel} \cdot (C_{\mathrm{dist}} + C_{\mathrm{vis}} + C_{\mathrm{mask}}) + C_{\mathrm{topk}}
$$

### ACL-class path (Phase 5, implemented)

$$
C_{\mathrm{acl}} \approx N_{acl} \cdot C_{\mathrm{policy}} + N_{sel} \cdot C_{\mathrm{bind}} + N_{sel} \cdot C_{\mathrm{match}} + N_{sel} \cdot C_{\mathrm{dist}} + C_{\mathrm{topk}}
$$

Policy term improved when `N_acl ≪ N_sel`; **distance term still × N_sel** (Phase 5C).

### Access-aware proof planning (target)

$$
C_{\mathrm{plan}} =
  N_{pv} \cdot C_{\mathrm{region\_visible\_proof}}
  + N_{pi} \cdot C_{\mathrm{region\_invisible\_proof}}
  + \sum_{R \in \mathrm{impure}} C_{\mathrm{impure}}(R)
  + N_{\mathrm{dist\_visible}} \cdot C_{\mathrm{dist}}
  + C_{\mathrm{topk\_plan}}
$$

| Symbol | Meaning |
|--------|---------|
| `N_pv` | Count of pure-visible regions |
| `N_pi` | Count of pure-invisible regions |
| `N_imp` | Count of impure regions (or sum of impure region costs) |
| `N_dist_visible` | Slots where ADC must be proved (visible slots only) |
| `C_region_visible_proof` | One-time purity + auth boundary proof for visible block |
| `C_region_invisible_proof` | One-time purity proof; no ADC |
| `C_impure(R)` | Fallback: ACL-class or per-slot path over `\|R\|` slots |

### When planning wins

Savings require:

$$
N_{pi} \cdot |R| \cdot C_{\mathrm{dist}} \gg N_{pi} \cdot C_{\mathrm{region\_invisible\_proof}}
$$

and similarly for policy batching in pure-visible regions.

**Key insight:** Benefit depends on **authorization structure purity** (how often regions are pure), not only global `N_vis/N_sel`. Two workloads with equal `N_vis/N_sel` can differ if one has compact pure-invisible blocks and the other has scattered visibility.

### Static circuit caveat (unchanged from Phase 6A)

Per-candidate mux in a fixed-shape circuit **does not** reduce gates. Proof planning gains materialize only when:

- Circuit shape **omits** ADC sub-circuits for pure-invisible regions, or
- Separate smaller proof is used for visible subset, or
- Region purity enables fewer policy gadgets in a **redesigned** constraint system.

---

## F. Relation to SA/QA and Proposed PA

Adapt indexing vocabulary to **verifiable authorized retrieval**:

### Storage Amplification (SA)

**Definition (for this paper):**

$$
SA = \frac{\mathrm{Storage}(\text{access-structured commitments + index metadata})}{\mathrm{Storage}(\text{minimal content-only snapshot})}
$$

Examples of SA sources:

- Duplicate IVF lists per tenant / clearance band (Veda-style copy).
- Extra Merkle trees: ACL-class table, binding tree, region purity certificates.
- Slot-aligned vs flat auth layout (Phase 3 appendix).

SA is **offline / publisher** cost; improves online proof or query structure.

### Proof Amplification (PA) — proposed metric

**Definition:**

$$
PA = \frac{C_{\mathrm{proof}}(\text{implemented path})}{C_{\mathrm{oracle}}(\text{ideal authorized-view proof})}
$$

where `C_oracle` is an idealized cost model with perfect purity information (no over-proving).

Phase 6A-2 uses PA to compare:

- Masked baseline (high PA when `N_vis ≪ N_sel`),
- ACL-class (reduces policy component of PA),
- Proof plan (reduces policy + distance components when regions are pure).

### Query / Proof planning trade-off

| More access-aware structure | Effect |
|----------------------------|--------|
| Higher SA (more commitments, copied blocks) | Lower QA / lower PA at query time |
| Finer region map | Better purity, fewer impure fallbacks |
| Coarser regions | Cheaper metadata, risk more impure |

**Paper discussion framework (no full curves required in 6B-1):**

- X-axis: structural purity (`pure_ratio`, `1 - impure_slot_ratio`).
- Y-axis: PA or estimated proof cost.
- Secondary axis: SA from commitment layout choices.

This parallels Veda's SA/QA figure but with **proof cost** on the Y-axis and **malicious security** constraints.

---

## G. Recommended Implementation Path

### Phase 6B-1 — Plaintext proof planning reference (P0, revised)

**Deliverables:**

- `auth_reference/proof_planning_reference.py` (proposed):
  - `build_proof_plan(candidates, user, checkpoint, region_fn)` → `Plan`
  - `score_region_pure_invisible`, `score_region_pure_visible`, `score_region_impure`
  - `run_authorized_reference_planned(...)` → same top-k as masked baseline
  - `compare_planned_vs_masked_reference(...)`
- Metrics: `N_vis/N_sel`, `pure_visible_ratio`, `pure_invisible_ratio`, `impure_ratio`, `N_dist_visible`
- Cost estimator: `estimate_planned_cost(plan)`

**Region construction (plaintext prototype):**

1. Default: partition by IVF probed list (natural block).
2. Classify each list as pure-visible / pure-invisible / impure under `P`.
3. Optional: merge adjacent pure blocks; split impure lists by ACL-class sub-blocks.

**Exit:** all equivalence tests pass; plan metrics exported for figures.

---

### Phase 6B-2 — Cost-model benchmark (P1)

- Plaintext counters only (no Rust).
- Sweeps:
  - `visible_ratio` (global),
  - `pure_invisible_ratio` (structural),
  - `N_acl/N_sel` (orthogonal).
- Figures:
  - `N_vis/N_sel` vs ideal cost (Phase 6A),
  - **pure/impure ratio** vs ideal planned cost (Phase 6A-2).

---

### Phase 6B-3 — Optional component ZK (P2, conditional)

- `region_purity_gadget` or `acl_region_purity_gadget`:
  - Prove all slots in region share visibility outcome given committed class/label set.
- **Do not** prioritize full dynamic visible-subset compaction in first ZK slice.
- Additive path only; baselines unchanged.

**Go/no-go:** region purity gadget + planned cost model shows break-even before full V3DB integration.

---

## H. How This Changes Phase 6A

| Phase 6A (frozen) | Phase 6A-2 (extension) |
|-------------------|-------------------------|
| Candidate-level visibility gating | **Primary:** block/class-aware proof planning |
| Single gate bit `g_x` | Region types + coverage + purity proofs |
| Ideal cost ∝ `N_vis` | Ideal cost ∝ `N_dist_visible` + region proof overhead |
| Compaction Option 3 as long-term | Compaction **within impure regions** or via pure-invisible blocks |
| N_vis/N_sel figure | Add **pure/impure ratio** figure; SA/PA discussion |

**Unchanged:**

- Masked-distance baseline semantics and top-k equivalence target.
- Authorized exclusion as top risk.
- Static circuit honesty constraint.
- No Veda extension claim.

**Deprioritized for immediate implementation:**

- Full ZK candidate-level dynamic compaction (Phase 6A Option 3 as first deliverable).
- Per-slot gating as **implementation** path (remains **semantic** minimum).

**Recommended narrative:**

> Candidate-level gating defines correctness; access-structure-aware proof planning defines **how to prove efficiently** when authorization layout exhibits purity—analogous to access-aware indexing but under malicious security.

---

## I. Document Index (Phase 6A-2)

| Document | Role |
|----------|------|
| [phase6_visibility_gated_design.md](phase6_visibility_gated_design.md) | Candidate-level semantics (still valid) |
| [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md) | This document — region planning |
| [phase6_access_aware_proof_plan_test_plan.md](phase6_access_aware_proof_plan_test_plan.md) | Test plan |
| [phase6_visibility_gated_decision.md](phase6_visibility_gated_decision.md) | Updated decision after 6A-2 |

**No source code modified in Phase 6A-2.**
