# Phase 6: Visibility-Gated Scoring — Decision Memo

**Phase:** 6A decision freeze  
**Audience:** Internal go/no-go for Phase 6B investment  
**Companion:** [phase6_visibility_gated_design.md](phase6_visibility_gated_design.md), [phase6_visibility_gated_test_plan.md](phase6_visibility_gated_test_plan.md)

---

## 1. Executive Summary

**Recommendation: proceed with Phase 6B-1 and 6B-2; defer Phase 6B-3 pending cost-model evidence.**

Visibility-gated scoring addresses a **real gap** left after Phase 5C: ACL-class compression reduces **policy** cost when `N_acl ≪ N_sel`, but **ADC/PQ distance** cost still scales with `N_sel` regardless of how many candidates are invisible. In enterprise-style workloads with low `N_vis/N_sel`, that distance term dominates auth-aware proof cost.

However, **static fixed-shape ZK circuits cannot honestly claim gate savings from a simple `if visibility then compute else skip` pattern.** Real savings require compaction, circuit-family parameterization, or multi-phase proofs—substantially harder than ACL-class compression.

The right near-term deliverable is:

1. **Frozen semantics + plaintext gated oracle** (equivalence proof obligation).
2. **Ideal cost model + N_vis/N_sel figure** (even if full ZK optimization is deferred).
3. **Optional full path** only if compaction design clears security + break-even analysis.

---

## 2. Is It Worth Continuing?

### Yes — for these reasons

| Factor | Assessment |
|--------|------------|
| **Problem fit** | Authorized view retrieval naturally has `N_vis ≪ N_sel`; post-filter literature motivates structure-aware cost |
| **Top-tier eval gap** | [top_tier_readiness_plan.md](top_tier_readiness_plan.md) lists N_vis/N_sel as missing headline figure |
| **Complements Phase 5** | ACL-class optimizes policy; gating optimizes distance—orthogonal axes |
| **Low-risk start** | Phase 6B-1 is plaintext-only; cheap equivalence validation |
| **Honest negative results OK** | Even proving static-circuit limits is publishable if framed correctly |

### Caveats — do not over-promise

| Factor | Assessment |
|--------|------------|
| **Static circuit trap** | Output mux alone does not reduce gates |
| **Authorized exclusion** | One bug = broken retrieval soundness |
| **Compaction complexity** | Option 3 may be months of work |
| **Set-equality floor** | Top-k / set constraints may stay Θ(`N_sel`) |

### Verdict

| Question | Answer |
|----------|--------|
| Worth Phase 6B-1 (plaintext + cost model)? | **Yes — P0** |
| Worth Phase 6B-2 (gadget + ideal vs actual analysis)? | **Yes — P1** |
| Worth Phase 6B-3 (full ZK path) unconditionally? | **Conditional — P2 after data** |
| Worth delaying paper for full 6B-3? | **No** — ship ideal curve + prototype story if needed |

---

## 3. Relationship to ACL-Class Compression (Phase 5)

| Dimension | ACL-class (Phase 5) | Visibility-gated (Phase 6) |
|-----------|---------------------|----------------------------|
| **Compresses** | Dynamic auth state openings + policy evals | ADC / PQ distance evals |
| **Parameter** | `N_acl / N_sel` | `N_vis / N_sel` |
| **Mechanism** | Class table + binding + policy-once | Skip distance for provably invisible slots |
| **Phase 5C result** | Wins when `N_acl` small; loses when `N_acl → N_sel` | Not yet measured |
| **Composable?** | Yes — policy-once per class + distance-on-visible per slot | Combined cost model in design doc §G |

**Paper narrative:** two structure-aware optimizations for committed authorization views:

- “Few distinct ACL classes” → Phase 5 curve.
- “Few visible candidates” → Phase 6 curve.

Neither replaces the other. A corpus can have small `N_acl` **and** small `N_vis/N_sel`.

---

## 4. Recommended Priority

```
P0  Phase 6B-1  plaintext gated reference + equivalence tests
P1  Phase 6B-2  cost model + ideal N_vis/N_sel figure + static-circuit honesty
P2  Phase 6B-3  full ZK gated path (go/no-go after P1)
P3  Combined ACL+gated benchmark + paper figures
```

**Parallel safe work:** Phase 6B-1 can start immediately; no Rust changes required.

**Do not start with:** full `set_based_auth` fork before PG-* tests pass.

---

## 5. Minimum Publishable Version (MPV)

Acceptable systems/security submission **without** Phase 6B-3:

| Asset | Content |
|-------|---------|
| **Problem** | Proof-carrying authorized retrieval (positioning reset) |
| **Kernel** | Committed + ACL-class ZK paths (Phase 0–5) |
| **Security** | Attack matrix (Phase 4C) |
| **Eval RQ2–3** | Overhead vs baseline; scaling in N_sel |
| **Eval RQ4 (partial)** | N_acl/N_sel curve (Phase 5C) |
| **Eval RQ4 (gated)** | **Ideal** N_vis/N_sel cost model + explanation of static-circuit limit |
| **Semantics** | Gated ≡ masked equivalence (plaintext tests only) |

**Claim style:** “We formulate visibility-gated authorized scoring and show equivalence to the masked baseline; our cost model identifies ADC-on-visible as the next optimization target; fixed-shape circuits realize policy savings (ACL-class) but not yet distance gating.”

This satisfies honesty without unfinished ZK engineering blocking the story.

---

## 6. Top-Tier Enhanced Version

Adds to MPV:

| Enhancement | Requirement |
|-------------|-------------|
| **Implemented gated ZK path** | Phase 6B-3 with ZK-01…ZK-15 |
| **Measured gate reduction** | BM-* at ≥5 visibility ratios; repeat=3 |
| **Compaction gadget** | Documented completeness + soundness |
| **Combined figure** | ACL × visibility 2D or two-panel figure |
| **Post-filter quant gap** | Non-toy workload (already on readiness plan) |

Target venues: VLDB / SIGMOD / ICDE main track per [top_tier_readiness_plan.md](top_tier_readiness_plan.md).

---

## 7. If Full ZK Gating Is Too Hard — Paper Framing

Use a **three-layer presentation** (recommended regardless):

### Layer 1 — Semantics (always include)

- Define gated program; prove equivalence to masked baseline **in plaintext**.
- Emphasize authorized-exclusion risk and circuit-computed visibility.

### Layer 2 — Cost model / prototype (include in MPV)

- Plot **ideal** `C_gated` vs `C_current` over `N_vis/N_sel`.
- Show **implemented** `auth_committed` / `auth_acl_class` gate counts flat w.r.t. visibility ratio (distance term dominates).
- Caption: *“Static fixed-shape circuits do not reduce constraints via conditional assignment alone.”*

### Layer 3 — Implementation (optional)

- If 6B-3 ships: add measured `auth_gated` series.
- If not: position as **future work** with frozen design ([phase6_visibility_gated_design.md](phase6_visibility_gated_design.md)) and test plan ready.

**Avoid:** claiming “we skip invisible distance in the prover” unless gate count data supports it.

**Acceptable ablation text:**

> “Visibility-gated scoring reduces plaintext ADC evaluations from `N_sel` to `N_vis` while preserving authorized top-k. Our Plonky2 realization of masked distance still allocates PQ constraints for all `N_sel` slots; §6.3 describes compaction-based circuit shaping required for proof-size/gate-count savings.”

---

## 8. Go / No-Go Checklist for Phase 6B-3

Proceed to full ZK path **only if all true**:

- [ ] PG-01…PG-07 pass (gated ≡ masked)
- [ ] AT-01 passes (exclusion attack detected in oracle)
- [ ] `(N_sel - N_vis) · C_dist > C_compact` at target ratios (e.g. `N_vis/N_sel ≤ 0.25`)
- [ ] Compaction design reviewed for completeness + soundness
- [ ] Additive API plan approved (no baseline path mutation)
- [ ] Engineering budget ≥ ~2–4 weeks for proof path + ZK tests

Otherwise: stop at 6B-2 and publish ideal curve.

---

## 9. Key Messages (Frozen)

1. **Visibility-gated scoring is not a syntax change—it is a proof obligation preservation problem.**
2. **`if visibility then compute else skip` in a static circuit does not reduce gates.**
3. **Real savings need changed circuit shape (compaction / phased proof / parameterized size).**
4. **Authorized exclusion is the critical security failure mode.**
5. **Phase 6A commits to design + tests + cost model—not to finished ZK optimization.**

---

## 10. Next Step: Phase 6B-1 Plaintext Reference

**Immediate actions (recommended order):**

1. Add `auth_reference/visibility_gated_reference.py`:
   - `score_candidate_gated(c, user, checkpoint)` — compute ADC only when `g=1`.
   - `run_authorized_reference_gated(...)` — same signature as `run_authorized_reference`.
   - `compare_gated_vs_masked_reference(...)` — returns equivalence dict.
   - `estimate_visibility_gated_cost(n_sel, n_vis, ...)` — plaintext cost model.

2. Add `tests/test_visibility_gated_reference.py` implementing PG-01…PG-07, PG-20…PG-22.

3. Add `tests/test_visibility_gated_cost_model.py` implementing CM-01…CM-04.

4. Add `scripts/bench_visibility_gated_model.py` (plaintext counters only, no ZK) to emit N_vis sweep table for paper figure—**optional CSV in 6B-1, not Phase 6A**.

5. Update [phase6_visibility_gated_design.md](phase6_visibility_gated_design.md) status banner to “6B-1 in progress” when implementation starts.

**Exit gate for 6B-2:** all PG-* + CM-* green; draft N_vis/N_sel ideal figure from cost model.

---

## 11. Document Index (Phase 6A deliverables)

| Document | Role |
|----------|------|
| [phase6_visibility_gated_design.md](phase6_visibility_gated_design.md) | Semantics, alternatives, cost model, risks |
| [phase6_visibility_gated_test_plan.md](phase6_visibility_gated_test_plan.md) | Test IDs and acceptance criteria |
| [phase6_visibility_gated_decision.md](phase6_visibility_gated_decision.md) | This memo — priority and publication framing |

**No source code modified in Phase 6A.**

---

## 12. Updated Decision After Access-Aware Indexing Review (Phase 6A-2)

**Date:** Phase 6A-2 design freeze  
**Companion:** [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md)

After reviewing access-aware indexing (Veda / EffVeda) as **motivation only**, Phase 6 scope is refined:

### What changed

| Before (6A) | After (6A-2) |
|-------------|--------------|
| Primary implementation target: candidate-level gated oracle | Primary target: **plaintext proof planning reference** with pure/impure regions |
| Compaction Option 3 as main long-term path | **Pure-invisible regions** + impure fallback as preferred structure; compaction deferred |
| Cost axis: `N_vis/N_sel` only | Add **pure/impure ratios** and SA/PA discussion framework |
| Single gating metaphor | **Proof plan** `Plan(q,U,σ)` covering all slots |

### Conclusions (frozen)

1. **Continue Phase 6B-1** — but implement **`proof_planning_reference` first**, not standalone candidate-level gated module alone. Candidate-level gating remains the **semantic floor** (impure region of size 1).

2. **Do not directly implement full ZK candidate-level dynamic compaction** as the first engineering milestone. Static fixed-shape circuits will not benefit from per-slot `if visibility` without shape change.

3. **Treat pure/impure proof planning as the preferred path** toward measurable proof-cost reduction:
   - `pure_invisible` regions → skip ADC + batched policy
   - `pure_visible` regions → batched policy + full distance
   - `impure` regions → existing masked / ACL-class path

4. **Veda/EffVeda are related work**, not dependencies. Do not claim Veda extension. Pure/impure here means **proof planning**, not trusted index execution.

5. **Phase 6B-2** should produce two figure families: `N_vis/N_sel` (6A) and **pure/impure structural ratio** (6A-2).

6. **Phase 6B-3** (optional ZK): start with **region purity gadget**, not full visible-subset compaction integrated into V3DB proof loop.

### Revised priority stack

```
P0  Phase 6B-1  plaintext proof planning reference + PP-* / PI-* / COV-* tests
P1  Phase 6B-2  cost model + N_vis/N_sel + pure/impure ratio sweeps (plaintext)
P2  Phase 6B-3  region purity component ZK (conditional)
P3  Full planned ZK path integrated with V3DB (only if P2 break-even)
```

### MPV paper claim (updated)

> “We formulate access-structure-aware **proof planning** over committed authorization views—pure-visible, pure-invisible, and impure regions—showing equivalence to masked-distance authorized top-k. Inspired by access-aware indexing but under malicious security; ideal cost scales with visible distance work and region purity, not merely global visibility ratio.”
