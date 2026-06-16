# Phase 6A: Visibility-Gated Scoring — Design Freeze

**Phase:** 6A (design documentation only — no implementation)  
**Branch:** `phase6-visibility-gated-design`  
**Status:** frozen specification for Phase 6B implementation planning

This document defines **visibility-gated scoring** as a proof-preserving optimization over the current **masked-distance baseline**, specifies soundness obligations, compares circuit alternatives, and outlines cost models and evaluation plans.

**Related:** [formal_statement.md](formal_statement.md), [security_properties.md](security_properties.md), [next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md), [phase5_acl_class_eval_log.md](phase5_acl_class_eval_log.md), [phase5_acl_class_proof_log.md](phase5_acl_class_proof_log.md)

**Phase 6A does not implement any ZK optimization.** It freezes semantics, risks, and a recommended prototype path.

---

## A. Motivation

### Current state (Phase 0–5C)

The repository implements proof-carrying authorized IVF-PQ retrieval with:

- **Object-level committed auth** (`auth_committed`): per-slot policy + Merkle label opening.
- **Slot-aligned committed auth** (`auth_slot_aligned`): layout optimization only.
- **ACL-class committed auth** (`auth_acl_class`): policy-once per ACL class + per-slot binding opening.

All paths share the same **authorized top-k semantics**: rank the full declared candidate set `Cand(q,S,θ)` by masked distance `hat_d_x`, not post-filter.

### Why masked-distance cost scales with N_sel

In every implemented path, the per-slot loop roughly does:

1. Open content / auth witness for slot `x`.
2. Compute or bind approximate distance `d_x = ADC(q, x)` (PQ LUT accumulation).
3. Compute visibility `v_x = P(γ_U, λ_x, σ)` (or inherit from class visibility).
4. Apply mask: `hat_d_x = (valid_x · v_x) · d_x + (1 - valid_x · v_x) · d_max`.
5. Feed `(cid_x, hat_d_x)` into set equality + top-k constraints.

Steps 2–4 run for **every valid slot** in the fixed-shape grid, even when `v_x = 0`. This is **semantically correct** but expensive when:

$$
N_{vis} = |\{x \in Cand : valid_x = 1 \land v_x = 1\}| \ll N_{sel}
$$

Enterprise workloads often have large probed candidate sets with **most slots invisible** under `(U, σ)` (wrong tenant, insufficient clearance, inactive state, etc.). Phase 5C showed ACL-class compression helps mainly when `N_acl ≪ N_sel`; it does **not** remove per-slot ADC/PQ distance work for invisible candidates.

### Goal of visibility-gated scoring

**Visibility-gated scoring** aims to make proof cost correlate with **`N_vis / N_sel`**, not only `N_acl / N_sel`, by avoiding or reducing expensive distance computation for candidates that are **provably invisible**—while preserving **exact equivalence** with the masked-distance baseline:

$$
R_{gated} = R_{masked}
$$

---

## B. Current Masked-Distance Semantics (Baseline)

### Definitions

For each candidate slot `x` in the fixed-shape probed grid:

| Symbol | Meaning |
|--------|---------|
| `valid_x` | Slot occupancy bit (padding slots invalid) |
| `d_x` | Approximate distance `ADC(q, x)` under committed PQ codes / LUTs |
| `v_x` | Visibility bit: `P(γ_U, λ_x, σ) ∈ {0,1}` |
| `g_x` | Combined gate: `valid_x · v_x` |
| `d_max` | Sentinel distance (implemented: `2^62 - 1`) |
| `hat_d_x` | Authorized masked distance |

**Masking (Form B, implemented in `auth_mask_distance_gadget`):**

$$
g_x = valid_x \cdot v_x
$$

$$
\hat d_x = g_x \cdot d_x + (1 - g_x) \cdot d_{max}
$$

**Retrieval result:**

$$
R = \mathrm{TopK}_k\bigl(\{(cid_x, \hat d_x) \mid x \in Cand(q,S,\theta)\}\bigr)
$$

with V3DB-compatible tie-breaking on `hat_d_x` (then `cid`).

### What the current circuit does

For **every** slot `(i,j)` in the `n_probe × n` grid:

1. **Always** accumulates PQ sub-distances into `d_x` (via LUT lookup + add chain).
2. **Always** evaluates policy visibility (directly or via ACL-class inheritance).
3. **Always** runs `auth_mask_distance_gadget(valid, visibility, d_x, d_max)`.

Invisible candidates still pay **full ADC constraint cost**; invisibility only affects the **output** of the mux (`hat_d_x = d_max`), not whether ADC constraints are generated.

This matches plaintext oracle `compute_masked_distance` in `auth_reference/reference.py`.

---

## C. Visibility-Gated Semantics (Target)

### Intended gated program

Partition candidates by combined gate `g_x = valid_x · v_x`:

| Condition | Distance proof obligation | Masked output |
|-----------|---------------------------|---------------|
| `g_x = 1` (visible) | Prove `d_x = ADC(q, x)` correctly | `hat_d_x = d_x` |
| `g_x = 0` (invalid or invisible) | **Skip or reduce** ADC proof | `hat_d_x = d_max` |

**Output requirement (hard):**

$$
\forall x:\ \hat d_x^{gated} = \hat d_x^{masked}
\quad\Rightarrow\quad
R_{gated} = R_{masked}
$$

### Plaintext reference (Phase 6B-1)

Two oracles must agree on all fixtures:

- `run_authorized_reference` — current masked baseline (already exists).
- `run_authorized_reference_gated` — gated program above (to implement).

Gated oracle may **compute** `d_x` only when `g_x = 1`, but **output** `hat_d_x` must match baseline for every slot.

### What gating is **not**

- **Not** server-side pre-filter outside `Cand`.
- **Not** dropping slots from the declared candidate set (coverage obligation unchanged).
- **Not** a prover-chosen “skip bit” without circuit-derived visibility.
- **Not** `if visibility then compute else skip` in a static circuit **by itself**—that does not reduce gates (see §E, §G).

---

## D. Required Soundness Conditions

Visibility-gated scoring is a **proof-preserving optimization** only if the following hold.

### D.1 Invisible candidates cannot rank highly

If `g_x = 0`, then `hat_d_x = d_max`. Therefore invisible or invalid slots cannot enter top-k unless fewer than `k` visible candidates exist (same as baseline).

**Attack ruled out:** invisible object smuggled into `R` with low distance.

### D.2 Visible candidates must use correct distance

If `g_x = 1`, the proof must bind `d_x` to the committed PQ codes / LUT pipeline for `(q, x)`.

**Attack ruled out:** prover assigns arbitrary low `hat_d_x` to a visible slot without ADC soundness.

### D.3 Visible candidates cannot be declared invisible (authorized exclusion)

If the prover could set `gate_x = 0` for a slot that is **actually visible** under committed labels and public `γ_U`, they could:

- assign `hat_d_x = d_max`, excluding a closer authorized neighbor from top-k;
- violate retrieval soundness without breaking Merkle openings.

**Mitigation (mandatory):** `v_x` (hence `g_x`) must be **circuit-computed** from committed auth state + public user context—not a free prover witness bit.

This is the **authorized exclusion** risk; it is the primary reason Phase 6 is security-sensitive.

### D.4 Invisible candidates cannot be declared visible

If the prover sets `v_x = 1` for an invisible slot, they must still produce a low `d_x` to benefit; policy must fail unless label opening + `P` genuinely pass.

**Mitigation:** same as today—committed label / ACL class opening + `auth_policy_visibility_gadget` (or class-level equivalent).

### D.5 Top-k equivalence

Let `S_masked = {(cid_x, hat_d_x^{masked})}` and `S_gated = {(cid_x, hat_d_x^{gated})}` over the **same** slot set. Require:

$$
S_masked = S_gated \quad\Rightarrow\quad \mathrm{TopK}_k(S_masked) = \mathrm{TopK}_k(S_gated)
$$

Implemented via unchanged set-equality + sorted-distance + top-k constraints over the **full** `n_probe × n` multiset.

### D.6 Coverage unchanged

$$
|Cand| = N_{sel} = n_{probe} \cdot n
$$

Gating must not remove slots from the witness grid. “Skipping work” ≠ “skipping slots.”

---

## E. Circuit Design Alternatives

### Option 1: Distance mux after full computation (current baseline)

**Structure:** compute `d_x` for all slots → compute `v_x` → `auth_mask_distance_gadget`.

| Pros | Cons |
|------|------|
| Implemented, tested, attack-informed | **No ADC savings** when `N_vis ≪ N_sel` |
| Simple soundness story | Policy cost still per-slot (except ACL-class path) |
| Matches plaintext oracle directly | Gates scale with `N_sel` for distance + mask |

**Verdict:** correct reference implementation; optimization target, not destination.

---

### Option 2: Conditional distance with visibility-controlled arithmetic

**Idea:** use `v_x` to select whether ADC constraints bind `d_x` or force `d_max`.

**Static-circuit reality:**

In Plonky2-style **fixed-shape** circuits, a conditional such as:

```
if g_x == 1:
    prove ADC(q, x) = d_x
else:
    d_x := d_max
```

still typically instantiates **both** sub-circuits or pays mux overhead on **every** slot. `auth_mask_distance_gadget` already muxes the **output**; it does **not** remove LUT lookups or PQ accumulation constraints upstream.

| Pros | Cons |
|------|------|
| Local change to mask gadget region | **Unlikely to reduce gate count** in static layout |
| Easier than compaction | Prover could still assign fake `d_x` if ADC constraints absent without careful design |
| Good for witness-time short-circuit | False sense of optimization if only output is muxed |

**Verdict:** insufficient alone for paper-quality gate reduction; useful only as stepping-stone **if** paired with constraint gating that genuinely disables ADC sub-circuit (hard in uniform circuits).

---

### Option 3: Visibility-first candidate compaction (recommended long-term)

**Idea:**

1. Prove visibility `v_x` (or `g_x`) for all `N_sel` slots (same auth openings as today).
2. **Compact** visible slots into a buffer `Cand_vis` of capacity `N_vis_max` (or run two-phase proof).
3. Run ADC + partial top-k **only** on `Cand_vis`.
4. Merge back: invisible slots contribute `(cid, d_max)`; prove multiset equality with baseline scoring.

**Additional proof obligations (compaction soundness):**

| Property | Meaning |
|----------|---------|
| **Completeness** | Every slot with `g_x = 1` appears in `Cand_vis` |
| **Soundness** | No slot with `g_x = 0` appears in `Cand_vis` |
| **Membership binding** | Each compacted entry maps to a unique original slot / cid |
| **No duplication** | Each visible slot included at most once |

**Variants:**

- **3a. Fixed-shape compaction with padding:** output array length `N_sel`; compacted region holds visible entries; rest padded with `(⊥, d_max)`. Still fixed shape; savings depend on whether ADC loop runs only over compact prefix (requires **variable-length loop unrolling** or separate circuit size per `N_vis`—not standard today).

- **3b. Two-proof composition:** Proof A = visibility + compaction; Proof B = distance on visible multiset. Verifier checks composition. Higher engineering cost; potentially real savings.

- **3c. Per-list pure/invisible blocks:** if entire probed lists are all invisible, skip list ADC entirely (stronger structural assumption; see [next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md)).

| Pros | Cons |
|------|------|
| Only plausible path to **gates ∝ N_vis** | Highest design + implementation complexity |
| Aligns with paper story (structure-aware cost) | Compaction errors → authorized exclusion |
| Composable with ACL-class (policy-once + gate-once) | May need non-uniform circuit family or recursive proof |

**Verdict:** **recommended research direction** for Phase 6B-3+ if Phase 6B-2 cost model shows sufficient headroom.

---

## F. Recommended Prototype Path

### Phase 6B-1 — Plaintext gated reference (P0)

**Deliverables:**

- `auth_reference/visibility_gated_reference.py` (or extend `reference.py`):
  - `score_candidate_gated`, `run_authorized_reference_gated`
  - `compare_gated_vs_masked_reference` on all existing fixtures
- Cost counters:
  - `count_policy_evals`, `count_adc_evals` (plaintext proxies)
  - `estimate_gated_cost(N_sel, N_vis, N_acl, …)`
- Tests: equivalence top-k, masked distance multiset, visibility consistency.

**Exit criterion:** gated oracle matches masked oracle on 100% of regression fixtures + partial-visible sweeps.

---

### Phase 6B-2 — Conservative ZK prototype (P1)

**Scope:** component-level, not necessarily full V3DB path.

**Deliverables:**

- `visibility_gate_gadget` (or extension to `auth_mask_gadget`):
  - Prove `g_x` derived from circuit visibility (not witness).
  - Demonstrate **simulated** gate budget: count ADC sub-constraints enabled/disabled under ideal gating.
- Benchmark script extension or standalone micro-bench:
  - Compare **ideal gated cost model** vs **actual** static circuit gate count.
- Document explicitly when static circuit **fails** to realize savings.

**Exit criterion:** paper can show **N_vis/N_sel curve for ideal model** + honest “static circuit plateau” line from current path—even before full optimization lands.

---

### Phase 6B-3 — Optional full ZK path (P2, conditional)

**Only if** 6B-1 equivalence holds and 6B-2 shows compaction overhead `<` ADC savings at target `N_vis/N_sel`.

**Deliverables:**

- Additive path: `set_based_auth_ivf_pq_gadget_committed_gated` + proof + PyO3 API.
- Do **not** modify existing `auth_committed` / `auth_acl_class` paths.
- Equivalence ZK tests vs `auth_committed` on shared fixtures.
- `bench_visibility_gated_paths.py` + N_vis/N_sel CSV.

**Go/no-go gate:** authorized-exclusion negative tests + gated ≡ masked top-k on ZK API.

---

## G. Cost Model

### G.1 Current path (implemented)

Per fixed-shape proof over `N_sel` slots:

$$
C_{current} \approx N_{sel} \cdot (C_{open} + C_{vis} + C_{dist} + C_{mask}) + C_{set} + C_{topk}
$$

| Term | Typical dominance | Notes |
|------|-------------------|-------|
| `C_open` | auth Merkle / binding | Reduced by ACL-class when `N_acl ≪ N_sel` |
| `C_vis` | policy gadget | Reduced by ACL-class policy-once |
| `C_dist` | PQ LUT + accumulate | **Still × N_sel today** |
| `C_mask` | small mux | Always × N_sel |
| `C_set`, `C_topk` | V3DB set equality | Depends on `N_sel`, not `N_vis` |

Phase 5C observation: when `N_acl → N_sel`, ACL path overhead exceeds savings—**distance term unchanged**.

---

### G.2 Ideal gated path (target upper bound on savings)

$$
C_{gated,ideal} \approx N_{sel} \cdot C_{vis} + N_{vis} \cdot C_{dist} + C_{compact} + C_{set} + C_{topk}
$$

| Term | Scaling | Notes |
|------|---------|-------|
| `N_sel · C_vis` | visibility still per-slot (or per-class) | Cannot skip without breaking exclusion soundness |
| `N_vis · C_dist` | **key win** | Only visible slots pay ADC |
| `C_compact` | depends on compaction design | Must be ≪ `(N_sel - N_vis) · C_dist` to win |
| `C_set`, `C_topk` | often still Θ(`N_sel`) unless multiset structure changes | May limit tail savings |

**Break-even (ideal):**

$$
N_{sel} \cdot C_{dist} \stackrel{?}{>} N_{vis} \cdot C_{dist} + C_{compact}
\quad\Leftrightarrow\quad
(N_{sel} - N_{vis}) \cdot C_{dist} > C_{compact}
$$

---

### G.3 Static circuit honesty constraint

> **Conditional assignment ≠ conditional constraints.**

In a uniform static circuit:

- `hat_d = g · d + (1-g) · d_max` costs **O(1)** mux per slot regardless of `g`.
- LUT lookups wired for every slot cost **O(M)** per slot regardless of `g`.
- **Gate count does not drop** merely because witness assigns `g = 0`.

Real gate reduction requires at least one of:

1. **Shape change:** smaller circuit when `N_vis` is small (separate circuit params, recursive proof, or off-chain witness compression with on-chain proof size tied to `N_vis`).
2. **Compaction with sparse ADC sub-circuit:** physically fewer ADC gadgets in the constraint system.
3. **Two-phase proof:** phase-1 visibility, phase-2 distance on visible multiset only.

Phase 6A **does not promise** (3) is feasible in the current Plonky2 fixed-shape pipeline without substantial new architecture.

---

## H. Evaluation Plan

### Primary figure: N_vis / N_sel vs cost ratio

| Axis | Definition |
|------|------------|
| **X** | `visible_ratio = N_vis / N_sel` (or `1 - invisible_ratio`) |
| **Y** | `median_gates` or `ideal_cost_ratio` or `prove_time` |

| Series | Source |
|--------|--------|
| `auth_committed` | Current implemented path (flat w.r.t. visibility ratio for distance component) |
| `auth_acl_class` | Optional: same flat distance, lower policy at small `N_acl` |
| `ideal_gated` | Phase 6B-1/6B-2 cost model (not fake ZK numbers) |
| `auth_gated` | Phase 6B-3 only if implemented |

### Workload generator

Extend partial-visible label builder with tunable invisible fraction:

- Fix `N_sel = 256` (`n_probe=4`, `slot=64`).
- Sweep `visible_ratio` ∈ `{0.05, 0.1, 0.25, 0.5, 0.75, 1.0}` (≥5 points).
- Record `N_vis`, `N_sel`, policy eval count, ADC eval count (plaintext); gates (ZK).

### Secondary ablations

- ACL-class + gated composition (policy-once + distance-on-visible).
- Breakdown: auth-component gates vs PQ/set-component gates.
- Prove time vs gate count (expect correlation but not identity).

### Honest reporting

If Phase 6B-3 is deferred, paper still includes **ideal gated curve** + explanation of static-circuit limit—see [phase6_visibility_gated_decision.md](phase6_visibility_gated_decision.md).

---

## I. Risks and Non-Goals

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Authorized exclusion** (declare visible slot invisible) | Critical | `v_x` must be circuit-computed from committed auth; never prover-supplied gate bit |
| **Invisible smuggling** (declare invisible visible with fake low d) | High | Policy + opening soundness (existing) |
| **Compaction incomplete** (drop visible slot) | Critical | Completeness proof / equivalence tests |
| **False optimization claim** (mux only) | Reputational | Separate ideal model from implemented gates; §G.3 |
| **Coverage erosion** | Critical | Fixed-shape `N_sel` grid unchanged |
| **Interaction with ACL-class** | Medium | Equivalence tests on combined fixtures |

### Phase 6A non-goals

- ❌ No Rust / Python implementation
- ❌ No new CSV / benchmark artifacts
- ❌ No promise of full ZK gate reduction in static circuit
- ❌ No dynamic candidate set outside declared `Cand`
- ❌ No private credentials / hidden `γ_U` (out of scope)
- ❌ No replacement of masked-distance baseline paths

### Phase 6A commitments

- ✅ Frozen gated semantics equaling masked baseline outputs
- ✅ Explicit soundness conditions (especially authorized exclusion)
- ✅ Three-option circuit comparison with static-circuit caveat
- ✅ Layered cost model (current vs ideal)
- ✅ Phased prototype plan (6B-1 → 6B-2 → optional 6B-3)
- ✅ Evaluation blueprint for N_vis/N_sel figure

---

## Appendix: Mapping to Current Code (reference only)

| Baseline piece | Location |
|----------------|----------|
| Masked distance gadget | `src/merkle_ver/auth_mask_gadget.rs` |
| Policy visibility | `src/merkle_ver/auth_policy_gadget.rs` |
| Per-slot loop (committed) | `set_based_auth_ivf_pq_gadget_committed` in `set_based_auth.rs` |
| ACL-class inheritance | `inherit_slot_visibility_from_class_gadget` |
| Plaintext oracle | `auth_reference/reference.py` |

No changes to these files in Phase 6A.
