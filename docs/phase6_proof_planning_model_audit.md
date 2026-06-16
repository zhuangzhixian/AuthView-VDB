# Phase 6B-2.7: Proof-Planning Cost Model Audit

**Phase:** 6B-2.7  
**Purpose:** Clarify what the cost model measures, what can be claimed in a paper, and what requires future ZK calibration.

---

## 1. Model Type

The Phase 6B proof-planning evaluation uses a **proof-planning work-unit model** — a plaintext counter of relative proof obligations under different region layouts.

It is **not** a measured ZK gate model. Ratios such as `plan_vs_masked_cost` express **structural proof-work savings** in abstract units, not observed circuit size or prove time.

---

## 2. Current Weights (`DEFAULT_COST_PARAMS`)

| Symbol | Value | Meaning in work-unit model |
|--------|-------|----------------------------|
| `C_dist` | 10 | Per-candidate distance / ADC proof work |
| `C_vis` | 3 | Per-candidate visibility / policy evaluation |
| `C_mask` | 1 | Per-candidate masked-distance binding |
| `C_region_pure` | 5 | One-time pure-visible or pure-invisible region certificate |
| `C_region_impure` | 2 | Impure region overhead before per-slot fallback |
| `C_topk_per_candidate` | 1 | Top-k contribution per candidate (fixed-shape) |
| `C_compact` | 5 | Ideal visible-subset compaction overhead |

Source: `auth_reference/proof_planning_reference.py` → `estimate_proof_plan_cost()`.

### Masked baseline

```
C_masked = N_valid × (C_vis + C_dist + C_mask + C_topk)
```

### Planned (conservative)

```
pure_visible:   C_region_pure + valid_count × C_dist
pure_invisible: C_region_pure
impure:         C_region_impure + valid_count × (C_vis + C_dist + C_mask)
+ N_valid × C_topk
```

### Ideal visible compaction

```
C_ideal = N_valid × C_vis + N_vis × C_dist + C_compact + N_vis × C_topk
```

---

## 3. Role of Weights

These weights are **exploratory** — chosen to reflect relative ordering:

- Distance work dominates per-slot cost (`C_dist` largest).
- Region purity certificates are cheap relative to skipping many ADC proofs (`C_region_pure` ≪ `k × C_dist` for large blocks).
- Impure fallback retains full per-slot path.

**No claim** should be made that absolute cost numbers match real prover time. Only **monotonic trends** and **ratios vs masked baseline** are intended for paper discussion.

---

## 4. Two Model Layers

| Layer | Status | Use |
|-------|--------|-----|
| **Work-unit model** | Implemented (Phase 6B) | Planner trend analysis; locality sweep; figure axes = `plan_vs_masked_cost` |
| **ZK-calibrated model** | Future work | Replace unit weights with measured gadget gate deltas from `auth_committed`, ACL-class, region purity gadget |

Future calibration sketch:

```
C_dist_zk ≈ Δ gates(auth_committed ADC path per slot)
C_vis_zk  ≈ Δ gates(policy gadget per slot)
C_region_pure_zk ≈ gates(region purity lemma)
```

Until calibrated, **do not** equate work-unit ratios with ZK speedup percentages.

---

## 5. Figure Placement Guidance

### Main paper (recommended after 6B-2.7)

| Figure | Variable | Claim level |
|--------|----------|-------------|
| Locality vs cost | access locality ∈ [0,1] | Structural trend under work-unit model |
| Visibility × locality interaction | visible ratio + locality | Same |
| Impure ratio vs cost | impure_valid_ratio | Explains cost increase mechanism |
| Block size trade-off | region granularity | System parameter sensitivity |

**Primary y-axis:** `plan_vs_masked_cost` (not `PA_plan`).

### Appendix / sanity only

| Figure | Issue |
|--------|-------|
| `PA_plan` vs visible ratio | Oracle denominator `max(1, N_vis)` tiny at low visibility → inflated PA |
| Pure-invisible ratio vs dist_reduction | Near-collinear by construction (same mechanism) |
| Legacy purity-mode figures (clustered/adversarial) | Hand-crafted extremes; superseded by locality sweep |

---

## 6. PA_plan Amplification at Low N_vis

```
PA_plan = estimated_cost_plan / (max(1, N_vis) × (C_dist + C_topk))
```

When `N_vis = 0`, denominator = 1×11 = 11 while numerator ≈ hundreds (top-k over all slots). **PA_plan → large** even when `plan_vs_masked_cost` is small (~0.07).

**Recommendation:** Use `plan_vs_masked_cost` in main text. Mention PA only in discussion with visible_ratio ≥ 0.1 filter or as normalized future work.

---

## 7. What Can Be Claimed

**Can claim:**

- Cost-model evaluation shows proof-planning benefit under **access locality** / pure-region structure.
- At fixed visible ratio, higher locality → lower planned/masked cost ratio (work-unit model).
- Low locality (mixed visibility within regions) → impure fallback dominates → cost ≈ masked baseline.
- All planned executions remain top-k equivalent to masked baseline (correctness).

**Cannot claim:**

- Implemented ZK gates decrease by the same ratio as `plan_vs_masked_cost`.
- Static per-candidate conditional mux reduces circuit size.
- PA_plan values at N_vis ≈ 0 are meaningful without normalization fix.

---

## 8. Locality Workload (Phase 6B-2.7)

Replaces hand-crafted `clustered` / `adversarial_mixed` purity modes as **default paper workload**.

- **locality = 1:** visibility clustered within regions → pure_visible / pure_invisible blocks.
- **locality = 0:** visibility spread within regions → impure regions.
- **Intermediate:** interpolated slot positions within each region.

Answers: *“At the same visible ratio, does access locality increase proof-planning benefit?”*

---

## Related

- [phase6_proof_planning_paper_figures_log.md](phase6_proof_planning_paper_figures_log.md)
- [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md)
- [auth_reference/proof_planning_reference.py](../auth_reference/proof_planning_reference.py)
