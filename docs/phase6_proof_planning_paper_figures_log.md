# Phase 6B-2.5: Paper-Ready Proof-Planning Figure Data

**Phase:** 6B-2.5 / 6B-2.6  
**Branch:** `phase6-proof-planning-paper-figures`  
**Status:** extended sweep + revised paper figures (cost model)

---

## Evaluation Goal

Extend Phase 6B-2 into **paper-ready figure data** for:

1. $N_{\mathrm{vis}}/N_{\mathrm{valid}}$ vs planned/masked **cost model** ratio
2. Pure/impure region ratio vs cost / $PA_{\mathrm{plan}}$
3. Grouping strategy comparison (acl_class, ivf_list, fixed_block)
4. fixed_block block_size effect on region count and cost
5. clustered vs adversarial_mixed degradation

**This is a plaintext proof-planning cost model — not measured ZK gate reduction.**

---

## Extended Sweep Configuration

| Parameter | Paper-ready value |
|-----------|-------------------|
| n_valid | 256 |
| n_lists | 4 |
| slot_per_list | 64 |
| top_k | 5 |
| visible_ratios | 0.0, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0 |
| grouping_strategies | acl_class, ivf_list, fixed_block |
| purity_modes | clustered, mixed, adversarial_mixed |
| block_sizes | 8, 16, 32, 64 (fixed_block only) |

**Row count:** 144 = 8 visible ratios × 3 purity modes × (2 non-block + 4 fixed_block)  
- acl_class: block_size **0** (NA)  
- ivf_list: block_size **0** (NA)  
- fixed_block: block_size ∈ {8, 16, 32, 64}

---

## Artifacts (revised figures, Phase 6B-2.6)

| File | Description |
|------|-------------|
| `artifacts/proof_planning_paper_metrics.csv` | Raw sweep (144 rows) |
| `artifacts/proof_planning_paper_summary.csv` | Aggregated medians per group |
| `artifacts/figures/proof_planning_cost_vs_visibility_by_purity.pdf` | **Main Fig 1** |
| `artifacts/figures/proof_planning_cost_vs_pure_invisible_ratio.pdf` | **Main Fig 2** |
| `artifacts/figures/proof_planning_distance_reduction_vs_pure_invisible.pdf` | **Main Fig 3** |
| `artifacts/figures/proof_planning_block_size_effect_revised.pdf` | **Main Fig 4** |
| `artifacts/figures/proof_planning_pa_appendix.pdf` | Appendix only |

**Deprecated (do not use as main figures):**

- `proof_planning_cost_vs_visibility.pdf` — acl/ivf overlap
- `proof_planning_purity_vs_cost.pdf` — pure_region_ratio confounds visible/invisible
- `proof_planning_block_size_effect.pdf` — single purity line only

PDF figures are generated locally; **not tracked in git**.

---

## Commands

```bash
PYTHONPATH=. python scripts/bench_proof_planning_model.py \
  --n-valid 256 --n-lists 4 --slot-per-list 64 \
  --visible-ratios 0.0,0.05,0.1,0.25,0.5,0.75,0.9,1.0 \
  --grouping-strategies acl_class,ivf_list,fixed_block \
  --purity-modes clustered,mixed,adversarial_mixed \
  --block-sizes 8,16,32,64 --top-k 5 \
  --output artifacts/proof_planning_paper_metrics.csv

PYTHONPATH=. python scripts/summarize_proof_planning_model.py \
  --input artifacts/proof_planning_paper_metrics.csv \
  --output artifacts/proof_planning_paper_summary.csv

PYTHONPATH=. python scripts/plot_proof_planning_figures.py \
  --input artifacts/proof_planning_paper_summary.csv \
  --output-dir artifacts/figures
```

---

## Figure Descriptions (Phase 6B-2.6)

### Main Fig 1: `proof_planning_cost_vs_visibility_by_purity.pdf`

- Grouping: **ivf_list only** (single strategy)
- X: $N_{\mathrm{vis}}/N_{\mathrm{valid}}$
- Y: planned / masked cost (**cost model**)
- Lines: clustered, mixed, adversarial_mixed
- Story: clustered saves cost at low visibility; adversarial_mixed → 1

### Main Fig 2: `proof_planning_cost_vs_pure_invisible_ratio.pdf`

- X: **pure_invisible_valid_ratio** = $N_{\mathrm{pi}}/N_{\mathrm{valid}}$
- Y: planned / masked cost
- Points colored by purity_mode
- Story: cost drops as pure-invisible **candidates** dominate (not generic pure regions)

### Main Fig 3: `proof_planning_distance_reduction_vs_pure_invisible.pdf`

- X: pure_invisible_valid_ratio
- Y: dist_reduction_plan (distance proof work saved)
- Markers by grouping_strategy
- Story: proof-planning opportunity = skip distance on pure-invisible mass

### Main Fig 4: `proof_planning_block_size_effect_revised.pdf`

- fixed_block, visible_ratio ≈ 0.5
- Left: region_count vs block_size; Right: plan_vs_masked_cost vs block_size
- Lines: three purity modes
- Story: block size controls region granularity and planning benefit

### Appendix: `proof_planning_pa_appendix.pdf`

- Cost-model $PA_{\mathrm{plan}}$ vs visible ratio (filtered visible_ratio ≥ 0.1)
- **Not recommended as main figure** — oracle denominator tiny at low $N_{\mathrm{vis}}$

---

## Figure Sanity Revision (Phase 6B-2.6)

### Problems with Phase 6B-2.5 figures

| Old figure | Issue |
|------------|-------|
| cost_vs_visibility | acl_class and ivf_list lines **overlap** (identical layout on synthetic grid) |
| purity_vs_cost | **pure_region_ratio** mixes pure_visible and pure_invisible regions |
| purity_vs_cost | **PA_plan** inflated when $N_{\mathrm{vis}}=0$ (oracle = max(1, N_vis)) |
| block_size_effect | Only clustered; no purity comparison |

### Better explanatory variables

| Variable | Why |
|----------|-----|
| **pure_invisible_valid_ratio** | Pure-invisible regions skip distance proofs — direct mechanism |
| **dist_reduction_plan** | Links structure to distance work reduction |
| **purity_mode** (lines) | Shows clustered vs adversarial degradation |
| **visible_ratio** (Fig 1) | Standard workload axis |

**pure_region_ratio** retained in CSV as auxiliary metric only — not main x-axis.

Plotting script loads **metrics CSV** (auto-detected from summary path) and derives ratios in `enrich_rows()`.

---

## PA Definition (Cost-Model PA)

```
oracle_authorized_cost = max(1, N_vis) × (C_dist + C_topk)
PA_plan  = estimated_cost_plan  / oracle_authorized_cost
PA_ideal = estimated_cost_ideal / oracle_authorized_cost
```

**Not** real proof-size PA or ZK gate amplification.

---

## Key Observations (144-row sweep)

1. **Correctness:** all cases `planned_equals_masked=true`, `validation_passed=true`.
2. **clustered + low visibility:** large `dist_reduction_plan` (up to 1.0); `plan_vs_masked` as low as ~0.07 (cost model).
3. **adversarial_mixed:** `impure_region_ratio → 1`; `plan_vs_masked ≈ 1.0` (no structural savings).
4. **clustered vs adversarial:** clustered pure_region_ratio consistently higher at mid visibility.
5. **fixed_block:** region_count decreases as block_size increases (8 → 64).
6. **ideal_vs_masked** rises with visible ratio (more visible distance work).

---

## How to Describe in the Paper

> “We evaluate a **plaintext proof-planning cost model** over committed authorization views. The model estimates relative proof obligation under pure-visible, pure-invisible, and impure regions compared to per-slot masked-distance baseline. **Reported ratios are not measured ZK gate counts.** Structural savings appear when authorization layout yields pure regions (clustered visibility); adversarial mixing within regions removes benefit. Real gate reduction would require region-specific proof circuits or visible-subset compaction (future work).”

Do **not** write “ZK gates reduced by X%” from these curves.

---

## Limitations

1. Plaintext cost model with fixed relative weights (`C_dist`, `C_region_pure`, etc.).
2. **Static circuit mux does not reduce gates** — fixed-shape ZK still pays per-slot ADC unless circuit shape changes.
3. Synthetic ACL layout (one class per IVF list).
4. PA normalization uses ideal oracle baseline — interpret carefully at very low $N_{\mathrm{vis}}$.

---

## Phase 6B-3 Recommendation

**Defer full ZK region gadget** until paper figures and architecture are drafted.

Proceed to Phase 6B-3 **only if**:

- Paper needs a ZK mechanism section beyond cost-model curves
- Break-even analysis shows `C_region_pure` overhead paid off for clustered enterprise ACL layouts
- Team capacity for region purity gadget without blocking paper writing

**Priority now:** integrate figures into paper draft + RQ table; optional 6B-3 as enhancement.

---

## Phase 6B-2.7: Locality-Aware Workload & Figure Redesign

### Why previous figures looked artificial

1. **Hand-crafted purity modes** (`clustered` / `adversarial_mixed`) are binary extremes, not a continuous workload axis.
2. **acl_class ≡ ivf_list** on synthetic grid → overlapping lines.
3. **pure_region_ratio** conflates pure_visible and pure_invisible regions.
4. **pure_invisible_valid_ratio ≈ dist_reduction_plan** — near-collinear by construction.
5. **PA_plan** unstable at low $N_{\mathrm{vis}}$ (see [phase6_proof_planning_model_audit.md](phase6_proof_planning_model_audit.md)).

### Locality-aware workload model

| Parameter | Meaning |
|-----------|---------|
| `locality ∈ [0,1]` | 1 = visibility clustered within regions; 0 = spread within regions |
| `visible_ratio` | Global $N_{\mathrm{vis}}/N_{\mathrm{valid}}$ |
| `grouping_strategy` | Region partition (ivf_list, fixed_block, acl_class) |

**Paper question:** At the same visible ratio, does higher access locality reduce planned/masked cost?

### Main figure recommendation (Phase 6B-2.7)

| Figure | File |
|--------|------|
| Locality vs cost | `proof_planning_locality_vs_cost.pdf` |
| Visibility × locality | `proof_planning_visibility_vs_cost_by_locality.pdf` |
| Impure ratio vs cost | `proof_planning_impure_ratio_vs_cost.pdf` |
| Block size trade-off | `proof_planning_region_granularity_tradeoff.pdf` |

**Appendix only:** `proof_planning_pa_appendix.pdf`

**Deprecated main figures:** legacy purity-mode PDFs from 6B-2.5/2.6.

### Locality sweep artifacts

| File | Rows |
|------|------|
| `artifacts/proof_planning_locality_metrics.csv` | 180 |
| `artifacts/proof_planning_locality_summary.csv` | 180 |

```bash
PYTHONPATH=. python scripts/bench_proof_planning_model.py \
  --workload-model locality_sweep \
  --visible-ratios 0.05,0.1,0.25,0.5,0.75,0.9 \
  --locality-values 0.0,0.25,0.5,0.75,1.0 \
  --grouping-strategies ivf_list,fixed_block,acl_class \
  --block-sizes 8,16,32,64 \
  --output artifacts/proof_planning_locality_metrics.csv
```

### What can be claimed

- Cost-model evaluation shows planning benefit under **access locality** / pure-region structure.
- At fixed visible ratio, higher locality → lower `plan_vs_masked_cost` (work-unit model).
- Low locality → impure fallback → cost ≈ masked baseline.
- All cases remain top-k equivalent to masked baseline.

### What cannot be claimed

- ZK gates decrease by the same ratio as `plan_vs_masked_cost`.
- Static mux reduces circuit size.
- PA_plan at $N_{\mathrm{vis}} \approx 0$ without normalization caveat.

---

## Phase 6B-2.8: Beta-Binomial Locality & Paper Figures

### Why line figures were insufficient

Phase 6B-2.7 rule-based locality behaved like a **discrete switch**: locality 0–0.75 often collapsed to masked baseline, locality 1.0 jumped to full benefit. Intermediate values lacked smooth, interpretable variation for a paper narrative.

### Beta-binomial locality model

For each region $r$, sample $p_r \sim \mathrm{Beta}(\alpha, \beta)$ with $\mathbb{E}[p_r]=\rho$ and concentration $\kappa = \kappa_{\max}(1-\lambda)+\kappa_{\min}$ controlling access locality $\lambda$:

- $\alpha = \rho \kappa$, $\beta = (1-\rho)\kappa$
- Low $\lambda$ → high $\kappa$ → $p_r \approx \rho$ → impure mixed regions
- High $\lambda$ → low $\kappa$ → $p_r \in \{0,1\}$ → pure visible/invisible regions
- Each candidate in region $r$ visible independently with probability $p_r$
- Multiple seeds (0–4) average stochastic variation

Default scale: `n_valid=1024`, `n_lists=32`, `seeds=0..4`.

### Main figure recommendation (Phase 6B-2.8)

| Figure | File |
|--------|------|
| Design-space heatmap | `proof_planning_heatmap_cost.pdf` |
| Cost breakdown | `proof_planning_cost_breakdown.pdf` |
| Degradation curve | `proof_planning_degradation_curve.pdf` |
| Granularity sensitivity | `proof_planning_granularity_sensitivity.pdf` |

**Appendix:** `proof_planning_pa_appendix.pdf`  
**Legacy (6B-2.7 line plots):** not primary paper figures.

### Beta sweep artifacts

| File | Rows |
|------|------|
| `artifacts/proof_planning_beta_metrics.csv` | 450 (= 90 configs × 5 seeds) |
| `artifacts/proof_planning_beta_summary.csv` | 90 |

```bash
PYTHONPATH=. python scripts/bench_proof_planning_model.py \
  --workload-model beta_locality \
  --n-valid 1024 --n-lists 32 --slot-per-list 32 \
  --visible-ratios 0.05,0.1,0.25,0.5,0.75,0.9 \
  --locality-values 0.0,0.25,0.5,0.75,1.0 \
  --grouping-strategies ivf_list,fixed_block \
  --block-sizes 16,32 --seeds 0,1,2,3,4 \
  --output artifacts/proof_planning_beta_metrics.csv
```

### What can be claimed

- Access locality creates proof-planning opportunity under the **work-unit cost model**.
- Planner safely degenerates to masked baseline under high impure-valid ratio.
- Planning benefit primarily reduces the **distance/ADC** cost component.
- All cases remain top-k equivalent to masked baseline.

### What cannot be claimed

- Implemented ZK gates decrease by the same ratio.
- Static mux provides gate savings.

---

## Phase 6B-2.9: Access-Aware Layout & SA/PA Evaluation

### Goal

Shift evaluation from random visibility locality to **access-aware physical layout design** under role-combination workloads.

### Role-combination workload

- `num_roles` ACL classes with increasing clearance levels
- `selectivity` = fraction of roles visible to user (clearance threshold)
- Candidates assigned to roles in probe-major order

### Physical layouts

| Layout | Meaning |
|--------|---------|
| `global` | Single global proof region (max impure fallback) |
| `acl_class` | Regions aligned with ACL classes |
| `merged_k` | k consecutive IVF lists merged into one region |
| `oracle_authorized_view` | Ideal visible / invisible partition (oracle) |

### Metrics (cost model)

| Metric | Meaning |
|--------|---------|
| `SA_commit` | Commitment / storage amplification vs content-only baseline |
| `PA_plan` | Proof amplification vs ideal authorized-view oracle |
| `plan_vs_masked_cost` | Planned / masked work-unit ratio |
| Region / impure ratios | Structural purity under each layout |

**Not measured ZK gate counts.**

### Main figure recommendation (Phase 6B-2.9)

| Figure | File |
|--------|------|
| SA vs PA trade-off | `proof_planning_sa_pa_tradeoff.pdf` |
| Cost breakdown by layout | `proof_planning_layout_cost_breakdown.pdf` |
| Impure ratio by layout | `proof_planning_layout_impure_ratio.pdf` |
| Selectivity sensitivity | `proof_planning_layout_selectivity_sensitivity.pdf` |

### Artifacts

```bash
PYTHONPATH=. python scripts/bench_proof_planning_layout.py \
  --output artifacts/proof_planning_layout_metrics.csv

PYTHONPATH=. python scripts/summarize_proof_planning_layout.py \
  --input artifacts/proof_planning_layout_metrics.csv \
  --output artifacts/proof_planning_layout_summary.csv

PYTHONPATH=. python scripts/plot_proof_planning_layout_figures.py \
  --input artifacts/proof_planning_layout_summary.csv \
  --output-dir artifacts/figures
```

### What can be claimed

- Access-aware layout creates proof-planning opportunity under cost model.
- Oracle authorized-view layout lower-bounds PA; global layout upper-bounds impure fallback.
- SA/PA trade-off mirrors access-aware indexing SA/QA but for **verifiable** retrieval.

### What cannot be claimed

- Implemented ZK gates decrease by plotted ratios.
- Repaired SA units equal production storage bytes.

---

## Phase 6B-2.10: Layout Model Repair

**Phase 6B-2.9 figures are exploratory and NOT paper-ready.** See [phase6_layout_model_failure_analysis.md](phase6_layout_model_failure_analysis.md).

Repaired model uses **access-signature workload** + layout-specific SA units. Sanity audit must pass before any new layout figures.

```bash
PYTHONPATH=. python scripts/bench_proof_planning_layout.py \
  --output artifacts/proof_planning_layout_metrics_repaired.csv
PYTHONPATH=. python scripts/audit_proof_planning_layout_model.py \
  --input artifacts/proof_planning_layout_summary_repaired.csv
```

**Do not re-plot until sanity CSV all-pass.**

---

## Related

- [phase6_proof_planning_cost_model_log.md](phase6_proof_planning_cost_model_log.md) — Phase 6B-2
- [phase6_proof_planning_reference_log.md](phase6_proof_planning_reference_log.md) — Phase 6B-1
- [contribution_map_and_top_tier_gap.md](contribution_map_and_top_tier_gap.md)
