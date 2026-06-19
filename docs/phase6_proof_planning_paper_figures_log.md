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

## Phase 6B-2.11: Repaired Layout Figures

**Status:** paper-ready candidate figures from repaired access-signature model (sanity 10/10).

### Do not use Phase 6B-2.9 layout figures

The following were generated from the **broken role-combination workload** and must **not** appear in the paper:

- `proof_planning_sa_pa_tradeoff.pdf`
- `proof_planning_layout_cost_breakdown.pdf`
- `proof_planning_layout_impure_ratio.pdf`
- `proof_planning_layout_selectivity_sensitivity.pdf`

See [phase6_layout_model_failure_analysis.md](phase6_layout_model_failure_analysis.md).

### Repaired figure set

All filenames use the `repaired_` prefix. Data source:

- `artifacts/proof_planning_layout_summary_repaired.csv`
- `artifacts/proof_planning_layout_metrics_repaired.csv`

Figures slice **effective selectivity ≈ 0.5** via query role closest to 0.5 in metrics (role 4, median eff_sel ≈ 0.54), aggregated over seeds.

```bash
PYTHONPATH=. python scripts/plot_proof_planning_layout_figures.py \
  --summary artifacts/proof_planning_layout_summary_repaired.csv \
  --metrics artifacts/proof_planning_layout_metrics_repaired.csv \
  --output-dir artifacts/figures
```

| Figure | File | Story |
|--------|------|-------|
| SA/PA frontier | `repaired_sa_pa_frontier.pdf` | Global = low SA, high PA; oracle = high SA, low PA; merged-k traces continuous trade-off |
| Merged-k sensitivity | `repaired_merged_k_sensitivity.pdf` | k↑ → SA↓, PA↑ (dual axis, merged-k only) |
| Cost breakdown | `repaired_layout_cost_breakdown.pdf` | PA drop vs global driven mainly by distance/ADC component |
| Impure vs PA | `repaired_impure_vs_pa.pdf` | Higher impure_valid_ratio → higher PA_plan |
| Selectivity (optional) | `repaired_selectivity_sensitivity.pdf` | PA vs effective selectivity by layout; acl/oracle PA close but SA differs — use SA/PA frontier as main figure |

### Core narrative (repaired model)

1. **Global:** lowest $SA_{\mathrm{commit}}$, highest $PA_{\mathrm{plan}}$ — single impure region, max proof fallback.
2. **Oracle authorized-view:** highest $SA_{\mathrm{commit}}$, lowest $PA_{\mathrm{plan}}$ (= 1.0 by construction) — role-view replication cost.
3. **Merged-k:** monotone trade-off curve between global and fine-grained layouts as k decreases.
4. **ACL-signature:** $PA_{\mathrm{plan}}$ near oracle, but **lower** $SA_{\mathrm{commit}}$ — per-signature regions without full role-view replication.
5. **Impure ratio:** $N_{\mathrm{impure}}/N_{\mathrm{valid}}$ explains residual $PA_{\mathrm{plan}}$ above oracle (especially merged-k at large k).

All axes labeled **cost model** — not measured ZK gates.

### Artifact cleanup plan (do not delete yet)

After repaired figures pass review, archive or remove legacy exploratory PDFs:

| Pattern / file | Origin |
|----------------|--------|
| `proof_planning_locality_*.pdf` | Phase 6B-2.7 |
| `proof_planning_heatmap_cost.pdf` | Phase 6B-2.8 |
| `proof_planning_cost_breakdown.pdf` | Phase 6B-2.8 |
| `proof_planning_degradation_curve.pdf` | Phase 6B-2.8 |
| `proof_planning_granularity_sensitivity.pdf` | Phase 6B-2.8 |
| `proof_planning_sa_pa_tradeoff.pdf` | Phase 6B-2.9 (broken) |
| `proof_planning_layout_cost_breakdown.pdf` | Phase 6B-2.9 (broken) |
| `proof_planning_layout_impure_ratio.pdf` | Phase 6B-2.9 (broken) |
| `proof_planning_layout_selectivity_sensitivity.pdf` | Phase 6B-2.9 (broken) |

**Action:** move to `artifacts/figures/archive/` or delete in a dedicated cleanup PR after paper figure sign-off.

---

## Phase 6B-2.12: Final Figure Selection

**Status:** final paper candidates from repaired access-signature model.

### Final figure set (use in paper)

Data slice: query role closest to effective selectivity 0.5 (role 4, median eff_sel ≈ 0.54), aggregated over seeds.

```bash
PYTHONPATH=. python scripts/plot_proof_planning_layout_figures.py \
  --summary artifacts/proof_planning_layout_summary_repaired.csv \
  --metrics artifacts/proof_planning_layout_metrics_repaired.csv \
  --output-dir artifacts/figures
```

| Role | File | Paper placement |
|------|------|-----------------|
| **Main Fig A** | `final_sa_pa_frontier.pdf` | Storage–proof trade-off; merged-k curve + Global / ACL / Oracle bound |
| **Main Fig B** | `final_merged_k_sensitivity.pdf` | Merged-k as continuous design knob (dual panel: PA↑, SA↓ as k↑) |
| **Main Fig C** | `final_normalized_cost_breakdown.pdf` | Normalized planned cost (Global = 1.0); savings from distance/ADC |
| **Supplementary** | `final_impure_vs_pa.pdf` | Mechanism: impure fallback drives PA |

### Key narrative points

1. **Global:** lowest $SA_{\mathrm{commit}}$, highest $PA_{\mathrm{plan}}$.
2. **Oracle bound:** highest $SA_{\mathrm{commit}}$, lowest $PA_{\mathrm{plan}}$ (= 1.0 by construction).
3. **Merged-k:** the **continuous design-space knob** — tune k to trace the SA/PA frontier between Global and fine-grained layouts.
4. **ACL-signature vs Oracle:** $PA_{\mathrm{plan}}$ are **close by design** (both pure regions); the meaningful difference is **$SA_{\mathrm{commit}}$** (role-view replication vs per-signature regions). Do not over-interpret PA gap.
5. **Impure ratio:** explains residual $PA_{\mathrm{plan}}$ above oracle for large-k merged layouts.

All figures labeled **cost model** — not measured ZK gates.

### Deprecated figures (do not use in paper)

| File | Reason |
|------|--------|
| `repaired_selectivity_sensitivity.pdf` | Connected points across different query roles / configs — **no valid continuous-curve semantics** |
| `repaired_sa_pa_frontier.pdf` | Superseded by `final_sa_pa_frontier.pdf` (crowded labels, legend overlap) |
| `repaired_merged_k_sensitivity.pdf` | Superseded by dual-panel `final_merged_k_sensitivity.pdf` (dual y-axis unclear) |
| `repaired_layout_cost_breakdown.pdf` | Superseded by normalized `final_normalized_cost_breakdown.pdf` |
| `repaired_impure_vs_pa.pdf` | Superseded by `final_impure_vs_pa.pdf` (cleaner endpoint markers) |
| Phase 6B-2.9 `proof_planning_layout_*.pdf` | Broken role-combination workload |
| Phase 6B-2.7/2.8 locality/beta figures | Exploratory; superseded by layout SA/PA story |

### Artifact cleanup recommendation

After final figures are accepted in paper draft:

1. Move deprecated PDFs to `artifacts/figures/archive/`.
2. Keep only `final_*.pdf` in the active figures directory.
3. Do not regenerate `repaired_*` or selectivity sensitivity plots.

---

## Phase 6B-2.13: Strict Final Figure Selection

**Status:** strict presentation spec for main paper figures (model unchanged).

### Main figures (paper — three only)

```bash
PYTHONPATH=. python scripts/plot_proof_planning_layout_figures.py \
  --summary artifacts/proof_planning_layout_summary_repaired.csv \
  --metrics artifacts/proof_planning_layout_metrics_repaired.csv \
  --output-dir artifacts/figures
```

| # | File | Role |
|---|------|------|
| 1 | `main_sa_pa_frontier_zoom.pdf` | Zoomed SA/PA frontier (x ∈ [0.95, 1.55]); Oracle off-scale as dashed PA=1 line + caption |
| 2 | `main_merged_k_sensitivity_dual_axis.pdf` | Merged-k design knob; dual y-axis (PA red, SA blue) |
| 3 | `main_normalized_cost_breakdown.pdf` | 5 bars, 3 muted components; Global = 1.0 baseline; no Oracle bar |

Data slice: query role closest to effective selectivity 0.5 (role 4).

### Appendix (optional, not main)

| File | Role |
|------|------|
| `appendix_impure_vs_pa.pdf` | Sanity explanation only — impure fallback drives PA; **not a main figure** |

### Presentation fixes vs Phase 6B-2.12

| Issue (6B-2.12) | Fix (6B-2.13) |
|-----------------|---------------|
| Oracle point compresses frontier | Oracle removed from axes; PA=1 dashed line + off-scale caption |
| Cost breakdown too busy | 5 bars (no Oracle), 3 stacked components, muted palette |
| Impure vs PA as main candidate | Moved to appendix only |
| Dual-panel merged-k | Restored dual y-axis per spec |

### Deprecated figures (do not use)

**Phase 6B-2.12 superseded:**

- `final_sa_pa_frontier.pdf`
- `final_merged_k_sensitivity.pdf`
- `final_normalized_cost_breakdown.pdf`
- `final_impure_vs_pa.pdf`

**Earlier exploratory / broken:**

- `repaired_selectivity_sensitivity.pdf` — invalid cross-config lines
- All `repaired_*.pdf`, Phase 6B-2.9 `proof_planning_layout_*.pdf`
- Phase 6B-2.7/2.8 locality/beta figures (`proof_planning_locality_*`, heatmap, degradation, etc.)

### Artifact cleanup recommendation

Move all deprecated PDFs to `artifacts/figures/archive/`; keep only `main_*.pdf` (+ optional `appendix_*.pdf`) active.

---

## Phase 6B-2.14: Separate Subfigure Redesign

**Status:** Veda-style standalone PDFs for LaTeX `subfigure` / `subcaption` composition.

### Why separate PDFs (no multipanel)

Multipanel figures compress font sizes, obscure legends, and make revision costly. System papers (e.g. Veda) typically export **one plot per PDF** and compose in LaTeX at `0.30–0.33\textwidth` per subfigure. This phase follows that pattern.

### Data slice

- Source: `artifacts/proof_planning_layout_metrics_repaired.csv` (metrics slice preferred over summary aggregate).
- Query role closest to effective selectivity 0.5 → **role 4** (median eff_sel ≈ 0.54), aggregated over seeds.

```bash
PYTHONPATH=. python scripts/plot_proof_planning_layout_figures.py \
  --summary artifacts/proof_planning_layout_summary_repaired.csv \
  --metrics artifacts/proof_planning_layout_metrics_repaired.csv \
  --output-dir artifacts/figures
```

### Recommended paper subfigures (three)

| File | Role |
|------|------|
| `main_merged_k_knob.pdf` | **Primary** — merged-k as continuous design knob (dual y-axis: PA↑, SA↓) |
| `main_cost_breakdown_clean.pdf` | Savings from Distance/ADC component (Global = 1.0) |
| `main_impure_fallback_clean.pdf` | Mechanism — impure fallback drives PA |

### Optional / appendix

| File | Role |
|------|------|
| `main_sa_pa_frontier_clean.pdf` | Design-space overview; use only if visual clarity acceptable — **not required in main text** |

### Narrative

- **Merged-k** is the continuous design-space knob between Global and fine-grained layouts.
- **Global / ACL / Oracle** are endpoint references; Oracle vs ACL differs mainly in **SA**, not PA — Oracle should not dominate every cost figure.
- **Impure fallback** explains PA rise when regions are impure (mechanism subfigure).

### Palette (Veda-style)

| Element | Color |
|---------|-------|
| Auth/region proof | `#F1D097` |
| Distance/ADC | `#45A8BB` |
| Mask + top-k / PA line | `#CB5623` |
| SA line | `#45A8BB` |
| Reference markers | `#666666` |

Figure size: ~3.35 × 2.55 in; axis labels 9–10 pt; grid α ≤ 0.18.

### LaTeX usage

```latex
\begin{figure}[t]
  \centering
  \begin{subfigure}[t]{0.32\textwidth}
    \includegraphics[width=\linewidth]{figures/main_merged_k_knob.pdf}
    \caption{Merged-k knob (cost model).}
  \end{subfigure}\hfill
  \begin{subfigure}[t]{0.32\textwidth}
    \includegraphics[width=\linewidth]{figures/main_cost_breakdown_clean.pdf}
    \caption{Normalized cost breakdown.}
  \end{subfigure}\hfill
  \begin{subfigure}[t]{0.32\textwidth}
    \includegraphics[width=\linewidth]{figures/main_impure_fallback_clean.pdf}
    \caption{Impure fallback vs.\ PA.}
  \end{subfigure}
  \caption{Access-aware layout proof-planning cost model (plaintext work units, not ZK gates).}
\end{figure}
```

Do **not** force `main_sa_pa_frontier_clean.pdf` into main text if it feels crowded; explain Oracle off-scale in caption instead.

### Deprecated figures

All prior layout figure iterations and exploratory sweeps:

- `main_sa_pa_frontier_zoom.pdf`, `main_merged_k_sensitivity_dual_axis.pdf`, `main_normalized_cost_breakdown.pdf`, `appendix_impure_vs_pa.pdf` (6B-2.13)
- `final_*.pdf`, `repaired_*.pdf` (6B-2.11/2.12)
- `proof_planning_layout_*.pdf` (6B-2.9 broken)
- `proof_planning_locality_*.pdf`, `proof_planning_beta_*.pdf`, heatmap/degradation/granularity (6B-2.7/2.8)
- `repaired_selectivity_sensitivity.pdf`, any selectivity sensitivity figure

**Do not generate:** `main_layout_tradeoff_multipanel.pdf`, selectivity sensitivity, locality/beta figures.

### Artifact cleanup recommendation

After LaTeX integration: archive all deprecated PDFs; keep only `main_merged_k_knob.pdf`, `main_cost_breakdown_clean.pdf`, `main_impure_fallback_clean.pdf`, and optionally `main_sa_pa_frontier_clean.pdf`.

---

## Artifact Cleanup Result

**Phase:** 6 artifact cleanup (executed 2026-06-16)

### Active paper-candidate figures

Located in `artifacts/figures/`:

| File | Recommendation |
|------|----------------|
| `main_merged_k_knob.pdf` | **Main text** — merged-k design knob (dual y-axis PA/SA) |
| `main_cost_breakdown_clean.pdf` | **Main text** — normalized cost breakdown (Global = 1.0) |
| `main_impure_fallback_clean.pdf` | **Optional / appendix** — impure fallback mechanism |
| `main_sa_pa_frontier_clean.pdf` | **Backup / appendix** — SA/PA frontier overview |

### Archived exploratory figures

| Item | Value |
|------|-------|
| Archive path | `artifacts/figures/archive/phase6_exploratory/` |
| Archived file count | 33 PDFs |

Includes all Phase 6B exploratory iterations: locality/beta sweeps, repaired/final/main_zoom variants, 6B-2.9 broken layout figures, selectivity sensitivity, and prior appendix exports. **No PDFs were deleted** — only moved.

### Paper recommendation

- **Main text:** compose `main_merged_k_knob.pdf` + `main_cost_breakdown_clean.pdf` as LaTeX subfigures (see Phase 6B-2.14).
- **Appendix (optional):** `main_impure_fallback_clean.pdf` for mechanism explanation.
- **Appendix (backup):** `main_sa_pa_frontier_clean.pdf` only if design-space overview adds clarity.
- **Archived figures:** not paper candidates; retained for reproducibility and audit trail only.

---

## Related

- [phase6_proof_planning_cost_model_log.md](phase6_proof_planning_cost_model_log.md) — Phase 6B-2
- [phase6_proof_planning_reference_log.md](phase6_proof_planning_reference_log.md) — Phase 6B-1
- [contribution_map_and_top_tier_gap.md](contribution_map_and_top_tier_gap.md)
