# Phase 6B-2: Proof-Planning Cost-Model Sweep

**Phase:** 6B-2  
**Branch:** `phase6-proof-planning-cost-model`  
**Status:** plaintext cost-model sweep + CSV artifacts

---

## Evaluation Goal

Generate **proof-planning cost-model sweep** data for paper figures:

- **N_vis / N_valid** (visible ratio) vs structural cost
- **Pure / impure region ratio** vs planned cost
- **PA_plan / PA_ideal** (cost-model Proof Amplification)

This phase does **not** measure real ZK gates or claim gate reduction.

---

## Workload Structure

Deterministic synthetic IVF-PQ candidate grids:

| Parameter | Default |
|-----------|---------|
| n_valid | 256 |
| n_lists | 4 |
| slot_per_list | 64 |
| N_slots | 256 |
| top_k | 5 |

Visibility labels:

- **Visible:** tenant `acme`, project `proj-a`, level 2
- **Invisible:** tenant `other` (policy rejects for DEFAULT_USER)

Distances: `1000 + flat_index` (deterministic).

---

## Grouping Strategies

| Strategy | Region partition |
|----------|------------------|
| `acl_class` | Valid slots by `acl_class_id` (= list id); invalid by list |
| `ivf_list` | One region per probed `list_id` |
| `fixed_block` | Probe-major order, chunk by `block_size` |

---

## Purity Modes (visibility assignment)

| Mode | Assignment pattern |
|------|-------------------|
| `clustered` | Whole units (list / block / class) uniformly visible or invisible |
| `mixed` | Global spread across valid slots |
| `adversarial_mixed` | Alternate visible/invisible within each unit → maximize impure regions |

Purity mode controls **label layout**, independent of grouping strategy in the cross-product sweep.

---

## Scripts

```bash
PYTHONPATH=. python scripts/bench_proof_planning_model.py \
  --n-valid 256 --n-lists 4 --slot-per-list 64 \
  --visible-ratios 0.0,0.1,0.25,0.5,0.75,1.0 \
  --grouping-strategies acl_class,ivf_list,fixed_block \
  --purity-modes clustered,mixed,adversarial_mixed \
  --block-sizes 16 --top-k 5 \
  --output artifacts/proof_planning_model_metrics.csv

PYTHONPATH=. python scripts/summarize_proof_planning_model.py \
  --input artifacts/proof_planning_model_metrics.csv \
  --output artifacts/proof_planning_model_summary.csv
```

Default full sweep: **54 rows** (6 visible ratios × 3 strategies × 3 purity modes).

---

## Raw CSV Schema (`artifacts/proof_planning_model_metrics.csv`)

Key columns:

| Column | Meaning |
|--------|---------|
| `case_id` | Deterministic case identifier |
| `grouping_strategy` / `purity_mode` / `block_size` | Sweep dimensions |
| `N_valid`, `N_vis`, `N_invis`, `visible_ratio` | Visibility metrics |
| `pure_region_ratio`, `impure_region_ratio` | Structural purity |
| `N_dist_masked`, `N_dist_plan`, `N_dist_ideal` | Distance work counters |
| `dist_reduction_plan`, `dist_reduction_ideal` | Fractional reduction vs masked |
| `estimated_cost_*` | Relative cost-model units |
| `plan_vs_masked_cost`, `ideal_vs_masked_cost` | Cost ratios |
| `PA_plan`, `PA_ideal` | Proof Amplification (cost-model) |
| `planned_equals_masked`, `validation_passed` | Correctness flags |

---

## PA Definition (Cost-Model PA)

**Not** real proof-size PA or measured ZK gates.

```
oracle_authorized_cost = max(1, N_vis) × (C_dist + C_topk_per_candidate)
PA_plan  = estimated_cost_plan  / oracle_authorized_cost
PA_ideal = estimated_cost_ideal / oracle_authorized_cost
```

`oracle_authorized_cost` is an **ideal authorized-view proof baseline** — distance + top-k only on visible slots, with no masking overhead on invisible slots.

Default weights match Phase 6B-1 (`C_dist=10`, `C_topk=1`, etc.).

---

## Key Trends (Expected)

1. **All cases:** `planned_equals_masked=true`, `validation_passed=true`.
2. **visible_ratio=0.0, clustered:** `N_dist_plan=0`, high `dist_reduction_plan`.
3. **visible_ratio=1.0:** `N_dist_plan ≈ N_valid`; plan does not claim distance savings.
4. **clustered vs adversarial_mixed:** higher `pure_region_ratio` for clustered at mid ratios.
5. **ideal_vs_masked_cost:** increases with visible ratio (more visible distance work).
6. **plan_vs_masked_cost:** decreases when pure-invisible area is large (clustered, low visible ratio).
7. **All-impure degenerate:** `plan_vs_masked_cost ≥ 1` (region overhead, no forced win).

---

## Limitations

1. **Plaintext cost model only** — relative units, not ZK gate counts.
2. **Static circuit mux does not reduce gates** — per-candidate conditional in fixed-shape circuits still pays full ADC/policy cost.
3. Real ZK savings require **region purity proof gadget**, **visible-subset compaction**, or **redesigned circuit shape** (Phase 6B-3).
4. PA is **cost-model PA**, not measured proof-size amplification.
5. Synthetic ACL layout (one class per list) — not enterprise corpus trace.

---

## How to Draw Paper Figures

### Figure A: N_vis/N_valid vs cost

- X: `visible_ratio` or `N_vis/N_valid`
- Y: `plan_vs_masked_cost` or `median_PA_plan`
- Series: `grouping_strategy` × `purity_mode`

### Figure B: Pure/impure ratio vs PA

- X: `pure_region_ratio` or `pure_invisible_ratio`
- Y: `PA_plan` or `dist_reduction_plan`
- Color: `purity_mode`

Load from `artifacts/proof_planning_model_summary.csv` for medians per group.

---

## Phase 6B-3 Decision Criteria

Proceed to **region purity ZK gadget** only if:

1. Plaintext sweep shows **consistent** `dist_reduction_plan > 0` for clustered workloads at low visible ratio.
2. `plan_vs_masked_cost` break-even vs masked baseline after accounting for `C_region_pure` overhead.
3. `PA_plan` materially below `PA_ideal` gap suggests room for ZK structure change (not mux-only).

If all-impure / adversarial workloads dominate (`impure_region_ratio → 1`), prioritize **better planners** or **ACL-class + planning composition** before ZK gadget work.

---

## Related

- [phase6_proof_planning_reference_log.md](phase6_proof_planning_reference_log.md) — Phase 6B-1 reference
- [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md) — design
- [contribution_map_and_top_tier_gap.md](contribution_map_and_top_tier_gap.md) — paper gap tracking
