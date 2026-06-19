# Paper Figure and Table Inventory

**Phase:** 6C  
**Purpose:** Checklist for main-text and appendix figures/tables with data availability and priority  
**Companion:** [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md)

Legend for **measurement type:**

| Tag | Meaning |
|-----|---------|
| **ZK** | Real measured prove/verify/gates from PyO3 proof paths |
| **REF** | Plaintext authorized reference oracle |
| **COST** | Plaintext proof-planning work-unit cost model (not ZK gates) |
| **DESIGN** | Architecture / workflow diagram (no measurement) |
| **MISSING** | Not yet produced |

Priority: **P0** = paper blocker · **P1** = strongly recommended · **P2** = optional / appendix

---

## 1. Main-text figures

| ID | Target file / name | Section | Claim supported | Data source | Artifact today | Type | Priority |
|----|-------------------|---------|-----------------|-------------|----------------|------|----------|
| **Fig 1** | System architecture / workflow | §4 System | End-to-end: committed index → auth state → proof paths → verifier | Design doc + code map | ❌ MISSING | DESIGN | **P0** |
| **Fig 2** | Authorized IVF-PQ semantics / proof relation | §3–4 | Authorized masked top-k ≠ post-filter; binds to `root_auth` | `formal_statement.md` | ❌ MISSING | DESIGN | **P0** |
| **Fig 3** | Proof overhead / path comparison | §5.3 RQ2 | Auth paths increase gates vs content-only baseline | `artifacts/auth_zk_paper_ready_summary.csv` | CSV ✅, figure ❌ | **ZK** | **P0** |
| **Fig 4** | ACL-class compression vs N_acl/N_sel | §5.4 RQ3 | ACL-class wins when N_acl ≪ N_sel | `artifacts/auth_zk_acl_class_summary.csv` | CSV ✅ (repeat=1), figure ❌ | **ZK** | **P0** |
| **Fig 5a** | `main_merged_k_knob.pdf` | §5.5 RQ4 | Merged-k trades PA vs SA (design knob) | `proof_planning_layout_metrics_repaired.csv` | ✅ PDF | **COST** | **P0** |
| **Fig 5b** | `main_cost_breakdown_clean.pdf` | §5.5 RQ4 | Savings mainly from Distance/ADC component | same | ✅ PDF | **COST** | **P0** |
| **Fig 5c** | `main_impure_fallback_clean.pdf` | §5.5 RQ4 | Impure fallback drives PA | same | ✅ PDF | **COST** | **P1** |
| **Fig 6** | Public dataset retrieval utility | §5.2 RQ1 | Authorized reference matches unrestricted recall within ε | SIFT1M/GIST1M/MARCO (planned) | ❌ MISSING | **REF** | **P0** |
| **Fig 7** | Scalability / configuration trade-off | §5.7 RQ6 | Gates scale with N_sel, n_probe | `auth_zk_paper_ready_summary.csv` + extended bench | CSV partial | **ZK** | **P1** |
| **Fig 8** | Attack workflow (optional) | §5.6 RQ5 | Threat model + attack injection points | `attack_matrix_eval.md` | ❌ MISSING | DESIGN | **P2** |

### Fig 5 LaTeX composition (RQ4)

Use three **separate PDFs** as subfigures (Phase 6B-2.14):

```latex
% Fig 5 in paper — compose in LaTeX, not multipanel export
\includegraphics{figures/main_merged_k_knob.pdf}
\includegraphics{figures/main_cost_breakdown_clean.pdf}
\includegraphics{figures/main_impure_fallback_clean.pdf}
```

Caption must state: *plaintext cost model; not measured ZK gate reduction.*

### Optional figures (appendix only)

| File | Section | Notes | Priority |
|------|---------|-------|----------|
| `main_sa_pa_frontier_clean.pdf` | Appendix | Design-space overview; Oracle off-scale | **P2** |
| Slot-aligned vs global opening diagram | Appendix | ~2–5% gate reduction | **P2** |
| Post-filter vs authorized toy example | §2 Motivation | Micro-fixture A1 | **P1** |
| V3DB reproduction snapshot | Appendix | Baseline credibility | **P2** |

---

## 2. Main-text tables

| ID | Name | Section | Claim supported | Data source | Artifact today | Type | Priority |
|----|------|---------|-----------------|-------------|----------------|------|----------|
| **Table 1** | Dataset and workload setup | §5.1 | Reproducibility; public + synthetic | Planned + current params | Partial (synthetic only) | — | **P0** |
| **Table 2** | Proof overhead by path | §5.3 RQ2 | Median gates/time/size vs baseline | `auth_zk_paper_ready_summary.csv` | CSV ✅ | **ZK** | **P0** |
| **Table 3** | Attack matrix | §5.6 RQ5 | ZK rejects forgeries; limits for A9–A11 | `artifacts/auth_attack_matrix.csv` | CSV ✅ | **ZK**+REF | **P0** |
| **Table 4** | Ablation summary | §5.4 RQ3 | policy / committed / slot / ACL-class | paper-ready + acl-class CSV | Partial | **ZK** | **P0** |
| **Table 5** | Public dataset utility summary | §5.2 RQ1 | Recall@k, MRR, NDCG across datasets | Planned D1 | ❌ MISSING | **REF** | **P0** |
| **Table 6** | Artifact reproducibility | §Artifact / appendix | Build, bench commands, seeds | README + scripts | Partial | — | **P1** |

### Table 2 suggested columns

| Path | N_sel | median_gates | median_prove_time | median_verify_time | median_proof_size | vs baseline gates |
|------|-------|--------------|-------------------|--------------------|--------------------|-------------------|
| baseline (V3DB-shaped) | 256 | … | … | … | … | 1.00 |
| auth_committed | 256 | … | … | … | … | ~1.26 |
| auth_acl_class (N_acl=1) | 256 | … | … | … | … | ~0.94× committed |

Source: filter `auth_zk_paper_ready_summary.csv` + join ACL row.

### Table 3 suggested rows

Map directly from [attack_matrix_eval.md](attack_matrix_eval.md): A1–A12 with columns {Attack, Layer, Path, Expected, Tested, Outcome}.

---

## 3. Appendix inventory

| Item | Content | Priority |
|------|---------|----------|
| Extended scaling grid | All 6 workloads × all paths | P1 |
| ACL-class full grid repeat=3 | N_acl sweep with error bars | P0 |
| Slot-aligned opening cost model | Plaintext opening counts | P2 |
| Proof-planning sanity CSV excerpt | 10/10 checks | P2 |
| Test coverage matrix | pytest module → property | P2 |
| Limitations table | public γ_U, freshness, fixed-shape Cand | P0 (main text or appendix) |

---

## 4. Deprecated / do-not-use figures

Do **not** submit these to the paper (see [phase6_proof_planning_paper_figures_log.md](phase6_proof_planning_paper_figures_log.md)):

| Pattern | Reason |
|---------|--------|
| `repaired_selectivity_sensitivity.pdf` | Invalid cross-role line connections |
| `proof_planning_layout_*.pdf` (6B-2.9) | Broken role-combination workload |
| `proof_planning_locality_*`, beta heatmaps | Superseded by layout SA/PA story |
| `final_*`, old `main_*_zoom`, multipanel exports | Superseded by 6B-2.14 clean subfigures |
| Any figure without cost-model / ZK label | Reviewer confusion risk |

---

## 5. Priority summary

### P0 — must have before submission

1. Fig 1 System architecture  
2. Fig 3 Proof overhead (from existing CSV)  
3. Fig 4 ACL-class N_acl/N_sel (re-run repeat=3)  
4. Fig 5a–b (merged-k + cost breakdown) — **done**  
5. Fig 6 Public dataset utility — **missing**  
6. Table 1–5 core set  
7. Explicit cost-model disclaimer on Fig 5  

### P1 — strongly recommended

- Fig 5c impure fallback (done)  
- Fig 7 scaling curves  
- Table 6 artifact reproducibility  
- Post-filter quantitative figure (RQ1/RQ5 bridge)  

### P2 — optional polish

- Fig 8 attack workflow  
- `main_sa_pa_frontier_clean.pdf`  
- V3DB reproduction appendix figure  

---

## 6. Figure production checklist

| Step | Owner action |
|------|--------------|
| 1 | Draft Fig 1–2 in TikZ or draw.io (no code change) |
| 2 | Script grouped bar from `auth_zk_paper_ready_summary.csv` → Fig 3 |
| 3 | Re-run `bench_acl_class_paths.py --repeat 3` → Fig 4 |
| 4 | Include existing `main_*.pdf` in LaTeX → Fig 5 |
| 5 | Execute D1 public dataset plan → Fig 6 + Table 5 |
| 6 | Export attack matrix LaTeX from `auth_attack_matrix.csv` → Table 3 |
| 7 | Label every figure caption with ZK / REF / COST |

---

## 7. Status dashboard (2026-06)

| Category | Ready | Missing |
|----------|-------|---------|
| ZK overhead data | ✅ paper-ready CSV | Figure export |
| ACL-class data | ⚠️ repeat=1 | repeat=3 + figure |
| Proof planning figures | ✅ 3 subfigures | LaTeX only |
| Security table | ✅ CSV + tests | Paper formatting |
| Public datasets | ❌ | Full D1 pipeline |
| Architecture figures | ❌ | Design work |
