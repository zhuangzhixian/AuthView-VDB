# Phase 9C: Evaluation Consolidation and Paper-Ready Audit

**Phase:** 9C  
**Purpose:** Consolidate Phase 6–9B evaluation artifacts; audit paper readiness without new experiments  
**Branch:** `phase9c-evaluation-consolidation`  
**Companion:** [paper_evaluation_blueprint.md](paper_evaluation_blueprint.md), [paper_ready_claims_and_evidence.md](paper_ready_claims_and_evidence.md), [figure_table_decision_matrix.md](figure_table_decision_matrix.md)

---

## 1. Phase 9C purpose

Phase 9C does **not** run new long experiments. It:

1. Maps each evaluation module to research claims and paper placement.
2. Audits **reference_scope** boundaries (`unrestricted` / `candidate_level` / `full_base_calibration`).
3. Confirms **full-base** public benchmark status (Phase 8C/9A/9B).
4. Positions AuthView against **V3DB** (verifiable content-only search) and **Veda/EffVeda** (access-aware indexing).
5. Identifies remaining gaps and minimal next experiments.

Auto-generated inventories: `artifacts/evaluation_inventory/figure_table_inventory.csv`, `result_summary_inventory.csv` (via `scripts/build_evaluation_inventory.py`).

---

## 2. Evaluation chain overview

```text
Phase 6  ── Proof-planning cost model (merged-k, SA/PA, purity)
           Plaintext planning; NOT measured ZK gates

Phase 7  ── Measured ZK proof overhead (RQ2), ACL-class (RQ3), scaling (RQ6)
           Controlled parameterized proof workloads; repeat=3 paper-ready CSV (overhead)

Phase 8C ── Public utility baseline (RQ1 unrestricted)
           SIFT1M/GIST1M full 1M base; IVF-PQ high-acc + zk-opt

Phase 9A ── Authorization overlay on public traces (RQ1 semantics)
           Post-filter vs candidate-level; reference_scope=candidate_level

Phase 9B ── Full authorized-reference calibration (RQ1 boundary)
           Exact L2 on full 1M visible subset; query-calibrated subset
           reference_scope=full_base_calibration
```

| Phase | Module | Base scale | Query scale | Reference scope |
|-------|--------|------------|-------------|-----------------|
| 8C | Unrestricted IVF-PQ utility | **1M full** | SIFT 10k / GIST 1k | Unrestricted baseline |
| 9A | Auth overlay on traces | Trace from **1M index** | Full public query sets | **candidate_level** |
| 9B | Full auth calibration | **1M full** scan | ~572 calibrated queries | **full_base_calibration** |
| 7 | ZK overhead | Parameterized Cand shapes | Controlled proof grid | N/A (proof cost) |
| 6 | Proof planning | Parameterized n_valid | Cost model grid | N/A (planning) |

---

## 3. Phase roles (6 / 7 / 8C / 9A / 9B)

### Phase 6 — Proof planning (RQ4)

- **Role:** Design-space analysis for access-structure-aware **proof planning** (merged-k, purity regions, grouping).
- **Evidence:** `main_merged_k_knob.pdf`, `main_cost_breakdown_clean.pdf`, `main_impure_fallback_clean.pdf`.
- **Paper:** Main text with **mandatory cost-model disclaimer** — not measured ZK reduction.

### Phase 7 — ZK measurement (RQ2, RQ3, RQ6)

- **Role:** Real prove/verify/gates/size on auth proof paths vs V3DB-shaped **content-only baseline**.
- **Evidence:** `auth_zk_paper_ready_summary.csv`, proof overhead/scaling figures, ACL-class figures.
- **Paper:** Main text for overhead + ACL-class; scaling in appendix.

### Phase 8C — Public utility baseline (RQ1 foundation)

- **Role:** V3DB-aligned **unrestricted** IVF-PQ utility on standard ANN benchmarks.
- **Evidence:** `sift_gist_utility_summary.csv`, `main_public_utility_recall.pdf`.
- **Paper:** Table + figure for reproducible public baseline before authorization.

### Phase 9A — Authorization overlay (RQ1 semantics)

- **Role:** Quantify post-filter failure (underfill, utility gap) vs candidate-level authorized reference on **full query sets**.
- **Evidence:** `public_trace_auth_summary.csv` (144 rows), overlay figures.
- **Paper:** Main text for authorization semantics story.

### Phase 9B — Full-base calibration (RQ1 boundary)

- **Role:** Bound Phase 9A candidate-level approximation against **exact authorized top-k** over visible 1M vectors.
- **Evidence:** `full_authorized_reference_summary.csv`, calibration figure/table.
- **Paper:** Appendix + caption footnote; supports honest scope claims.

---

## 4. Public datasets and full-base status

| Dataset | num_base | num_queries | dim | full_base | Phase |
|---------|----------|-------------|-----|-----------|-------|
| SIFT1M | 1,000,000 | 10,000 | 128 | **true** | 8C, 9A trace, 9B calibration |
| GIST1M | 1,000,000 | 1,000 | 960 | **true** | 8C, 9A trace, 9B calibration |

- Phase 8C `full_base=true` in summary CSV for all four configs.
- Phase 9A traces were produced by querying the **full** indexed corpus; overlay applies to 1M object IDs.
- Phase 9B reads full `*_base.fvecs` (1M vectors); calibration uses a **stratified calibration query set** drawn from public benchmark queries — **not** a truncated base.

**MS MARCO:** Not in scope for Phases 8C–9B; listed in blueprint as future D1 extension.

---

## 5. high-acc / zk-opt configuration explanation

Both configs use **full 1M base**, `M=8`, `K=256`, `top_k=100`, `scale_n=65536` (ZK rescale bound, not data truncation).

| Config | Purpose | SIFT1M n_list/n_probe | GIST1M n_list/n_probe |
|--------|---------|------------------------|------------------------|
| **high-acc** | V3DB-comparable accuracy-oriented IVF-PQ | 8192 / 64 | 8192 / 64 |
| **zk-opt** | Proof-aware tradeoff (smaller probe, larger cluster_bound) | 1024 / 8 | 512 / 4 |

**Important:** `zk-opt` is a **proof-aware operating point** aligned with ZK-friendly IVF-PQ parameters (V3DB-style). Paper text should describe it as **proof-aware configuration**, not as an intentionally degraded baseline.

Phase 8C results (unrestricted R@10):

| Dataset | high-acc | zk-opt |
|---------|----------|--------|
| SIFT1M | 0.749 | 0.668 |
| GIST1M | 0.241 | 0.211 |

---

## 6. reference_scope boundaries

| Scope | Where | Meaning | Paper language |
|-------|-------|---------|----------------|
| **Unrestricted baseline** | Phase 8C | Standard IVF-PQ top-k on full index | “Unrestricted public utility baseline” |
| **candidate_level** | Phase 9A | Authorized ranking within trace prefix `pred[:100]` | “Trace-level candidate approximation; not full-database authorized ANN” |
| **full_base_calibration** | Phase 9B | Exact top-k over all visible vectors in **full 1M base** | “Query-calibrated full-base authorized reference” |

**Do not conflate:**

- Phase 9A **full public trace trends** (10k / 1k queries) with Phase 9B **query calibration** (~572 queries).
- “Calibration” in 9B = **stratified public queries for exact reference**, **not** base truncation.

Phase 9B observed pattern (aggregated): `candidate_full_recall_gap ≤ 0` often — candidate-level can **underestimate** full authorized recall when the true neighbor ranks beyond the trace prefix but remains visible in the full corpus.

---

## 7. Do current results support paper claims?

| Claim area | Supported? | Evidence strength |
|------------|------------|-------------------|
| Post-filter ≠ authorized semantics | **Yes** | Phase 9A: utility gap, 100% underfill at low selectivity @k=10 |
| Public benchmark utility baseline | **Yes** | Phase 8C full-base CSV + figure |
| Candidate-level trends | **Yes** | Phase 9A 144-row summary, all `candidate_level` |
| Approximation boundary | **Yes** | Phase 9B 144 aggregated rows, `full_base_calibration` |
| ZK overhead vs baseline | **Yes** | Phase 7 paper-ready CSV + figures |
| ACL-class optimization | **Partial** | Figures/tables exist; verify repeat=3 for final caption |
| Proof planning design | **Yes** | Phase 6 figures with cost-model label |
| End-to-end ZK on public traces | **No** | Not run; by design out of scope 8C–9B |
| MS MARCO / production IAM | **No** | Future work |

Overall: **RQ1 semantics + public baseline + calibration boundary** are paper-ready with explicit scope disclaimers. **RQ2–4** supported on **controlled parameterized proof workloads** (overhead trends); end-to-end public-trace ZK remains a follow-up.

---

## 8. Configuration strength audit

1. **SIFT1M/GIST1M use full 1M base** — confirmed in Phase 8C summary and 9B `num_base=1000000`.
2. **SIFT1M: 10,000 queries; GIST1M: 1,000 queries** — standard TEXMEX query sets.
3. **high-acc uses n_list=8192, n_probe=64** — V3DB-comparable accuracy configuration.
4. **zk-opt is proof-aware tradeoff**, not a deliberately weakened baseline.
5. **Phase 9B uses a stratified calibration query set** from public benchmark queries; base remains full 1M L2 scan over visible IDs.
6. **Phase 9A = full public trace trends**; **Phase 9B = full-base query calibration** — complementary, not redundant.
7. Public benchmark results should be described at **full-corpus scale** on the **corpus** dimension (1M base).
8. When using “calibration,” always specify **query calibration** (Phase 9B), not base subsampling.

**Residual scope limits (publication-grade corpus; controlled overlays and proof grids):**

- Authorization policies in 9A/9B are **generated ACL overlays** / **controlled authorization overlays** (uniform / clustered / skewed ACL), not production IAM logs.
- Phase 7 proof workloads use **parameterized candidate shapes** on **controlled proof workloads** — appropriate for overhead-trend measurement, separate from public utility benchmark claims and not a substitute for them.
- GIST1M has **1k queries** (benchmark standard, not a project choice to shrink).

---

## 9. Positioning against V3DB and Veda-style access-aware indexing

1. **V3DB** establishes verifiable vector search over **committed snapshots** with content-focused proofs (IVF-PQ pipeline, gate/time/size metrics). AuthView **reuses** this geometry and uses V3DB-shaped paths as the **content-only lower bound** (`baseline`).

2. **Veda / EffVeda** pursue **access-aware indexing** under a **trusted** server — optimizing SA/QA, purity, and recall/QPS at execution time without proof obligations.

3. **AuthView** targets **proof-carrying authorized retrieval** over committed access views `V(U,σ)`: the prover must show results match **authorized masked top-k** over declared candidate set `Cand`, not merely that returned vectors exist in the snapshot.

4. We prove **authorized-view retrieval semantics**, not only per-vector visibility or label validity.

5. **Phase 8C** aligns public ANN **utility baseline** with V3DB evaluation conventions (full SIFT1M/GIST1M, high-acc + zk-opt).

6. **Phase 9A/9B** add the dimension V3DB unrestricted verification **does not cover**: post-filter vs authorized-view utility under visibility constraints — complementary, not a claim of dominating V3DB on all axes.

7. **Honest framing:** AuthView advances **verifiable authorization semantics**; Veda advances **trusted access-aware execution**; V3DB advances **verifiable content-only search**. Cross-domain superiority claims should be avoided.

---

## 10. Current limitations

- No MS MARCO evaluation yet.
- No ZK proofs on public benchmark traces (8C–9B are plaintext/reference).
- Phase 9A authorized reference is **candidate_level** only without 9B context.
- Phase 9B is **query-calibrated**, not exhaustive per-query full scan of all 11k queries.
- ACL-class figure may need repeat=3 confirmation in caption.
- Architecture / attack workflow figures still missing (blueprint P0 design items).

---

## 11. Minimal next-step experiments (priority order)

| Priority | Experiment | Effort | Impact |
|----------|------------|--------|--------|
| P0 | Finalize ACL-class repeat=3 caption audit | Low | Table 4 / Fig 4 credibility |
| P0 | System architecture figure (Fig 1) | Design | Paper blocker |
| P1 | Public trace **ZK proof pilot** (stratified calibration query set from 9B) | Medium | Bridge RQ1 → RQ2 |
| P1 | MS MARCO utility baseline (Phase 8D) | High | Blueprint D1 completeness |
| P2 | Expand 9B to full 572-query metrics in appendix table | Medium | Stronger calibration |
| P2 | Production-like IAM policy (beyond generated ACL overlays) | High | External validity |

---

## 12. Commands

```bash
# Build inventory
PYTHONPATH=. .venv/bin/python scripts/build_evaluation_inventory.py \
  --figures-dir artifacts/figures \
  --tables-dir artifacts/tables \
  --public-utility artifacts/public_utility/sift_gist_utility_summary.csv \
  --auth-overlay artifacts/auth_overlay/public_trace_auth_summary.csv \
  --auth-calibration artifacts/auth_calibration/full_authorized_reference_summary.csv \
  --output-dir artifacts/evaluation_inventory

# Tests
PYTHONPATH=. .venv/bin/python -m pytest tests/test_evaluation_inventory.py -v
```

---

## 13. Related documents

- [paper_ready_claims_and_evidence.md](paper_ready_claims_and_evidence.md)
- [figure_table_decision_matrix.md](figure_table_decision_matrix.md)
- [phase8_public_utility_baseline_log.md](phase8_public_utility_baseline_log.md)
- [phase9_authorization_overlay_log.md](phase9_authorization_overlay_log.md)
- [phase9b_authorized_reference_calibration_log.md](phase9b_authorized_reference_calibration_log.md)
