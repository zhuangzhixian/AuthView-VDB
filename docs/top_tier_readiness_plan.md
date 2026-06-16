# Top-Tier Readiness Plan (VLDB / SIGMOD / ICDE)

**Phase:** 4B  
**Audience:** Internal go/no-go before targeting database systems venues.

**Bottom line:** The current artifact is a **credible proof kernel** with initial overhead numbers. It is **not yet sufficient** for a strong VLDB/SIGMOD/ICDE submission without attack evaluation, ACL-class compression, visibility-gated scoring, and the two ratio figures (N_vis/N_sel, N_acl/N_sel).

---

## 1. Venue bar (what reviewers expect)

| Dimension | VLDB / SIGMOD / ICDE implicit standard |
|-----------|----------------------------------------|
| **Problem novelty** | New workload or guarantee not addressed by prior systems; clear gap vs closest work |
| **Algorithm / mechanism** | Non-trivial technique with articulated trade-offs—not only integration |
| **System** | End-to-end prototype demonstrating feasibility at meaningful scale |
| **Evaluation** | Multiple RQs, realistic or well-motivated synthetic workloads, ablations, sensitivity curves |
| **Security / correctness** | Attack or failure-mode evaluation for security-sensitive claims |

AuthView-VDB sits at **systems + security** boundary. Database venues will ask: *“Is this a new query semantics with proof, or an crypto add-on?”* Positioning reset ([research_positioning_reset.md](research_positioning_reset.md)) must be clear in the paper.

---

## 2. Problem novelty standard

### Required

- Formal distinction: **authorized view top-k** vs **post-filter** vs **per-item authorization** ([formal_statement.md](formal_statement.md) §11, [security_properties.md](security_properties.md) §1).
- Clear statement that **V3DB proves content retrieval only**—no \(V(U,\sigma)\).
- Motivating enterprise scenario: shared embedding index, multi-tenant ACL, audit requirement.

### Current state

| Criterion | Met? | Gap |
|-----------|------|-----|
| Formal spec frozen | ✅ | Update “not implemented” banners in formal/security docs |
| Problem distinct from V3DB | ✅ (docs) | Paper prose not written |
| Motivation with numbers | ⚠️ | Only synthetic micro post-filter example |
| Related work survey | ❌ | Outline only |

**Verdict:** Novelty **adequate for workshop / arXiv**; **needs attack-driven motivation + related work depth** for top-tier.

---

## 3. Algorithm contribution standard

### Required (at least one strong + one supporting)

1. **Authorization-view retrieval semantics** in ZK (policy + mask + coverage)—*supporting, largely done*.
2. **ACL-class compression** with candidate↔class binding proof—*missing, high value*.
3. **Visibility-gated scoring** with partition correctness—*missing, high value*.
4. Slot-aligned Merkle layout—*done, too weak alone*.

### Current state

| Contribution type | Status |
|-------------------|--------|
| New retrieval objective + ZK realization | Partial (kernel) |
| Cost optimization with proof obligation | Not started (ACL, gating) |
| Asymptotic / structural argument (\(N_{acl}\), \(N_{vis}\)) | Not demonstrated |

**Verdict:** **Fails** top-tier algorithm bar today. Phase 5–6 are **required**, not optional polish.

---

## 4. System implementation standard

### Required

- Prover/verifier pipeline reproducible from artifact
- Multiple proof configurations (baseline, full auth, optimized auth)
- Documented witness layouts and public inputs
- Reasonable performance at \(N_{sel}\) ≥ 256–512 with trends

### Current state

| Criterion | Met? |
|-----------|------|
| Rust + Python + PyO3 pipeline | ✅ |
| 5 proof paths | ✅ |
| 56+ pytest + gadget tests | ✅ |
| Paper-ready CSV (90 rows, repeat=3) | ✅ |
| Real dataset / larger scale | ❌ |
| ACL / gated paths | ❌ |

**Verdict:** **Prototype quality good** for a kernel; **not** full system story.

---

## 5. Experimental evaluation standard

### Required for top-tier

| RQ | Requirement | Current |
|----|-------------|---------|
| **RQ1 Security** | Attack matrix, ZK-level failures | Partial (unit tests only) |
| **RQ2 Overhead** | vs content-only baseline | ✅ summary CSV |
| **RQ3 Scaling** | vs \(N_{sel}\), n_probe, slot | ✅ 6 workloads |
| **RQ4 Structure-aware cost** | N_vis/N_sel, N_acl/N_sel curves | ❌ |
| **RQ5 Semantic gap** | Post-filter vs authorized (quantified) | ❌ (toy only) |

Also expected:

- Ablation: policy only vs committed vs committed+optimizations
- Discussion of limitations (public \(\gamma_U\), synthetic data)
- Reproducibility package

**Verdict:** **Insufficient**—missing the two headline figures and attack table.

---

## 6. Current gap summary

```
Dimension              Current          Top-tier need
─────────────────────────────────────────────────────
Problem framing        Reset (4B)       Paper §1–2 written
Proof kernel           Strong           —
ACL-class compression  None             Core algorithm + N_acl/N_sel
Visibility-gated       None             Core opt + N_vis/N_sel
Attack experiments     Partial          Full matrix + table
Paper draft            Outline          8–10 page eval + security
Real / larger data     None             At least one public benchmark overlay
```

---

## 7. Priority roadmap (recommended)

| Priority | Work item | Est. impact on readiness |
|----------|-----------|--------------------------|
| **P0** | Positioning + paper §1–2 (no V3DB extension framing) | Required for any submission |
| **P0** | Attack matrix completion (plaintext + ZK + table) | Security RQ |
| **P1** | ACL-class compression (Phase 5) + N_acl/N_sel | Algorithm + eval |
| **P1** | Visibility-gated scoring (Phase 6) + N_vis/N_sel | Algorithm + eval |
| **P2** | Paper tables from existing CSV (overhead/scaling) | Supports RQ2–3 |
| **P2** | Update formal/security doc status | Consistency |
| **P3** | SIFT / larger synthetic overlay | Strengthen eval |
| **P4** | Slot-aligned appendix | Optional |

**Do not prioritize** slot-aligned layout, pure/impure blocks, or private credentials before P0–P1.

---

## 8. Go / no-go checklist

Before targeting VLDB/SIGMOD/ICDE main conference:

- [ ] Paper title/abstract contain no “V3DB extension”
- [ ] Attack table with ≥8 scenarios and ZK outcomes
- [ ] ACL-class path implemented + N_acl/N_sel figure
- [ ] Visibility-gated path implemented + N_vis/N_sel figure
- [ ] Post-filter vs authorized quantitative comparison (≥1 non-toy workload)
- [ ] Related work: V3DB, verifiable DB, filtered ANN, ZK access control
- [ ] Full draft with limitations section
- [ ] Artifact instructions (build, bench, reproduce tables)

**Current count: ~3/8** (kernel, overhead CSV, positioning docs).

---

## 9. Alternative venue ladder (if timeline slips)

| Venue type | Fit with current kernel |
|------------|-------------------------|
| Security workshop / short paper | Possible after attack matrix |
| arXiv + reproducibility badge | Now (with clear “kernel” labeling) |
| VLDB/SIGMOD/ICDE **industrial** or demo track | Possible with stronger demo story |
| Main conference | Needs Phase 5–6 + attacks |

---

## 10. Key message for authors

> **The proof kernel is the foundation, not the destination.**  
> Top-tier reviewers will accept V3DB as related work and ask what **new** algorithm and **which curves** justify a database venue. ACL-class compression and visibility-gated scoring answer that question; slot-aligned Merkle saves ~3% and belongs in appendix.

See [next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md) for Phase 5–6 design.
