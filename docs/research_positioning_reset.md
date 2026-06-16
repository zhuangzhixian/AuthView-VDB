# Research Positioning Reset

**Phase:** 4B — positioning reset (documentation only)  
**Branch:** `phase4-positioning-reset`

This document resets how AuthView-VDB should be **framed for publication**. It supersedes any implicit narrative that treats this work as a “V3DB extension,” “V3DB follow-up,” or “V3DB + auth patch.”

---

## 1. What this paper is **not**

| ❌ Do not claim | Why |
|----------------|-----|
| V3DB extension or continuation | Different problem object, security goal, and verifier belief |
| V3DB reproduction paper | Reproduction is infrastructure, not the contribution |
| Incremental Merkle optimization on V3DB | Slot-aligned layout is engineering; not the thesis |
| “We add ACL to V3DB” | Authorization **view retrieval** is the problem; V3DB has no such semantics |

**V3DB** (Qiu et al., verifiable vector search over committed snapshots) proves:

$$
R = \mathrm{TopK}_k\bigl(\{(x, d_x) \mid x \in \mathrm{Cand}(q,S,\theta)\}\bigr)
$$

over a **single committed content snapshot** \(S\). It does **not** model user-specific visible subsets, committed authorization state, policy-evaluated visibility, or authorized masked top-k. AuthView-VDB addresses a **different verification question**.

---

## 2. What this paper **is**

**Problem (one sentence):**  
*Proof-carrying authorized vector retrieval over committed authorization/access views on a shared physical index.*

**Verifier target:**

$$
R = \mathcal{A}_{auth}(q, S, V(U,\sigma); \theta)
= \mathrm{TopK}_k\bigl(\{(x, \hat d_x) \mid x \in \mathrm{Cand}(q,S,\theta)\}\bigr)
$$

where \(\hat d_x\) incorporates visibility from committed labels at checkpoint \(\sigma\), and the prover covers the **full** declared candidate set—not a server-chosen subset and not post-filtered global top-k.

This is a **new problem formulation** at the intersection of:

- verifiable / auditable vector search,
- enterprise access control on embeddings,
- zero-knowledge proof of correct execution of an **authorization-aware retrieval program**.

The current repository is a **proof kernel** toward that problem—not a finished systems paper.

---

## 3. Core system objects (paper vocabulary)

Use these consistently; avoid “V3DB index + auth plugin” wording.

```
┌─────────────────────────────────────────────────────────────────┐
│  Shared physical vector index (IVF-PQ snapshot S)               │
│  - committed content: centroids, slots, PQ codes, cids          │
│  - fixed-shape Cand(q,S,θ) for auditability                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼
  User-specific        Committed            Proof-carrying
  authorized view      authorization        retrieval result
  V(U,σ)               state @ σ            (R, π)
  from P(γ_U,λ_x,σ)    root_auth, CP_σ
```

| Object | Role in paper |
|--------|----------------|
| **Shared physical index** | One corpus layout; many tenants/projects share IVF-PQ structure |
| **User-specific authorized view** | Semantic search universe \(V(U,\sigma)\); not post-filter |
| **Committed authorization state** | Labels \(\lambda_x\) Merkle-bound to `root_auth` at checkpoint σ |
| **Proof-carrying retrieval result** | Public top-k cids + ZK proof π that ranking used authorized masked distances on full \(Cand\) |

**Checkpoint tuple** (public):

$$
CP_\sigma = (\sigma,\ root_{content},\ root_{auth},\ policyID,\ \theta)
$$

---

## 4. V3DB — correct paper placement

V3DB appears **only** in these roles:

### 4.1 Related work (representative baseline class)

- **Category:** verifiable vector database / proof-carrying ANN over committed snapshots.
- **Citation purpose:** closest prior work on IVF-PQ + Merkle + set-based ZK top-k.
- **Explicit gap:** no authorization view, no visibility mask, no `root_auth`, no retrieval soundness under \(V(U,\sigma)\).

### 4.2 Baseline without authorization-view semantics

In experiments, `baseline` / `py_set_based_with_merkle` measures **content-only** verifiable retrieval cost. It answers: *“What does V3DB-style proof cost look like on our fixed-shape reference?”* It does **not** implement or prove authorized retrieval.

Label in tables: **“content-only verifiable baseline (V3DB-style)”** — not “our system without auth.”

### 4.3 Fixed-shape IVF-PQ reference point

V3DB’s fixed-shape IVF-PQ program defines:

- \(N_{sel} = n_{probe} \times n\),
- candidate coverage requirement,
- ADC/PQ distance pipeline,
- set-based top-k witness.

AuthView-VDB **inherits the reference geometry** (for ZK tractability) but replaces the **retrieval objective** and adds **authorization commitments**. Say “fixed-shape IVF-PQ reference semantics (following verifiable ANN literature)” rather than “V3DB pipeline.”

---

## 5. Relationship diagram (for paper §2)

```
                    Verifiable vector search
                              │
              ┌───────────────┴───────────────┐
              │                               │
     Content snapshot only              Authorization view
     (V3DB, vSQL, …)                   (this work)
              │                               │
     R = TopK(d_x) on Cand              R = TopK(̂d_x) on Cand
     no V(U,σ)                          V(U,σ) + root_auth
```

**Filtered ANN** (trusted server, no proof) is a **different row** in related work—not our baseline class.

---

## 6. Recommended title directions

Avoid “V3DB,” “extension,” or “building on V3DB” in the title.

| Priority | Title direction |
|----------|-----------------|
| ★★★ | **Proof-Carrying Authorized Vector Retrieval over Committed Access Views** |
| ★★★ | **Verifiable Vector Search over Committed Authorization Views** |
| ★★ | **Zero-Knowledge Retrieval under Committed Access Control on Shared Embedding Indexes** |
| ★★ | **Beyond Post-Filter: Verifiable Top-k over Authorization-Masked Candidate Sets** |
| ★ | **AuthView: Auditable ANN Retrieval with Committed Authorization State** |

Subtitle (optional): *Fixed-shape IVF-PQ realization and proof kernel* — mentions mechanism without subordinating the problem to V3DB.

---

## 7. Contribution framing (reset)

**Primary (problem + semantics + prototype):**

1. Formalize **committed authorization-view retrieval** vs post-filter and per-item checks ([formal_statement.md](formal_statement.md), [security_properties.md](security_properties.md)).
2. Design **authorization-aware ZK retrieval semantics**: policy visibility + masked distance + full candidate coverage.
3. Implement **committed auth label binding** (`root_auth`) integrated with policy in-circuit.
4. Provide **proof kernel**, attack-informed plaintext reference, and initial overhead evaluation.

**Secondary (engineering / appendix):**

5. Slot-aligned auth commitment layout (2–5% gate reduction vs probe-local flat tree in current eval)—**layout optimization only**.

**Not yet contribution-ready (Phase 5–6):**

6. ACL-class compression (\(N_{acl} \ll N_{sel}\)).
7. Visibility-gated scoring (skip policy on provably invisible candidates).

---

## 8. What to remove from slides / abstract drafts

- “We extend V3DB with access control”
- “V3DB + Merkle auth”
- “First system to add authorization to verifiable vector search” (too strong until attack eval + ACL/visibility figures exist)
- Leading with slot-aligned savings

**Replace with:**

- “We study proof-carrying retrieval over committed authorization views on a shared IVF-PQ index.”
- “Verifier belief: authorized masked top-k over the complete declared candidate set.”
- “V3DB-style proofs serve as a content-only baseline without authorization-view semantics.”

---

## 9. Document cross-references

| Doc | Role after reset |
|-----|------------------|
| [remaining_work_gap_analysis.md](remaining_work_gap_analysis.md) | What blocks a top-tier submission |
| [top_tier_readiness_plan.md](top_tier_readiness_plan.md) | VLDB/SIGMOD/ICDE bar vs current state |
| [next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md) | Phase 5–6 technical plan |
| [paper_outline_draft.md](paper_outline_draft.md) | Update intro/related work to match this doc |

---

## 10. One-paragraph elevator pitch (internal)

> Enterprise vector platforms search a shared embedding index under tenant and clearance policies, but clients cannot today obtain a cryptographic proof that top-k results equal search over their **authorized view** rather than a post-filtered or manipulated candidate set. We formulate **proof-carrying authorized vector retrieval**: the prover demonstrates authorized masked top-k over the full IVF-PQ candidate set, with access labels bound to a committed authorization root at a checkpoint. V3DB-style content proofs appear only as a **related baseline without authorization semantics**. Our current artifact is a proof kernel; ACL-class compression and visibility-gated scoring are the next steps toward a top-tier systems evaluation.
