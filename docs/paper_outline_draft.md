# Paper Outline Draft — AuthView-VDB

**Phase:** 4A planning document (no code changes).  
**Audience:** systems / security / applied cryptography venue (e.g. USENIX Security, CCS, NDSS, or EuroSys with security track).

Slot-aligned commitment is an **implementation optimization** (authorization commitment layout). It is **not** framed as a primary contribution.

---

## 1. Tentative title options

1. **AuthView-VDB: Verifiable Vector Retrieval over Committed Authorization Views**
2. **Zero-Knowledge Authorized Search over Committed IVF-PQ Snapshots**
3. **Proof-Carrying Access Control for Approximate Nearest-Neighbor Retrieval**
4. **Beyond Post-Filter: Authorization-Aware Zero-Knowledge Vector Search**

Recommended lead: **(1)** — emphasizes the *view* semantics distinction from per-item or post-filter checks.

---

## 2. Problem statement

Enterprises store embeddings in shared vector databases with tenant/project/clearance policies. A remote index operator may:

- Serve results from a stale or partial index (snapshot binding failure).
- Skip candidates to manipulate ranking (coverage failure).
- Mark unauthorized objects visible or hide authorized ones (view inconsistency).
- Return post-filtered global top-k instead of **authorized masked top-k** over the full candidate set (retrieval soundness failure).

V3DB proves ANN top-k over a **content** snapshot. It does **not** prove that ranking respects an **authorization view** \(V(U,\sigma)\) or that access labels are bound to a committed auth state.

**AuthView-VDB question:** Can a verifier check that published top-k cids equal top-k over authorized masked distances on the complete IVF-PQ candidate set, with labels bound to `root_auth` at checkpoint σ?

---

## 3. Key idea

Treat authorization as part of the **retrieval program**, not a post-processing filter:

$$
R = \mathrm{TopK}_k\bigl(\{(x, \hat d_x) \mid x \in \mathrm{Cand}(q,S,\theta)\}\bigr),
\quad \hat d_x = v_x \cdot d_x + (1-v_x)\cdot d_{\max},
\quad v_x = P(\gamma_U, \lambda_x, \sigma).
$$

The prover demonstrates:

1. Content snapshot binding (V3DB inheritance).
2. Full candidate coverage over \(N_{sel} = n_{probe} \times n\) slots.
3. Policy-evaluated visibility and masked distances in-circuit.
4. Merkle opening of each slot's auth label to public `root_auth` (committed path).

---

## 4. System architecture

```
Publisher                         Verifier
─────────                         ────────
Corpus S + labels λ_x    ──►      Public: q, R, root_content, root_auth,
Commit root_content               γ_U, θ, checkpoint σ
Commit root_auth
                                  Verify ZK proof π
Query service            ──►      Accept iff π valid and R matches
(prover)                          authorized masked top-k semantics
```

**Implementation stack:**

- **Indexing:** IVF-PQ fixed-shape slots (V3DB-compatible).
- **Proof system:** Plonky2 set-based IVF-PQ circuit (`set_based_auth_*`).
- **Reference oracle:** Python plaintext authorized top-k (`auth_reference/`).
- **Evaluation:** CSV benchmark harness (`scripts/bench_auth_paths.py`).

---

## 5. Protocol / proof semantics

**Public inputs:** query \(q\), top-k cids \(R\), content Merkle roots, `root_auth`, user context \(\gamma_U\), checkpoint epoch, search parameters \(\theta\).

**Witness (committed path):** slot PQ codes, ADC distances, auth label fields, Merkle paths to `root_auth`, sorted (cid, \(\hat d\)) multiset.

**Circuit checks (per slot):**

1. Open content record under content root (V3DB).
2. Compute \(d_x\) from committed PQ codes and codebooks.
3. Open auth label under `root_auth`.
4. Compute \(v_x = P(\gamma_U, \lambda_x, \sigma)\).
5. Compute \(\hat d_x\) via auth mask gadget.
6. Set equality + sorted top-k + public cid outputs.

**Optional layout (appendix):** slot-aligned two-level auth tree reduces Merkle verify cost; same authorization semantics.

---

## 6. Security properties

Map to [security_properties.md](security_properties.md):

| Property | Mechanism in prototype |
|----------|------------------------|
| Snapshot binding | V3DB Merkle commitment |
| Checkpoint binding | Public `root_auth` + epoch in policy |
| Candidate coverage | Fixed-shape set-based witness |
| View consistency | Committed labels + policy gadget |
| Authorization soundness | Visible slots require \(v_x=1\) for ranking |
| Authorized distance soundness | Mask gadget |
| Retrieval soundness under auth | Top-k over \(\hat d\), not post-filter |

**Explicit non-goals:** private credentials, global freshness, deletion proofs, full index-wide auth tree in benchmark baseline.

---

## 7. Implementation

**Rust (`src/merkle_ver/`):**

- `auth_mask_gadget`, `auth_policy_gadget`, `auth_commitment_gadget`
- `set_based_auth_ivf_pq_gadget_{all_visible,policy,committed,committed_slot_aligned}`
- PyO3 wrappers in `src/lib.rs`

**Python (`auth_reference/`):**

- Plaintext oracle and attack suite
- V3DB adapter and witness builders
- Global and slot-aligned auth Merkle builders

**Lines of effort (phases):** Phase 0–3D; ~56 pytest integration tests + Rust gadget tests.

---

## 8. Evaluation research questions

| RQ | Question |
|----|----------|
| **RQ1** | Do proofs preserve authorized top-k semantics and reject attacks (forgery, wrong paths, graft)? |
| **RQ2** | What is the overhead of authorization-aware paths vs V3DB baseline? |
| **RQ3** | How does cost scale with \(N_{sel}\), \(n_{probe}\), slot capacity? |
| **RQ4** | Does slot-aligned commitment layout reduce cost vs global flat auth tree (engineering)? |

See [evaluation_plan_paper_tables.md](evaluation_plan_paper_tables.md) for table/figure mapping.

---

## 9. Related work categories

1. **Verifiable vector search / VDB auditing** — V3DB, vSQL, other proof-of-retrieval systems.
2. **Authenticated data structures** — Merkle trees, vector commitments over structured indexes.
3. **ZK access control** — policy in circuits, credential systems (compare public-\(\gamma_U\) limitation).
4. **Private information retrieval / private ANN** — orthogonal (privacy of query/database vs integrity of authorized results).
5. **Enterprise vector DB + ABAC/RBAC** — motivate problem; no ZK guarantee in commercial systems.

---

## 10. Contribution framing (recommended)

**Primary contributions:**

1. **Problem formulation:** committed **authorization-view** retrieval — top-k over masked distances on the full candidate set, not post-filter (formal statement + attack cases).
2. **Authorization-aware ZK semantics:** integration of policy visibility and masked distance into V3DB set-based IVF-PQ proofs.
3. **Committed auth label binding:** Merkle commitment of per-object labels to `root_auth` with in-circuit policy on the same targets.
4. **Prototype and evaluation:** five-path implementation, 56+ tests, paper-ready CSV showing committed-auth overhead and scaling on synthetic workloads.

**Secondary / appendix contribution:**

5. **Commitment layout optimization:** slot-aligned two-level auth Merkle tree with list_id binding — modest gate savings (2–5% vs probe-local global tree in our evaluation); conservative vs production index-wide tree.

**Do not claim:**

- Production-ready deployment
- Privacy of user attributes
- Slot-aligned layout as main novelty
- Evaluation on large real-world datasets (yet)

---

## 11. Suggested paper structure

1. Introduction & motivation (post-filter vs authorized view)
2. Background (IVF-PQ, V3DB, threat model)
3. Authorized retrieval semantics (formal_statement summary)
4. AuthView protocol & circuit design
5. Security analysis (properties + assumptions)
6. Implementation
7. Evaluation (RQ1–RQ4)
8. Related work
9. Limitations & future work (real data, index-wide auth tree, private credentials)
10. Conclusion

---

## 12. Open writing tasks

- [ ] Update formal_statement.md status banners (spec says "not implemented" — now partially implemented).
- [ ] Diagram: candidate coverage + mask pipeline.
- [ ] Clarify benchmark global-tree scope in evaluation section.
- [ ] Cite V3DB and position AuthView as authorization extension.
- [ ] Appendix: slot-aligned layout, witness layouts, gadget test matrix.
