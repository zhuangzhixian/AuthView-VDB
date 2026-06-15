# Formal Statement: Authorized Vector Retrieval over Committed Views

Phase 1A frozen semantics for AuthView-VDB. This document defines the
reference retrieval program and proof target for future implementation and
paper writing.

**Status:** specification only. The V3DB baseline is implemented; authorization-view
semantics described here are **planned extensions** and are **not implemented**.

Related: [research_scope.md](research_scope.md), [security_properties.md](security_properties.md).

---

## 1. Problem setting

A potentially untrusted retrieval service holds a shared vector corpus indexed
with fixed-shape IVF-PQ. Clients issue approximate nearest-neighbour (ANN)
queries under an access-control policy. The service returns a top-k result set
$$R$$ and, when challenged, a succinct proof.

V3DB proves that $$R$$ equals ANN retrieval over a **committed content snapshot**
$$S$$ using declared public parameters $$\theta$$. AuthView-VDB extends this
setting: the service must prove that $$R$$ equals ANN retrieval over the user's
**committed authorization view** $$V(U,\sigma)$$, not merely that every item in
$$R$$ is individually authorized.

The authorization view is part of the retrieval program semantics, not an
external post-filter applied after ranking.

---

## 2. Notation

| Symbol | Meaning |
|--------|---------|
| $$S$$ | Committed content snapshot (IVF-PQ index, PQ codes, codebooks, slots) |
| $$q$$ | Query embedding vector |
| $$\theta$$ | Public search parameters (e.g. $$n_{list}$$, $$n_{probe}$$, $$M$$, $$K$$, $$k$$) |
| $$U$$ | Querying user (identity) |
| $$\gamma_U$$ | User authorization context for this query |
| $$x$$ | A corpus object / chunk in $$S$$ |
| $$\lambda_x$$ | Access label of object $$x$$ at checkpoint $$\sigma$$ |
| $$\sigma$$ | Authorization state checkpoint identifier |
| $$P(\cdot)$$ | Authorization predicate (visibility decision) |
| $$V(U,\sigma)$$ | User $$U$$'s visible subset of $$S$$ at checkpoint $$\sigma$$ |
| $$Cand(q,S,\theta)$$ | Candidate set fixed by V3DB-style reference semantics |
| $$d_x$$ | Approximate distance from $$q$$ to $$x$$ under declared ADC/PQ scoring |
| $$v_x$$ | Visibility bit for candidate $$x$$ |
| $$\hat d_x$$ | Authorized masked distance for candidate $$x$$ |
| $$d_{max}$$ | Large sentinel distance for invisible or invalid candidates |
| $$R$$ | Returned top-k result set |
| $$\mathcal{A}_{auth}$$ | Authorized ANN reference program |
| $$CP_\sigma$$ | Checkpoint tuple binding content, auth state, and policy |
| $$root_{content}$$ | Merkle root over content snapshot |
| $$root_{auth}$$ | Merkle root over authorization state |
| $$policyID$$ | Policy version identifier |

---

## 3. Content snapshot $$S$$

$$S$$ is a versioned, fixed-shape IVF-PQ snapshot committed by the service
publisher. It includes at minimum:

- Centroid table for $$n_{list}$$ inverted lists
- Per-list slot records with fixed capacity $$n$$ (after rebalancing and padding)
- PQ codes, global codebooks, and valid bits for padding slots
- Chunk identifiers (`cid`) linking slots to logical objects
- Optionally, static authorization metadata embedded in slot records (tenant,
  project, clearance level, ACL class id)

V3DB commits $$S$$ via a snapshot commitment, typically:

$$
com_{content} = (root_{mk}, root_{cb})
$$

where $$root_{mk}$$ binds the fixed-shape IVF layout and slot records, and
$$root_{cb}$$ binds PQ codebooks. AuthView-VDB may extend this with static auth
fields in slot records; dynamic auth state is committed separately (see
$$root_{auth}$$ below).

**Baseline status:** V3DB content snapshot commitment is **implemented** in the
imported codebase (`ivf_pq/merkle_zk.py`, `src/merkle_ver/`).

---

## 4. Query vector $$q$$ and public search parameters $$\theta$$

$$q \in \mathbb{Z}^D$$ (or a committed integer-quantized embedding) is a public
input to the proof. $$\theta$$ collects all parameters needed to fix the
reference ANN program, including but not limited to:

- $$n_{probe}$$: number of probed inverted lists
- $$n$$: fixed slot capacity per probed list
- $$M, K$$: PQ subspace count and codebook size
- $$k$$: result size (top-k)
- Optional layout / quantization settings shared with V3DB baseline

Both $$q$$ and $$\theta$$ are public inputs in the first prototype.

---

## 5. User $$U$$ and authorization context $$\gamma_U$$

$$U$$ identifies the querying principal. The authorization context

$$
\gamma_U = (tenant_U, Projects_U, clearance_U, role_U, epoch_U, \ldots)
$$

captures the credentials relevant to policy evaluation for this query.

**First-prototype assumption:** $$\gamma_U$$ is a **public authenticated input**
(e.g. signed by an enterprise IAM or policy issuer). Privacy-preserving
credentials are a later extension.

---

## 6. Access label $$\lambda_x$$ and checkpoint $$\sigma$$

Each object $$x \in S$$ has an access label at checkpoint $$\sigma$$:

$$
\lambda_x = (tenant_x, project_x, level_x, roleSet_x, state_x, epoch_x, \ldots)
$$

Dynamic fields (revocation, expiry, policy epoch) may live in a separate
authorization-state commitment keyed by `cid` or ACL class.

$$\sigma$$ identifies the authorization-state checkpoint against which labels
are interpreted. Content snapshots and authorization state may update at
different rates; proofs must bind both to the same checkpoint (Section 12).

---

## 7. Authorization predicate

Visibility is decided by a deterministic predicate:

$$
P(\gamma_U, \lambda_x, \sigma) \in \{0, 1\}
$$

Examples for the first plaintext reference (Phase 1B):

- tenant match: $$tenant_x = tenant_U$$
- project membership: $$project_x \in Projects_U$$
- clearance comparison: $$level_x \leq clearance_U$$
- state valid: object not revoked/expired at $$\sigma$$

$$P$$ is fixed by $$policyID$$ included in $$CP_\sigma$$.

---

## 8. Committed authorization view

The visible view of user $$U$$ at checkpoint $$\sigma$$ is:

$$
V(U,\sigma)=\{x\in S\mid P(\gamma_U,\lambda_x,\sigma)=1\}
$$

**Key point:** $$V(U,\sigma)$$ defines the semantic search universe. The proof
target is retrieval correctness **over this view**, not per-result authorization
alone.

---

## 9. V3DB-style candidate set $$Cand(q,S,\theta)$$

AuthView-VDB inherits V3DB's fixed-shape IVF-PQ reference semantics. Given
$$(q, S, \theta)$$, the candidate set is **uniquely determined** by the
declared program, not chosen by the server.

Informally, the five V3DB steps are:

1. **Centroid distances:** compute distances from $$q$$ to all list centroids
2. **Probe selection:** select the $$n_{probe}$$ nearest lists
3. **ADC lookup:** build per-list PQ lookup tables from codebooks
4. **Candidate scoring:** compute approximate distance $$d_x$$ for each slot in
   probed lists via PQ codes
5. **Top-k selection:** (extended in AuthView-VDB — see Section 11)

For fixed-shape indexing with probed lists $$P(q)$$ and slot capacity $$n$$:

$$
Cand(q,S,\theta) = \{(i,j) \mid i \in P(q),\ j \in [n]\}
$$

$$
N_{sel} = |Cand(q,S,\theta)| = n_{probe} \cdot n
$$

Padding slots remain in $$Cand$$ but are demoted via valid bits (V3DB) and,
in AuthView-VDB, additionally via visibility bits.

**Baseline status:** V3DB candidate enumeration, valid-bit masking, and
fixed-shape slot structure are **implemented**. Authorization extensions are
**not**.

---

## 10. Candidate coverage requirement

The prover must demonstrate that **every** slot in $$Cand(q,S,\theta)$$ was
processed through visibility evaluation and masked scoring—not an arbitrary
server-selected subset $$Cand_{service}$$.

Coverage decomposes into:

1. **List-selection coverage:** $$P(q)$$ equals the $$n_{probe}$$ nearest lists
   under committed centroids and $$q$$
2. **Within-list slot coverage:** for each $$i \in P(q)$$, all $$n$$ slots are
   opened and scored; padding slots use valid bit $$f_{i,j}=0$$ but are not skipped

Formally, the proof must rule out:

$$
R = TopK_k(\{(x,\hat d_x) \mid x \in Cand_{service}\})
$$

where $$Cand_{service} \subsetneq Cand(q,S,\theta)$$.

---

## 11. Visibility, masked distance, and authorized top-k

### 11.1 Visibility bit

For each candidate $$x \in Cand(q,S,\theta)$$:

$$
v_x = P(\gamma_U, \lambda_x, \sigma)
$$

Combining with V3DB valid bit $$f_x \in \{0,1\}$$ (padding), effective
visibility for ranking is $$f_x \cdot v_x$$ in the first prototype.

### 11.2 Authorized masked distance

Let $$d_x = d(q,x)$$ be the declared ADC/PQ approximate distance. Define:

$$
\hat d_x = v_x \cdot d_x + (1-v_x) \cdot d_{max}
$$

When combined with valid-bit demotion (padding), the full first-prototype scoring
key uses:

$$
\tilde d_x = f_x \cdot \hat d_x + (1-f_x) \cdot d_{max}
$$

For exposition, we write the core authorization mask as $$\hat d_x$$; implementers
should compose with $$f_x$$ exactly as V3DB composes valid-bit masking in
`set_based.rs`.

Optional tie-break sort key:

$$
key_x = (1-v_x,\ \tilde d_x,\ id_x)
$$

### 11.3 Authorized top-k semantics

The reference result is:

$$
R = TopK_k(\{(x,\hat d_x)\mid x\in Cand(q,S,\theta)\})
$$

Equivalently, the authorized retrieval program satisfies:

$$
R = \mathcal{A}_{auth}(q,S,V(U,\sigma);\theta)
$$

**Contrast with post-filter:** a weak semantics is $$R = Filter(TopK_k(\{(x,d_x)\}),
V(U,\sigma))$$. AuthView-VDB **does not** target this. Post-filter can omit
closer visible objects that were displaced by invisible candidates in the global
ranking; authorized masked top-k cannot.

---

## 12. Checkpoint tuple $$CP_\sigma$$

Proofs bind content, authorization state, policy, and search parameters to a
single checkpoint:

$$
CP_\sigma = (\sigma,\ root_{content},\ root_{auth},\ policyID,\ \theta)
$$

The verifier accepts public inputs only when the prover demonstrates that:

- slot content records open under $$root_{content}$$
- access labels open under $$root_{auth}$$ (or static labels under $$root_{content}$$
  plus dynamic state under $$root_{auth}$$)
- $$P$$ is evaluated under $$(\gamma_U, policyID, \sigma)$$
- $$\theta$$ matches the declared reference program

Extended form for static/dynamic auth split:

$$
CP_\sigma = (\sigma,\ root_{mk}^{static},\ root_{cb},\ root_{auth}^{dynamic},\ policyID,\ \theta)
$$

**Baseline status:** V3DB binds $$root_{content}$$ only. Full $$CP_\sigma$$ with
$$root_{auth}$$ is **planned**.

---

## 13. Relationship to V3DB baseline

| Aspect | V3DB (implemented) | AuthView-VDB (planned) |
|--------|-------------------|------------------------|
| Proof target | $$R = TopK_k(\{(x,d_x)\})$$ over full $$S$$ | $$R = TopK_k(\{(x,\hat d_x)\})$$ over $$Cand$$ with auth mask |
| Commitment | $$root_{content}$$ | $$root_{content} + root_{auth}$$ bound by $$CP_\sigma$$ |
| Candidate coverage | Required over $$Cand(q,S,\theta)$$ | Same, plus visibility on every candidate |
| Distance masking | Valid bit $$f_x$$ only | Valid bit $$f_x$$ **and** visibility $$v_x$$ |
| User context | N/A | $$\gamma_U$$ public input |
| Post-filter equivalence | N/A | Explicitly **not** equivalent |

V3DB's five-step pipeline, fixed-shape slots, Merkle commitment, and set-based
proof architecture remain the implementation substrate. Authorization semantics
insert between **candidate scoring** (step 4) and **top-k selection** (step 5).

See [v3db_code_map.md](v3db_code_map.md) for module-level integration points.

---

## 14. Public inputs and witness (first prototype sketch)

**Public inputs (planned):**

$$
q,\ R,\ CP_\sigma,\ \gamma_U,\ \theta
$$

**Witness (planned, non-exhaustive):**

- Content slot records and Merkle paths under $$root_{content}$$
- Authorization records and Merkle paths under $$root_{auth}$$
- PQ codes, ADC distances $$d_x$$, visibility bits $$v_x$$, masked distances $$\hat d_x$$
- Sorted top-k witness over $$\{(x,\tilde d_x)\}$$
- Policy evaluation trace for $$P$$ (as needed by circuit)

Exact witness layout is deferred to Phase 2 (ZK integration).

---

## 15. Explicit non-goals (first prototype)

The following are **out of scope** for the first AuthView-VDB prototype defined
by this document:

- Proving privacy of $$\gamma_U$$ or hiding user attributes from auditors
- Transparent-log freshness, right-to-be-forgotten, or deletion consistency proofs
- Slot-aligned auth commitment and ACL-class compression (optimization track)
- Pure/impure block proofs and access-structure-aligned commitment
- Replacing IVF-PQ with graph-based or learned index structures
- Proving only $$\forall x \in R,\ x \in V(U,\sigma)$$ without full authorized top-k
- Claiming authorization-view ZK proofs are already implemented in this repository

---

## 16. Phase 1A exit criterion

This document is complete when implementers and paper authors can answer:

1. What does $$R$$ mean formally? → Section 11.3
2. What must the prover cover? → Sections 9–10
3. How does auth differ from V3DB? → Section 13
4. What is explicitly not promised? → Section 15

Next: [security_properties.md](security_properties.md) for verifier guarantees;
[phase1_plaintext_reference_plan.md](phase1_plaintext_reference_plan.md) for
Phase 1B engineering plan.
