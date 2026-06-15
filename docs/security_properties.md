# Security Properties

Phase 1A frozen security properties for AuthView-VDB. These properties state
what a verifier should believe after accepting a proof, and what the system
**does not** guarantee.

**Status:** specification only. Authorization-view proofs are **not implemented**.
The V3DB baseline provides snapshot binding and candidate coverage over the
full corpus only.

Related: [formal_statement.md](formal_statement.md).

---

## 1. What we prove (and what we do not)

### 1.1 Target guarantee

After verifying a proof under public inputs
$$(q, R, CP_\sigma, \gamma_U, \theta)$$, the verifier should believe:

$$
R = \mathcal{A}_{auth}(q,S,V(U,\sigma);\theta)
$$

That is, the returned result equals **top-k over authorized masked distances on
the full declared candidate set** derived from committed snapshot $$S$$ and
authorization view $$V(U,\sigma)$$ at checkpoint $$\sigma$$.

### 1.2 Weaker guarantee we explicitly reject

The following is **insufficient**:

$$
\forall x \in R,\ P(\gamma_U, \lambda_x, \sigma) = 1
$$

Per-item authorization says nothing about whether closer **visible** objects were
omitted, whether the server searched the correct candidate universe, or whether
authorization state was consistent with the content snapshot.

### 1.3 Contrast with post-filter

Post-filter semantics:

$$
R_{post} = Filter\left(TopK_k(\{(x,d_x)\mid x\in Cand(q,S,\theta)\}),\ V(U,\sigma)\right)
$$

Authorized semantics:

$$
R = TopK_k(\{(x,\hat d_x)\mid x\in Cand(q,S,\theta)\})
$$

where $$\hat d_x = v_x \cdot d_x + (1-v_x)\cdot d_{max}$$ and $$v_x =
P(\gamma_U,\lambda_x,\sigma)$$.

These can differ when invisible candidates occupy top-k slots that would
displace visible neighbors under post-filter. AuthView-VDB targets the second.

---

## 2. Security properties

Each property below is stated informally, then tied to formal objects from
[formal_statement.md](formal_statement.md).

### 2.1 Snapshot Binding

**Informal:** The prover uses the content index, PQ codes, codebooks, slot
layout, and chunk identifiers committed in $$root_{content}$$—not an alternate
or partial database.

**Formal:** All opened content records hash to leaves consistent with
$$root_{content}$$ in $$CP_\sigma$$. Candidate distances $$d_x$$ are computed
from PQ codes and codebooks bound to that snapshot.

**Inherited from V3DB:** yes (baseline implements Merkle binding over IVF-PQ
layout).

**AuthView extension:** static authorization fields embedded in content slot
records must also come from $$root_{content}$$ (or a designated static sub-root).

---

### 2.2 Checkpoint Binding

**Informal:** The prover cannot mix content from one epoch with authorization
state from another, nor apply an outdated policy to a current query.

**Formal:** Public input $$CP_\sigma = (\sigma, root_{content}, root_{auth},
policyID, \theta)$$ is satisfied atomically. All auth labels $$\lambda_x$$
used in $$P(\gamma_U,\lambda_x,\sigma)$$ open under $$root_{auth}$$ (or the
static/dynamic split defined in $$CP_\sigma$$) at the same $$\sigma$$.

**Attack ruled out:** stale $$root_{auth}$$ / checkpoint mismatch—serving new
content with old permissions, or evaluating visibility under a revoked policy
while claiming a fresh snapshot.

**Baseline status:** V3DB binds snapshot commitment only; full checkpoint binding
is **planned**.

---

### 2.3 Candidate Coverage

**Informal:** The server cannot silently skip candidates mandated by the
declared IVF-PQ reference program to manipulate ranking or hide visible objects.

**Formal:** For every $$(i,j) \in Cand(q,S,\theta)$$ with $$|Cand| = n_{probe}
\cdot n$$, the proof attests that slot $$(i,j)$$ was opened, assigned distance
$$d_x$$ (or padding demotion via $$f_x$$), evaluated for $$v_x$$, and included in
the multiset equality / ordering check leading to $$R$$.

**Attack ruled out:** skipped candidate—dropping a slot that contains a closer
visible object so it never competes in top-k.

**Inherited from V3DB:** yes (fixed-shape semantics and set-based top-k witness).

---

### 2.4 View Consistency

**Informal:** Visibility bits are computed from committed access labels and the
declared user context—not ad hoc server decisions.

**Formal:** For each candidate $$x$$, $$v_x = P(\gamma_U, \lambda_x, \sigma)$$
where $$\lambda_x$$ is obtained from records bound to $$CP_\sigma$$, and $$P$$
is fixed by $$policyID$$.

**Attacks ruled out:**

- **Forged label:** inventing or altering $$\lambda_x$$ to make unauthorized
  objects appear visible (or vice versa)
- **Stale root / checkpoint mismatch:** using labels from a different
  $$root_{auth}$$ than advertised in $$CP_\sigma$$

---

### 2.5 Authorization Soundness

**Informal:** No returned object is presented as a top-k result unless it was a
visible candidate under the committed view (subject to valid-bit padding rules).

**Formal:** If $$x \in R$$ and slot $$(i,j)$$ maps to $$x$$ with $$f_x=1$$, then
$$v_x = 1$$ at the time of masked scoring, i.e. $$P(\gamma_U,\lambda_x,\sigma)=1$$.

**Note:** This property is **necessary but not sufficient** alone; it must hold
together with Retrieval Soundness (Section 2.7).

---

### 2.6 Authorized Distance Soundness

**Informal:** Masked distances used for ranking faithfully implement the
visibility policy.

**Formal:** For each $$x \in Cand(q,S,\theta)$$:

$$
\hat d_x = v_x \cdot d_x + (1-v_x) \cdot d_{max}
$$

and ADC distance $$d_x$$ matches declared PQ scoring on committed codes. Invisible
candidates ($$v_x=0$$) cannot rank ahead of visible candidates with smaller
$$\tilde d_x$$ under the declared sort key.

**Attack ruled out:** **visibility manipulation**—marking a visible, closer object
as invisible ($$v_x=0$$) to promote a less relevant visible object; or marking
invisible objects visible to smuggle them into $$R$$ (also blocked by
Authorization Soundness).

---

### 2.7 Retrieval Soundness under Authorization

**Informal:** The returned top-k is exactly the authorized masked top-k over the
**full** candidate set—not a subset, not post-filtered global top-k.

**Formal:**

$$
R = TopK_k(\{(x,\hat d_x)\mid x\in Cand(q,S,\theta)\})
$$

Equivalently:

$$
R = \mathcal{A}_{auth}(q,S,V(U,\sigma);\theta)
$$

**Attacks ruled out:**

- **Post-filter missing authorized neighbor:** returning
  $$Filter(TopK_{global}, V)$$ when a closer visible object existed in $$Cand$$
  but was excluded because invisible objects consumed ranking slots
- **Subset top-k:** computing top-k on $$Cand_{service} \subsetneq Cand(q,S,\theta)$$
- **Unauthorized expansion / contraction:** searching outside declared probe lists
  or omitting probed slots

This is the **central** AuthView-VDB guarantee beyond V3DB.

---

## 3. Property dependency map

```
Checkpoint Binding ──► View Consistency ──► Authorization Soundness
        │                      │
        ▼                      ▼
Snapshot Binding ──► Candidate Coverage ──► Authorized Distance Soundness
                                              │
                                              ▼
                              Retrieval Soundness under Authorization
```

All properties together imply the top-level statement $$R =
\mathcal{A}_{auth}(q,S,V(U,\sigma);\theta)$$.

---

## 4. Assumptions

The properties above hold under the following first-prototype assumptions:

| Assumption | Description |
|------------|-------------|
| **A1. Cryptographic hardness** | Plonky2 / hash assumptions used in V3DB baseline |
| **A2. Honest checkpoint publication** | $$CP_\sigma$$ is authenticated by a trusted directory or policy issuer (out of band) |
| **A3. Public $$\gamma_U$$** | User authorization context is known to the verifier for this query |
| **A4. Fixed reference program** | $$\theta$$ fully specifies IVF-PQ steps; no alternate ANN algorithm |
| **A5. Static epoch** | Within $$\sigma$$, $$root_{content}$$ and $$root_{auth}$$ are stable for the proof |
| **A6. Deterministic $$P$$** | Policy is a pure function of $$(\gamma_U,\lambda_x,\sigma,policyID)$$ |

---

## 5. Non-goals and limitations

The first prototype **does not** guarantee:

| Limitation | Meaning |
|------------|---------|
| **Privacy of user attributes** | $$\gamma_U$$ may be public; no hidden credential proofs |
| **Policy issuer correctness** | Verifier trusts that $$policyID$$ and $$\gamma_U$$ reflect enterprise intent |
| **Freshness beyond $$\sigma$$** | No proof that $$\sigma$$ is the latest global state |
| **Deletion / revocation propagation** | Only that evaluation is consistent with committed state at $$\sigma$$ |
| **Recall optimality** | Fixed-shape $$Cand$$ may miss global nearest neighbors outside probed slots (inherited ANN limitation) |
| **Implementation completeness** | Properties are **targets**; ZK circuits are not yet built |

---

## 6. Verifier belief summary (one page)

**After successful verification, believe:**

1. $$R$$ is the authorized masked top-k over the complete declared candidate set
2. Every candidate slot in $$Cand(q,S,\theta)$$ was scored with committed PQ data
3. Visibility used committed labels at checkpoint $$\sigma$$ under policy $$policyID$$
4. Content and authorization roots match the advertised $$CP_\sigma$$

**Do not infer:**

1. That $$\sigma$$ is the newest checkpoint globally
2. That all nearest neighbors in the full corpus appear in $$R$$ (ANN + probe limit)
3. That authorization-view proofs exist in the current repository baseline

---

## 7. Phase 1A exit criterion

Security properties are frozen when Phase 1B attack cases and the plaintext
reference can be checked against Sections 2.1–2.7 without semantic ambiguity.

Next: [phase1_plaintext_reference_plan.md](phase1_plaintext_reference_plan.md).
