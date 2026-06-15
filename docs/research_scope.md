# Research Scope

AuthView-VDB is a research prototype that extends V3DB-style verifiable IVF-PQ
search toward **proof-carrying retrieval over committed authorization views**.
This document describes the intended research scope. **None of the
authorization-view mechanisms below are implemented in the current baseline.**

## Problem statement

V3DB proves that a returned top-k equals the output of a fixed-shape IVF-PQ
reference semantics on a committed content snapshot. In multi-tenant enterprise
knowledge bases and private RAG settings, retrieval is often executed over a
**user-specific visible subset** of the corpus, not the full snapshot.

The research target is stronger than per-object authorization checks. The prover
should demonstrate:

```
R = A_auth(q, S, V(U, σ); θ)
```

where `R` is the returned top-k, `q` is the query, `S` is the committed content
snapshot, `V(U, σ)` is the user's visible view under access checkpoint `σ`, `U`
is the user authorization context, and `θ` are public retrieval parameters.

The goal is to prove that the service executed the **declared ANN program on the
authorized view**, not that it searched the full corpus and post-filtered results.

## Core concepts

### Committed authorization view retrieval

A shared physical IVF-PQ index may serve many tenants, but each query is
semantically scoped to objects visible under `(γ_U, λ_x, σ)`—user context,
object access labels, and a dynamic access checkpoint. The verifier must be
convinced that ranking and selection happened within that view.

### Authorization-aware IVF-PQ proving semantics

V3DB standardizes five fixed-shape steps: centroid distances, probe selection,
ADC lookup tables, candidate scoring, and top-k selection. The planned extension
inserts authorization semantics between candidate scoring and top-k:

1. Open content and authorization records for each candidate slot.
2. Compute visibility `v_x = P(γ_U, λ_x, σ)`.
3. Apply visibility-gated or masked distances.
4. Select authorized top-k over the full declared candidate set.

### Content snapshot commitment plus authorization-state commitment

Content commitments bind centroids, inverted lists, slot records, PQ codes,
codebooks, valid bits, and chunk identifiers. Authorization commitments bind
access labels and dynamic state (tenant, project, clearance, revocation,
epoch, policy version). Proofs must bind both layers to the same checkpoint.

### Checkpoint binding

Content and authorization state may update at different rates. Public inputs
should include a checkpoint tuple, e.g. `CP_σ = (σ, root_content, root_auth,
policyID, θ)`, so the prover cannot mix roots from different epochs or policy
versions.

### Candidate coverage

A central security requirement inherited from V3DB: the prover must show that
**all candidates mandated by the reference semantics**—not an arbitrary
server-chosen subset—underwent visibility evaluation and masked scoring.

For fixed-shape IVF-PQ with `n_probe` lists and `n` slots per list, expected
coverage is `N_sel = n_probe · n`. Both list selection and within-list slot
coverage must be tied to committed index structure.

### Visibility mask

Each candidate slot carries a visibility bit `v_x ∈ {0,1}`. Invisible candidates
are demoted via a large distance constant `d_max` or an equivalent sort key
`(1 - v_x, d̂_x, id_x)` so they cannot outrank visible neighbors.

### Authorized top-k

Final results must equal top-k over masked or visibility-gated distances across
the full declared candidate set:

```
R = TopK_k({(x, d̂_x) | x ∈ Cand(q, S, θ)})
```

This differs from proving only `∀ x ∈ R, x ∈ V(U, σ)`.

### Slot-aligned auth commitment

Random cid-keyed authorization trees require independent Merkle openings per
candidate. A slot-aligned layout mirrors the fixed-shape inverted lists so that
opening a selected list can batch-open aligned authorization records and bind
`cid` consistency between content and auth layers.

### ACL-class compression

Enterprise permissions often cluster by tenant, project, role combination, or
ACL class. Dynamic authorization state can be organized by ACL class rather
than per-chunk, reducing opening cost when many candidates share the same class.

## Relationship to V3DB and filtered ANN search

| Aspect | V3DB | Filtered / access-aware ANN | AuthView-VDB (planned) |
|--------|------|----------------------------|------------------------|
| Trust model | Untrusted prover | Trusted server | Untrusted prover |
| Scope | Full committed snapshot | Authorized or filtered subset | Committed authorization view |
| Main output | Result + ZK proof | Result | Result + ZK proof |
| Candidate coverage | Required | Not typically proven | Required over authorized semantics |
| State consistency | Snapshot commitment | Not typically proven | Content + auth checkpoint binding |

AuthView-VDB is **not** primarily a faster filtered ANN algorithm. It targets
**proof-carrying filtered vector search** where authorization constraints are
part of the retrieval program, not an external post-filter.

Access-aware indexing informs optimization (pure/impure blocks, ACL classes) but
remains complementary: those systems optimize recall and cost under trust;
AuthView-VDB adds verifiability under distrust.

## Current baseline vs planned work

| Area | V3DB baseline (present) | AuthView-VDB (planned) |
|------|-------------------------|------------------------|
| Fixed-shape IVF-PQ semantics | Yes | Extend with auth-aware scoring |
| Snapshot / Merkle commitment | Yes | Add auth-state commitment |
| Visibility mask & authorized top-k | No | Planned |
| Checkpoint binding | Partial (snapshot only) | Full content + auth binding |
| Slot-aligned auth commitment | No | Planned optimization |
| ACL-class compression | No | Planned optimization |

## Out of scope for the first research milestone

- Privacy-preserving user authorization credentials (initial versions may treat
  `γ_U` as a public authenticated input).
- Dynamic freshness, transparent-log consistency, and deletion proofs beyond
  static epoch checkpoints.
- Replacing IVF-PQ with alternative index structures (fixed-shape semantics
  remain the primary ZK-friendly path).
