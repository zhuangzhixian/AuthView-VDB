# Phase 1B Plan: Plaintext Authorized IVF-PQ Reference

Engineering plan for the next phase after Phase 1A formal semantics freeze.
**This document is a plan only.** No reference implementation exists yet.

**Prerequisites (complete):**

- Phase 0: V3DB code map, baseline build, synthetic Merkle ZK proof path
- Phase 1A: [formal_statement.md](formal_statement.md),
  [security_properties.md](security_properties.md)

**Constraints for Phase 1B:**

- Do **not** modify Rust proof logic or V3DB baseline paths
- Add **independent** experimental/reference code under a new namespace
- Validate semantics in plaintext before any ZK circuit changes

---

## 1. Objective

Implement a **plaintext reference interpreter** for $$\mathcal{A}_{auth}$$ that:

1. Reuses V3DB Python IVF-PQ query structure where possible
2. Adds authorization records, visibility bits, and masked top-k
3. Provides a checker that rejects known attack instances
4. Demonstrates semantic gap vs post-filter baseline

Success means: given $$(q, S, \gamma_U, \sigma, \theta)$$, the reference
computes $$R$$ per [formal_statement.md](formal_statement.md) and a separate
validator confirms [security_properties.md](security_properties.md) at the
reference level (no ZK).

---

## 2. Why plaintext first

| Reason | Detail |
|--------|--------|
| Lower debug cost | ZK bugs conflate witness errors with circuit errors |
| Semantic anchor | Paper and circuits share one executable definition |
| Attack harness | Synthetic adversarial instances before proving |
| V3DB isolation | Baseline `ivf_pq/merkle_zk.py` path stays untouched |

Phase 0 showed the V3DB Merkle ZK path works on synthetic data. Phase 1B asks
**what correct authorized semantics produce** before encoding them in Plonky2.

---

## 3. Proposed code layout (Phase 1B — not created in Phase 1A)

```
auth_reference/           # new package (name tentative)
  __init__.py
  policy.py               # P(gamma_U, lambda_x, sigma)
  records.py              # content + auth record structs
  query.py                # authorized IVF-PQ reference query
  coverage.py             # Cand(q,S,theta) enumeration + checks
  post_filter_baseline.py # weak comparator
  checker.py              # security property tests at reference level
tests/
  test_auth_reference.py
  test_auth_attacks.py
artifacts/
  plaintext_attack_cases.json
  auth_reference_smoke_metrics.csv
```

**Do not** edit: `src/`, `ivf_pq/merkle_zk.py`, `ivf_pq/zk.py`, `bench/`,
`bench_free_bench/`, or existing `tests/merkle_zk.py`.

Optional: thin wrapper script `scripts/auth_reference_demo.sh` (new file only).

---

## 4. Implementation tasks

### 4.1 Authorization records and policy

| Task | Description |
|------|-------------|
| Define `AuthLabel` | Fields aligned with $$\lambda_x$$: tenant, project, level, state, epoch |
| Define `UserContext` | $$\gamma_U$$ struct |
| Implement `P(gamma_U, lambda_x, sigma)` | First version: tenant match + project membership + clearance + state valid |
| Synthetic dataset generator | Small corpora with mixed visibility for unit tests |

Reference: [formal_statement.md](formal_statement.md) Sections 5–7.

### 4.2 Build on V3DB Python query path (read-only reuse)

Copy **logic patterns** from (do not modify originals):

| Source | Reuse |
|--------|-------|
| `ivf_pq/pipeline.py` or `ivf_pq/merkle_zk.py` | Centroid distance, probe selection, ADC scoring loop |
| `ivf_pq/rebalance.py`, `upperbound` | Fixed-shape $$n$$ per list |
| `ivf_pq/merkle_zk.py` slot layout | `(valid, item, vpqs)` per $$(i,j)$$ |

The reference computes $$d_x$$ the same way as V3DB Python (integer ADC/PQ).
Authorization layers wrap this output.

### 4.3 Candidate coverage check

Implement explicit enumeration of:

$$
Cand(q,S,\theta) = \{(i,j) \mid i \in P(q),\ j \in [n]\}
$$

Checker verifies:

- $$|Cand| = n_{probe} \cdot n$$
- Every $$(i,j)$$ receives $$(f_{i,j}, v_{i,j}, d_{i,j}, \hat d_{i,j})$$
- No $$(i,j)$$ missing from scoring trace

Maps to **Candidate Coverage** in [security_properties.md](security_properties.md).

### 4.4 Visibility mask

For each candidate slot with object $$x$$:

$$
v_x = P(\gamma_U, \lambda_x, \sigma)
$$

$$
\hat d_x = v_x \cdot d_x + (1-v_x) \cdot d_{max}
$$

Combine with valid bit:

$$
\tilde d_x = f_x \cdot \hat d_x + (1-f_x) \cdot d_{max}
$$

Use $$d_{max}$$ consistent with V3DB sentinel (e.g. $$2^{62}-1$$ in Merkle path).

### 4.5 Authorized top-k

$$
R = TopK_k(\{(x,\tilde d_x) \mid (i,j) \in Cand(q,S,\theta)\})
$$

Stable sort by $$(\tilde d_x, id_x)$$. Return item ids and full scoring trace for
checker consumption.

### 4.6 Post-filter baseline (comparator)

Implement weak semantics for contrast:

$$
R_{post} = Filter\left(TopK_k(\{(x,d_x)\}),\ V(U,\sigma)\right)
$$

Document and test cases where $$R_{post} \neq R$$ (see Section 5).

---

## 5. Attack case harness

Each attack is a **negative test**: reference checker must **reject** or
reference output must **differ** from adversarial claim.

| Attack | Description | Expected outcome |
|--------|-------------|------------------|
| **Skipped candidate** | Omit slot $$(i,j)$$ containing closer visible $$x$$ from scoring | Checker fails Candidate Coverage |
| **Forged label** | Use $$\lambda'_x \neq \lambda_x$$ from committed auth state | Checker fails View Consistency |
| **Stale root / checkpoint mismatch** | Evaluate $$P$$ with $$\sigma' \neq \sigma$$ in $$CP_\sigma$$ | Checker fails Checkpoint Binding |
| **Post-filter missing authorized neighbor** | Adversary returns $$R_{post}$$ when $$R$$ (masked top-k) differs | Comparator shows $$R_{post} \neq R$$; closer visible object omitted from $$R_{post}$$ |
| **Visibility manipulation** | Set $$v_x=0$$ for visible closer $$x$$ | Authorized top-k changes; checker detects inconsistent $$v_x$$ vs $$P$$ |

Store parameterized instances in `artifacts/plaintext_attack_cases.json`.

Optional additional cases (lower priority):

- Return unauthorized object in $$R$$ (violates Authorization Soundness)
- Search strict subset of probe lists (violates Candidate Coverage)

---

## 6. Testing strategy

| Test type | Content |
|-----------|---------|
| Unit | $$P$$ policy, mask arithmetic, sort key |
| Integration | End-to-end reference query on synthetic $$S$$ |
| Regression | $$R_{auth} = R_{v3db}$$ when all $$v_x=1$$ and policy is trivial |
| Negative | All Section 5 attacks |
| Contrast | At least one constructed case with $$R_{post} \neq R$$ |

Run without Rust extension for core reference logic (numpy/faiss only). Optional
cross-check: when all visible, reference top-k matches `ivf_pq/merkle_zk.py`
`proof=False` path output.

---

## 7. Deliverables and exit criteria

| Deliverable | Description |
|-------------|-------------|
| `auth_reference/` package | Plaintext $$\mathcal{A}_{auth}$$ implementation |
| `tests/test_auth_reference.py` | Correctness on visible-only and mixed-visibility corpora |
| `tests/test_auth_attacks.py` | Negative tests for Section 5 |
| `artifacts/plaintext_attack_cases.json` | Serialized attack parameters |
| `artifacts/auth_reference_smoke_metrics.csv` | Query time, $$|Cand|$$, $$|R|$$ on smoke configs |

**Phase 1B exit criteria:**

1. Reference computes $$R = TopK_k(\{(x,\hat d_x)\mid x\in Cand\})$$ per frozen semantics
2. All five attack categories detected or demonstrated
3. At least one documented $$R_{post} \neq R$$ example with explanation
4. V3DB baseline files and Rust modules unchanged
5. No claim of ZK proof for authorization view

---

## 8. Explicit non-goals (Phase 1B)

- Modifying `src/merkle_ver/set_based.rs` or other proof circuits
- Integrating auth into `py_set_based_with_merkle`
- Merkle commitment of $$root_{auth}$$ (Phase 2+)
- SIFT / MS MARCO large-scale benchmarks
- Performance optimization (ACL-class compression, block proofs)

---

## 9. Suggested execution order

| Step | Duration | Output |
|------|----------|--------|
| 1. Records + policy | 2–3 days | `policy.py`, unit tests |
| 2. Reference query loop | 3–4 days | `query.py` with coverage trace |
| 3. Post-filter comparator | 1 day | `post_filter_baseline.py` |
| 4. Checker + attacks | 2–3 days | `checker.py`, attack JSON, negative tests |
| 5. Smoke + doc update | 1 day | metrics CSV, link from reproduction log |

---

## 10. Handoff to Phase 2 (ZK integration preview)

After Phase 1B, the following should be ready for circuit design **without**
semantic changes:

- Frozen $$P$$, $$\hat d_x$$, and top-k sort key
- Witness trace format: per-slot $$(f_x, v_x, d_x, \tilde d_x)$$
- Attack cases as circuit regression fixtures

ZK work extends `set_based.rs` valid-bit masking pattern; plaintext reference
is the oracle. See [v3db_code_map.md](v3db_code_map.md) Section 7.

---

## Related documents

- [formal_statement.md](formal_statement.md)
- [security_properties.md](security_properties.md)
- [v3db_code_map.md](v3db_code_map.md)
- [v3db_reproduction_log.md](v3db_reproduction_log.md)
