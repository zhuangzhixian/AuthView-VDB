# Phase 2A: ZK Integration Design

Design freeze for extending V3DB set-based Merkle IVF-PQ proofs with
authorization-view semantics. **No Rust implementation in Phase 2A** — this
document specifies the integration plan for Phase 2B.

**Status:** design only. V3DB baseline proofs are implemented; authorized
visibility masking is **not**.

Related: [formal_statement.md](formal_statement.md),
[security_properties.md](security_properties.md),
[phase1_v3db_adapter_log.md](phase1_v3db_adapter_log.md),
[phase2_witness_layout.md](phase2_witness_layout.md),
[phase2_test_plan.md](phase2_test_plan.md).

---

## 1. Current V3DB set-based Merkle proof path

### 1.1 Python entry

`ivf_pq/merkle_zk.py` → `py_set_based_with_merkle` (`src/lib.rs`) →
`set_based_ivf_pq_proof` (`src/merkle_ver/set_based_proof.rs`).

### 1.2 Circuit pipeline (`set_based_ivf_pq_gadget`)

| Step | Location | What is proved |
|------|----------|----------------|
| 1 | `static_nn_gadget` | Probe list selection matches committed centroids + query |
| 2 | `codebooks_query_gadget` | ADC LUT entries per probed list |
| 3 | Loop `i,j` over slots | PQ distance sum; **valid-bit masking** → `(item, effective_dis)` |
| 4 | `set_equal_gadget` + `comp_gadget` | Witness sorted `(item, dis)` multiset equals computed pairs; non-decreasing |
| 5 | `set_belong_gedget` | PQ codes / per-code distances ⊆ LUT set |
| 6 | Public inputs | Top-k item ids from sorted witness |
| 7 | `standalone_commitment_gadget` (optional) | Merkle opens for content snapshot |

Content Merkle leaf format (`merkle_cluster_gadget`, `ivf_pq_merkle.rs`):

```
(cluster_idx, slot_j, valid, item_id, pq_codes[M])
```

Commitment public inputs: `root`, `codebooks_root`.

### 1.3 Distance semantics today (valid-bit only)

For each candidate slot $$x$$ with raw ADC/PQ distance $$d_x$$ and valid bit
$$valid_x \in \{0,1\}$$:

$$
\tilde d_x = valid_x \cdot d_x + (1-valid_x)\cdot d_{max}
$$

Implemented in `set_based.rs` lines 91–96:

```rust
let vld = valids[i][j];
let vld_dis = builder.mul(vld, curr_dis);
let max_dis = builder.mul(sub_vld, max_gadget);  // (1-vld) * d_max
vpqss_item_dis.push(vec![itemss[i][j], builder.add(vld_dis, max_dis)]);
```

where $$d_{max} = 2^{62}-1$$ (`4611686018427387903`).

Top-k public outputs are the first $$k$$ item ids from witness
`ordered_vpqss_item_dis` sorted by effective distance.

---

## 2. AuthView-VDB extension semantics

Per [formal_statement.md](formal_statement.md), add visibility
$$v_x = P(\gamma_U, \lambda_x, \sigma)$$ before top-k:

$$
\hat d_x = valid_x\cdot(v_x\cdot d_x+(1-v_x)\cdot d_{max})+(1-valid_x)\cdot d_{max}
$$

Equivalently, with combined gate $$g_x = valid_x \cdot v_x$$:

$$
\hat d_x = g_x \cdot d_x + (1-g_x)\cdot d_{max}
$$

where $$g_x = 1$$ only when the slot is valid **and** visible.

**Authorized top-k:**

$$
R = TopK_k(\{(x,\hat d_x) \mid x \in Cand(q,S,\theta)\})
$$

The set-equality / ordering check in step 4 must bind to $$\hat d_x$$, not
$$\tilde d_x$$, when authorization mode is enabled.

---

## 3. Exact insertion point in `set_based.rs`

**Primary edit locus:** step 3 inner loop, lines 81–97, **after** `curr_dis`
is computed and **before** pushing to `vpqss_item_dis`.

```
Current:
  curr_dis = sum(vpqss_dis[i][j])
  effective = valid * curr_dis + (1-valid) * d_max

Proposed (auth mode):
  curr_dis = sum(vpqss_dis[i][j])
  v_x      = auth_policy_gadget(gamma_U, lambda_x, sigma)   // NEW
  gated    = valid * v_x                                    // NEW (optional explicit)
  hat_d    = v_x * curr_dis + (1 - v_x) * d_max           // NEW (auth mask on raw d)
  hat_d    = valid * hat_d + (1 - valid) * d_max          // SAME pattern as today
  push (item, hat_d)
```

**Do not** change steps 1–2 (probe + LUT) or step 5 (LUT membership) in the
first Phase 2B milestone unless a bug is found.

**Secondary insertion points (later milestones):**

| Location | Purpose |
|----------|---------|
| `standalone_commitment_gadget` | Bind `cid` across content and auth Merkle opens |
| `merkle_cluster_gadget` / new `merkle_cluster_auth_gadget` | Slot-aligned auth leaves |
| Public input registration | `CP_sigma`, $$\gamma_U$$, optional `root_auth` |

---

## 4. Proposed authorization witness layout (per selected slot)

For each $$(i,j) \in Cand$$ (see [phase2_witness_layout.md](phase2_witness_layout.md)):

| Field | Role |
|-------|------|
| Content (existing) | `valid`, `item_id/cid`, `vpqss`, Merkle path |
| Auth label $$\lambda_x$$ | `tenant`, `project`, `level`, `state`, `epoch`, optional `role` bits |
| Auth open | Merkle path under `root_auth` (Phase 2C; optional stub in 2B) |
| Visibility | $$v_x$$ as witness bit, constrained by policy gadget |
| Distances | $$d_x$$ (computed), $$\hat d_x$$ (constrained) |

**Phase 2B minimal:** auth label fields carried as witness without
`root_auth` Merkle verification; prover supplies labels, circuit computes
$$v_x$$ from public $$\gamma_U$$ and public checkpoint epoch/policy id.
Labels bound to `cid` by equality constraint with `itemss[i][j]`.

---

## 5. Proposed public inputs

### 5.1 Unchanged from V3DB

| Input | Description |
|-------|-------------|
| `query` | $$q$$ |
| `root` | $$root_{content}$$ / global Merkle root |
| `codebooks_root` | $$root_{cb}$$ |
| `top_k` item ids | First $$k$$ entries of sorted authorized witness |

### 5.2 New (authorization mode)

| Input | Description |
|-------|-------------|
| $$\gamma_U$$ | User context (tenant, clearance, project set encoding, epoch) |
| $$CP_\sigma$$ | Checkpoint tuple — minimally `(sigma_id, epoch, policy_id)` |
| `auth_mode` flag | Distinguish baseline vs authorized proof (compile-time or runtime) |

### 5.3 Deferred (Phase 2C+)

| Input | Description |
|-------|-------------|
| `root_auth` | Authorization-state Merkle root |
| Full $$R$$ as public set | May remain top-k item ids only, matching V3DB |

Search parameters $$\theta$$ remain implicit in circuit shape
(`n_probe`, `n`, `M`, `K`, `top_k`).

---

## 6. Proposed private witnesses

| Witness | Description |
|---------|-------------|
| IVF / PQ (existing) | `ivf_center`, `cluster_idx_dis`, `vpqss`, `vpqss_dis`, `valids`, `itemss`, `cluster_pairs`, `ordered_vpqss_item_dis` |
| Auth per slot | Label fields, optional auth Merkle siblings |
| Policy aux | Bit decompositions for comparison gadgets (clearance ≥ level) |
| Set-equality aux | `f_`, `t_` for `set_belong_gedget` (unchanged) |

Prover computes `ordered_vpqss_item_dis` from authorized $$\hat d_x$$ off-circuit;
circuit verifies via `set_equal_gadget` (same pattern as V3DB).

---

## 7. Proposed circuit relation

Authorization-mode proof $$\pi$$ for public
$$(q, root_{content}, root_{cb}, \gamma_U, CP_\sigma, R_{topk})$$ demonstrates:

1. **Snapshot binding:** content slots and codebooks open under committed roots
2. **Candidate coverage:** all $$n_{probe} \cdot n$$ slots scored (unchanged loop bounds)
3. **ADC correctness:** PQ distances ⊆ LUT set (unchanged)
4. **Visibility:** $$v_x = P(\gamma_U, \lambda_x, \sigma)$$ for each valid slot
5. **Masked distance:** $$\hat d_x = valid_x(v_x d_x + (1-v_x)d_{max}) + (1-valid_x)d_{max}$$
6. **Authorized top-k:** public item ids equal first $$k$$ of sorted $$\{(cid, \hat d_x)\}$$

Does **not** prove (Phase 2B): freshness of $$\sigma$$, privacy of $$\gamma_U$$,
or that labels come from `root_auth` (unless Merkle auth path added).

---

## 8. Computing visibility in-circuit

First-prototype policy (matches `auth_reference/policy.py`):

| Rule | Gadget sketch |
|------|---------------|
| Tenant match | `is_equal(tenant_x, tenant_U)` |
| Project membership | `is_member(project_x, Projects_U)` |
| Clearance | `clearance_U >= level_x` (range/compare) |
| Active state | `state_x == ACTIVE` |
| Epoch | `epoch_x == 0 OR epoch_x == checkpoint.epoch` |
| Role (optional) | OR of role match bits |

$$
v_x = AND(\text{all rules})
$$

For invalid slots ($$valid_x=0$$), $$v_x$$ may be constrained to 0 or left
 unconstrained but masked out by valid gate in $$\hat d_x$$.

**All-visible mode:** set policy gadget output to 1 when `auth_mode=all_visible`
(bypass or constant-wire), for regression against V3DB.

---

## 9. Extending masked distance

Algebraically equivalent forms (choose one for minimal gates):

**Form A (two-step, mirrors Python reference):**

$$
\hat d_x = v_x \cdot d_x + (1-v_x)\cdot d_{max}
\quad\text{then}\quad
\hat d_x := valid_x \cdot \hat d_x + (1-valid_x)\cdot d_{max}
$$

**Form B (single combined gate):**

$$
g_x = valid_x \cdot v_x,\quad \hat d_x = g_x \cdot d_x + (1-g_x)\cdot d_{max}
$$

Form B reuses the **existing valid-bit mul pattern** with $$g_x$$ replacing
$$valid_x$$ — lowest-risk insertion for Phase 2B.

---

## 10. Binding auth label to content slot

Phase 2B (minimal):

```
constraint: itemss[i][j] == cid_from_auth_record
constraint: auth_label.cid == itemss[i][j]
```

Phase 2C (slot-aligned):

- Content leaf: `(list_id, slot_j, valid, cid, pq_codes)`
- Auth leaf: `(list_id, slot_j, cid, tenant, project, level, state, epoch)`
- Constraint: content.list_id = auth.list_id AND content.slot_j = auth.slot_j
- Merkle opens at same path depth under `root_auth`

**cid-keyed fallback:** auth Merkle keyed by `cid`; circuit checks opened auth
record cid matches content item id (higher opening cost, simpler commitment).

---

## 11. All-visible regression in ZK

Requirement from Phase 1C: when $$v_x=1$$ for all valid slots,

$$
\hat d_x = \tilde d_x \quad\text{(V3DB effective distance)}
$$

Implementation strategy:

1. **Compile flag** `auth_all_visible` wires $$v_x \leftarrow 1$$ for valid slots
2. Proof must reproduce identical `ordered_vpqss_item_dis` as baseline prover
3. Python test: same slot buffers → `py_set_based_auth_with_merkle` vs
   `py_set_based_with_merkle` → identical public top-k ids and verify success
4. Gate count should equal baseline + small constant (policy bypass)

---

## 12. Keeping baseline V3DB path unchanged

| Principle | Implementation |
|-----------|----------------|
| No destructive edits | Keep `set_based_ivf_pq_gadget` and `py_set_based_with_merkle` behavior identical when auth disabled |
| Additive API | New `set_based_auth_ivf_pq_gadget` + `py_set_based_auth_with_merkle` |
| Shared sub-gadgets | Reuse LUT, Merkle, set-equality modules |
| Python baseline untouched | New wrapper in `auth_reference/` or `ivf_pq/auth_merkle_zk.py` (new file) calling new pyo3 export |
| Feature flag | `auth_mode: none | all_visible | policy` |

Existing benchmarks and `tests/merkle_zk.py` continue to call original APIs.

---

## 13. Phase 2B implementation order

| Priority | Task | Rationale |
|:--------:|------|-----------|
| 1 | `auth_policy_gadget` (Rust) + unit tests vs `auth_reference/policy.py` | Oracle alignment |
| 2 | `set_based_auth_ivf_pq_gadget` with Form B masking | Single insertion point |
| 3 | `set_based_auth_ivf_pq_proof` + `py_set_based_auth_with_merkle` | End-to-end smoke |
| 4 | All-visible regression test | Proves no regression vs V3DB |
| 5 | Partial-visible test vs plaintext reference | Proves auth semantics |
| 6 | Python witness builder from `v3db_adapter` + labels | Prover plumbing |
| 7 | Gate count / timing CSV | Baseline comparison |

**Defer:** `root_auth` Merkle, slot-aligned auth commitment, checkpoint binding
beyond epoch integer, role-set optimization.

---

## 14. Risk summary

| Risk | Mitigation |
|------|------------|
| Accidental baseline breakage | Separate gadget function; CI runs old + new tests |
| Tie-break mismatch | Use V3DB stable sort for witness generation; document cid tie-break |
| Policy gadget cost | Start with simplified public $$\gamma_U$$; all-visible mode first |
| Witness size | Fixed-shape slots keep $$N_{sel}$$ constant |
| Label forgery without `root_auth` | Document as Phase 2B limitation; add Merkle in 2C |

---

## Related files (read-only reference)

| File | Relevance |
|------|-----------|
| `src/merkle_ver/set_based.rs` | Primary insertion point |
| `src/merkle_ver/set_based_proof.rs` | Prover witness assembly |
| `src/merkle_ver/ivf_pq_merkle.rs` | Content leaf layout |
| `src/merkle_ver/standalone_commitment.rs` | Merkle verification |
| `auth_reference/reference.py` | Plaintext oracle |
| `auth_reference/v3db_adapter.py` | Slot buffer → candidate records |
