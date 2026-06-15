# Phase 2 Witness Layout

Witness and public-input specification for authorized set-based IVF-PQ proofs.
Aligned with [formal_statement.md](formal_statement.md) and
[phase2_zk_integration_design.md](phase2_zk_integration_design.md).

**Status:** design only — not yet implemented in Rust.

---

## 1. Overview

Fixed-shape candidate set:

$$
Cand(q,S,\theta) = \{(i,j) \mid i \in P(q),\ j \in [0,n)\},\quad N_{sel} = n_{probe}\cdot n
$$

Each slot carries **content witness** (V3DB) and **authorization witness**
(AuthView extension). The prover supplies a sorted array
`ordered_auth_item_dis` of shape `(N_sel, 2)` as `(cid, hat_d_x)`; the circuit
recomputes pairs and checks multiset equality and non-decreasing order.

---

## 2. Public inputs

### 2.1 Shared with V3DB

| Name | Type / shape | Symbol |
|------|--------------|--------|
| `query` | `[D]` int | $$q$$ |
| `root` | field | $$root_{content}$$ |
| `codebooks_root` | field | $$root_{cb}$$ |
| `top_k_items[k]` | `k` ints | Top-k cids from authorized ranking |

### 2.2 Authorization (Phase 2B)

| Name | Type / shape | Symbol |
|------|--------------|--------|
| `user_tenant` | int / bytes | $$\gamma_U.tenant$$ |
| `user_clearance` | int | $$\gamma_U.clearance$$ |
| `user_epoch` | int | $$\gamma_U.epoch$$ |
| `user_projects` | bit vector / hash | $$\gamma_U.Projects_U$$ |
| `checkpoint_epoch` | int | $$\sigma.epoch$$ |
| `policy_id` | int | `policyID` |

**Design choice (Phase 2B):** $$\gamma_U$$ and checkpoint fields are **public**
authenticated inputs, matching [formal_statement.md](formal_statement.md) Section 14.

### 2.3 Future public inputs (Phase 2C+)

| Name | Symbol |
|------|--------|
| `root_auth` | $$root_{auth}$$ |
| `checkpoint_id` | $$\sigma$$ (full binding) |

---

## 3. Per-slot content witness

For each probe index `i ∈ [0, n_probe)` and slot `j ∈ [0, n)`:

| Field | Source (V3DB) | Notes |
|-------|---------------|-------|
| `list_id` | `cluster_idxes[i]` | IVF list id |
| `slot_id` | `j` | Fixed-shape slot index |
| `valid` | `valids[i][j]` | 1 = real vector, 0 = padding |
| `cid` | `itemss[i][j]` | Item / chunk id |
| `vpqss[i][j][0:M]` | PQ code indices | ADC lookup |
| `vpqss_dis[i][j][0:M]` | Per-subspace LUT distances | For set membership |
| `cluster_pairs[i]` | Merkle path | Content snapshot open |

Merkle leaf hash (content):

```
H(list_id, slot_id, valid, cid, pq_codes[0], ..., pq_codes[M-1])
```

Matches `merkle_cluster_gadget` in `ivf_pq_merkle.rs`.

---

## 4. Per-slot authorization witness

### 4.1 Phase 2B minimal (no root_auth Merkle)

| Field | Type | Role |
|-------|------|------|
| `auth_cid` | int | Must equal content `cid` |
| `tenant` | tag | $$\lambda_x.tenant$$ |
| `project` | tag | $$\lambda_x.project$$ |
| `level` | int | $$\lambda_x.level$$ |
| `state` | enum int | $$\lambda_x.state$$ |
| `epoch` | int | $$\lambda_x.epoch$$ |
| `roles` | bitset (optional) | $$\lambda_x.roleSet$$ |
| `visibility` | bit | $$v_x$$ (witness, constrained) |
| `raw_distance` | int | $$d_x$$ (copy of computed ADC sum) |
| `hat_distance` | int | $$\hat d_x$$ (constrained masked value) |

Constraints:

1. `auth_cid == cid`
2. `visibility == P(gamma_U, lambda_x, sigma)` via policy gadget
3. `hat_distance == valid * (visibility * raw_distance + (1-visibility)*d_max) + (1-valid)*d_max`

### 4.2 Phase 2C extension (root_auth Merkle)

Additional per slot:

| Field | Role |
|-------|------|
| `auth_merkle_siblings[]` | Open auth record under `root_auth` |
| `auth_leaf_hash` | Recomputed leaf binds label fields + cid |

Slot-aligned auth leaf (target):

```
H(list_id, slot_id, cid, tenant, project, level, state, epoch, ...)
```

---

## 5. User context and checkpoint

### 5.1 User context $$\gamma_U$$

| Field | Public / witness | Phase 2B |
|-------|------------------|----------|
| `user_id` | public (optional) | omit |
| `tenant` | **public** | yes |
| `projects` | **public** (encoded set) | yes |
| `clearance` | **public** | yes |
| `roles` | **public** (encoded set) | optional |
| `epoch` | **public** | yes |

### 5.2 Checkpoint $$CP_\sigma$$

Minimal tuple for Phase 2B:

```
CP_sigma = (checkpoint_epoch, policy_id, root_content, root_cb)
```

Full tuple (Phase 2C):

```
CP_sigma = (sigma, root_content, root_auth, policy_id, theta)
```

Circuit binds `checkpoint_epoch` against label epochs in policy evaluation.

---

## 6. Distance fields summary

| Symbol | Meaning | Computed in circuit |
|--------|---------|---------------------|
| $$d_x$$ | Raw ADC/PQ sum | yes (`add_many(vpqss_dis)`) |
| $$\tilde d_x$$ | V3DB effective (valid only) | baseline mode |
| $$\hat d_x$$ | Authorized masked distance | auth mode |
| $$d_{max}$$ | Sentinel $$2^{62}-1$$ | constant |

Relationship:

$$
\hat d_x = valid_x\cdot(v_x\cdot d_x+(1-v_x)\cdot d_{max})+(1-valid_x)\cdot d_{max}
$$

---

## 7. Top-k public outputs

V3DB registers `ordered_vpqss_item_dis[i][0]` for `i < top_k` as public inputs.

AuthView preserves this interface: public outputs are **authorized** top-k cids
(sorted by $$\hat d_x$$ with V3DB-compatible stable tie-break in witness
generation).

Optional future extension: publish $$\hat d_x$$ values for audit (not required
Phase 2B).

---

## 8. All-visible compatibility mode

When `auth_mode = all_visible`:

| Field | Behavior |
|-------|----------|
| `visibility` | Hard-wire or constrain to 1 when `valid=1` |
| Policy gadget | Bypassed or trivially satisfied |
| `hat_distance` | Must equal V3DB $$\tilde d_x$$ |
| Witness sort order | Match V3DB slot iteration order for ties |

Regression oracle: `auth_reference/v3db_adapter.py` → `authorized_topk_v3db_tiebreak`
must match `py_set_based_with_merkle` public outputs.

---

## 9. Partial-visible mode

When some $$v_x = 0$$:

| Field | Behavior |
|-------|----------|
| `visibility` | From policy gadget |
| `hat_distance` | $$d_{max}$$ for invisible valid slots |
| Top-k | Visible valid cids ranked by $$\hat d_x$$ |
| Oracle | `auth_reference/reference.py` → `run_authorized_reference` |

Padding slots ($$valid_x=0$$): $$\hat d_x = d_{max}$$ regardless of $$v_x$$.

---

## 10. Phase 2B minimal witness checklist

Per slot (required for first implementation):

- [x] `cid`
- [x] `valid`
- [x] `list_id`
- [x] `slot_id`
- [x] raw distance $$d_x$$
- [x] auth label fields (tenant, project, level, state, epoch)
- [x] visibility bit $$v_x$$
- [x] masked distance $$\hat d_x$$
- [x] global sorted witness `ordered_auth_item_dis[N_sel, 2]`
- [x] selected top-k ids (public)

Global (required):

- [x] `query`, `root`, `codebooks_root`
- [x] public $$\gamma_U$$ fields
- [x] `checkpoint_epoch`, `policy_id`
- [x] V3DB PQ / Merkle witnesses (unchanged)

Deferred:

- [ ] `root_auth` Merkle paths
- [ ] Private $$\gamma_U$$ credentials
- [ ] ACL-class compressed auth opens

---

## 11. Witness generation flow (prover, off-circuit)

```
1. Build slot buffers (v3db_adapter.build_fixed_shape_slot_buffers)
2. Compute ADC distances (compute_v3db_slot_distances)
3. Attach auth labels per cid
4. Evaluate v_x via auth_reference.policy (plaintext oracle)
5. Compute hat_d_x via auth_reference.reference.compute_masked_distance
6. Sort (hat_d_x, cid) → ordered_auth_item_dis  [V3DB tie-break option]
7. Take first k cids → public top-k
8. Feed all fields into set_based_auth_ivf_pq_proof
```

Plaintext reference is the **oracle** for steps 4–6 during development.

---

## 12. Future root_auth extension

When `root_auth` is added:

1. Prover commits auth records in slot-aligned tree (parallel to content)
2. Witness adds Merkle siblings per slot
3. Public input adds `root_auth` to $$CP_\sigma$$
4. Circuit verifies auth leaf opens and `auth_cid == content cid`
5. Policy gadget inputs come from opened auth leaf, not free witness

This closes label-forgery gap identified in Phase 1B attack tests.

---

## Related documents

- [phase2_zk_integration_design.md](phase2_zk_integration_design.md)
- [phase2_test_plan.md](phase2_test_plan.md)
- [security_properties.md](security_properties.md)
