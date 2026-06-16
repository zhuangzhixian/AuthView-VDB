# Phase 3A: Slot-Aligned Auth Commitment — Design Freeze

**Status:** design document only (no circuit implementation in Phase 3A).  
**Branch:** `phase3-slot-aligned-design`  
**Related:** [phase2_set_based_auth_committed_log.md](phase2_set_based_auth_committed_log.md),
[phase2_scaling_eval_log.md](phase2_scaling_eval_log.md),
[phase2_auth_commitment_gadget_log.md](phase2_auth_commitment_gadget_log.md),
[formal_statement.md](formal_statement.md),
[security_properties.md](security_properties.md).

---

## 1. Motivation from Phase 2E

Phase 2C-2 introduced a **global** auth Merkle tree: every fixed-shape selected
slot carries a full opening to a single public `root_auth`. Phase 2D/2E measured
the additive cost on a **synthetic** IVF-PQ workload (400 vectors, dim=64,
repeat=1, pad/truncate slot buffers).

### 1.1 Observed scaling trends (indicative, not final)

| n_probe | slot_per_list | N_sel | auth_tree_depth | committed gates | c/b gate ratio |
|---------|---------------|-------|-----------------|-----------------|----------------|
| 2 | 32 | 64 | 6 | 11,062 | 1.103 |
| 2 | 64 | 128 | 7 | 12,706 | 1.215 |
| 4 | 32 | 128 | 7 | 20,110 | 1.126 |
| 4 | 64 | 256 | 8 | 23,583 | 1.260 |

**Trends (Phase 2E snapshot):**

- Committed-auth gates grow with **N_sel** and **auth_tree_depth** (global tree
  padded to `next_pow2(N_sel)`).
- Committed overhead above policy-only is ~620–3,225 gates on this small grid.
- Prove-time ratio committed/baseline is ~1.03–1.10×; gate growth outpaces prove
  time on the measured configurations.

These numbers characterize **implementation overhead of the current global-tree
layout** on synthetic data. They are **not** a production performance verdict:
workload size, hardware, prover tuning, and real cluster distributions were not
studied.

### 1.2 Root cause of opening cost

In Phase 2C-2, **each** of the `N_sel = n_probe × n_slot` fixed-shape slots
independently verifies:

$$
\text{MerkleVerify}(\text{authLeaf}_x, \text{path}_x, root_{auth}) = 1
$$

Each slot pays a Merkle path of length `auth_tree_depth = tree_depth(next_pow2(N_sel))`.
There is **no sharing** of path prefixes across slots in the same IVF list, even
though V3DB already organizes candidates as `[n_probe][n_slot]` aligned with
IVF inverted lists.

Phase 3A proposes a **slot-aligned** layout that mirrors the IVF list structure
so list-level Merkle work can be amortized across slots within a probed list.

---

## 2. Current global commitment layout (Phase 2C-2)

### 2.1 Leaf and verify semantics

Per slot index \(x\) (row-major over probed lists):

$$
\text{authLeaf}_x = H(\text{cid}_x, \text{tenant}_x, \text{project}_x, \text{level}_x, \text{state}_x, \text{epoch}_x)
$$

$$
\text{MerkleVerify}(\text{authLeaf}_x, \text{path}_x, root_{auth}) = 1
$$

Field order matches `auth_commitment_gadget` / `auth_reference/auth_commitment.py`.
`cid_x` must equal `itemss[i][j]` (content slot item id).

After Merkle binding, the **same** label targets feed `auth_policy_visibility_gadget`
and `auth_mask_distance_gadget` unchanged from the policy path.

### 2.2 Tree construction in Phase 2C-2

The prover builds one binary Merkle tree over **all selected slots** flattened in
row-major order, padded to the next power of two with dummy leaf
\(H(0,0,0,0,0,0)\). Invalid padding slots use deterministic dummy labels
\((\text{cid}, 0,0,0,0,0)\) with valid openings (fixed-shape witness).

Let:

$$
N_{sel} = n_{probe} \cdot n_{slot}
$$

$$
N_{auth} = next\_pow2(N_{sel})
$$

$$
depth_{global} = tree\_depth(N_{auth})
$$

### 2.3 Cost model (global, Phase 2C-2 as implemented)

**Per-slot naive opening cost** (hash steps along path):

$$
O(N_{sel} \cdot depth_{global}) = O(N_{sel} \cdot \log N_{auth})
$$

Because Phase 2C-2 builds the tree **only over the selected-slot leaf set**
(not the full corpus), effectively \(N_{auth} = next\_pow2(N_{sel})\) and:

$$
O(N_{sel} \cdot \log N_{sel})
$$

If instead the publisher committed auth labels for **all** lists and slots in the
full index (\(|S|\) slots), a literal global tree would imply
\(N_{auth} = next\_pow2(n_{list} \cdot n_{slot})\) and cost
\(O(N_{sel} \cdot \log(n_{list} \cdot n_{slot}))\) per query — worse as the
index grows. Phase 3A targets the publisher-scale layout where auth commitment
covers the full snapshot, while the **prover only opens probed lists**.

### 2.4 Witness shape (current)

| Witness | Shape |
|---------|-------|
| `root_auth` | public `u64` |
| `auth_path_directions` | `[n_probe][n_slot][depth_global]` |
| `auth_path_siblings` | `[n_probe][n_slot][depth_global]` |
| label fields | `[n_probe][n_slot]` |

---

## 3. Slot-aligned auth commitment layout

### 3.1 Two-level Merkle structure

Align auth commitment with V3DB IVF inverted-list layout:

**Level 1 — intra-list (slot) tree** for each IVF list \(\ell\):

$$
\text{authLeaf}_{\ell,j} = H(\text{cid}_{\ell,j}, \text{tenant}_{\ell,j}, \text{project}_{\ell,j}, \text{level}_{\ell,j}, \text{state}_{\ell,j}, \text{epoch}_{\ell,j})
$$

$$
root^{auth}_{\ell} = \text{MerkleRoot}(\{\text{authLeaf}_{\ell,j}\}_{j=1}^{n_{slot}})
$$

Leaves are padded to `next_pow2(n_slot)` within each list (same convention as
content Merkle clusters).

**Level 2 — top-level list tree** over all lists \(\ell = 1..n_{list}\):

$$
root_{auth} = \text{MerkleRoot}(\{root^{auth}_{\ell}\}_{\ell=1}^{n_{list}})
$$

Top level padded to `next_pow2(n_list)`.

### 3.2 Query-time opening (probed lists only)

Let \(L_q \subseteq \{1,\ldots,n_{list}\}\) be the probed list ids, \(|L_q| = n_{probe}\).

For each probed list \(\ell \in L_q\):

1. **Once per list:** verify \(root^{auth}_{\ell}\) opens to public `root_auth`:
   $$\text{MerkleVerify}(root^{auth}_{\ell}, \text{path}^{top}_{\ell}, root_{auth}) = 1$$

2. **Per slot** \(j \in \{1,\ldots,n_{slot}\}\) in that list:
   $$\text{MerkleVerify}(\text{authLeaf}_{\ell,j}, \text{path}^{intra}_{\ell,j}, root^{auth}_{\ell}) = 1$$

List identity \(\ell\) must match the content-side list id from IVF probe selection
(`cluster_idxes[i]` / `itemss` row).

### 3.3 Semantic equivalence

For every opened slot, the **auth label fields and leaf hash are identical** to
Phase 2C-2. Only the **Merkle anchoring path** changes (two shorter paths instead
of one long global path). Policy, mask, sorting, top-k, and content Merkle
semantics are unchanged.

---

## 4. Cost model

Define:

$$
N_{sel} = n_{probe} \cdot n_{slot}
$$

$$
depth_{list} = tree\_depth(next\_pow2(n_{list}))
$$

$$
depth_{slot} = tree\_depth(next\_pow2(n_{slot}))
$$

### 4.1 Global opening (Phase 2C-2 style, selected-slot tree)

$$
Cost_{global} \approx O(N_{sel} \cdot \log N_{sel})
$$

(as implemented) or \(O(N_{sel} \cdot \log N_{auth})\) for full-index auth tree
size \(N_{auth}\).

### 4.2 Slot-aligned opening with shared list-level verification

**Ideal** (one top-level opening per probed list, reused by all slots in that list):

$$
Cost_{aligned} \approx O(n_{probe} \cdot depth_{list} + N_{sel} \cdot depth_{slot})
$$

$$
= O(n_{probe} \cdot \log n_{list} + N_{sel} \cdot \log n_{slot})
$$

### 4.3 Comparison intuition

When \(n_{probe} \ll N_{sel}\) and \(depth_{slot} \ll depth_{global}\):

$$
depth_{global} \approx \log(n_{probe} \cdot n_{slot}), \quad
depth_{slot} \approx \log(n_{slot})
$$

Example: \(n_{probe}=4\), \(n_{slot}=64\), \(N_{sel}=256\):

| Layout | Dominant per-query Merkle depth per slot |
|--------|------------------------------------------|
| Global | \(\log_2 256 = 8\) |
| Slot-aligned | \(\log_2 64 = 6\) intra + amortized \(\log_2 n_{list}\) top |

Savings grow when \(N_{sel}\) crosses power-of-two boundaries (global depth +1)
while \(depth_{slot}\) stays fixed.

### 4.4 Risk: sharing not realized in-circuit

If Phase 3B verifies the **top-level list path independently per slot** (no
shared intermediate targets), cost reverts toward:

$$
O(N_{sel} \cdot (depth_{list} + depth_{slot}))
$$

which may **exceed** global cost. Phase 3B **must** implement shared list-root
verification (one top opening per probed list, connected to all intra-list
verifications for that list) to capture the intended savings.

---

## 5. Circuit integration plan

Additive path alongside existing `set_based_auth_ivf_pq_gadget_committed`
(global). Proposed name: **`set_based_auth_ivf_pq_gadget_committed_slot_aligned`**.

Per probed list index \(i\) with list id \(\ell_i\):

```
1. list_auth_root[i] = merkle_verify(intra_list_leaves, intra_paths for list i)
2. connect(merkle_verify(list_auth_root[i], top_path[i]), root_auth)
   -- OR: verify list_auth_root[i] via shared top path once, fan-out to slots
3. For each slot j:
     commitment_label = (itemss[i][j], tenant, project, level, state, epoch)
     authLeaf = H(commitment_label)
     merkle_verify(authLeaf, intra_path[i][j], list_auth_root[i])
     visibility = auth_policy_visibility_gadget(user, label, checkpoint_epoch)
     hat_d = auth_mask_distance_gadget(valid[i][j], visibility, d_x, d_max)
4. Unchanged: set_equal on ordered masked distances, top-k public cids, content Merkle
```

**Invariants (unchanged from Phase 2C-2):**

- Same label targets for Merkle leaf and policy gadget.
- `cid` from `itemss[i][j]`.
- Invalid slots: dummy label \((cid,0,0,0,0,0)\) + valid intra-list opening;
  masked to \(d_{max}\) via `valid × visibility`.
- No conditional skip of Merkle verification (fixed-shape proof).

---

## 6. Public inputs and witnesses

### 6.1 Public inputs

| Input | Notes |
|-------|-------|
| `root_auth` | Top-level auth Merkle root (unchanged type: `u64`) |
| `checkpoint_epoch` | Policy checkpoint (witness or public per existing policy path) |
| `query` | Existing public input |
| Top-k `cid`s | First `k` entries of sorted masked `(cid, hat_d)` witness |
| Content roots | Existing V3DB `root`, `codebooks_root` when `merkled=true` |

### 6.2 Witness — top level (per probed list)

| Field | Shape | Description |
|-------|-------|-------------|
| `list_id` | `[n_probe]` | IVF list index \(\ell_i\) (must match content probe) |
| `list_auth_root` | `[n_probe]` | \(root^{auth}_{\ell_i}\) (can be computed in-circuit or supplied) |
| `top_path_directions` | `[n_probe][depth_list]` | Opening of list root under `root_auth` |
| `top_path_siblings` | `[n_probe][depth_list]` | Sibling hashes |

**Sharing:** One top-level opening verification per probed list; result
`list_auth_root[i]` is a **single target** reused by all `n_slot` intra-list
verifications for row `i`.

### 6.3 Witness — intra-list (per slot)

| Field | Shape | Description |
|-------|-------|-------------|
| `object_tenant_ids` … `object_epochs` | `[n_probe][n_slot]` | Same as Phase 2C-2 |
| `intra_path_directions` | `[n_probe][n_slot][depth_slot]` | Slot leaf → list root |
| `intra_path_siblings` | `[n_probe][n_slot][depth_slot]` | Sibling hashes |

### 6.4 Invalid / padding slots

Same as Phase 2C-2: deterministic dummy labels, full intra-list paths, fixed shape.

---

## 7. Compatibility with V3DB fixed-shape IVF-PQ

V3DB proof path uses fixed-shape buffers:

```
vpqss   : [n_probe][n_slot][M]
valids  : [n_probe][n_slot]
itemss  : [n_probe][n_slot]
cluster_idxes : [n_probe]   → list id per probe row
```

Slot-aligned auth commitment maps **directly**:

- Probe row `i` ↔ IVF list \(\ell_i = cluster\_idxes[i]\)
- Slot column `j` ↔ fixed-shape slot index within that list
- Publisher builds `root^{auth}_{\ell}` for **every** list in the snapshot; prover
  only opens lists in \(L_q\)

This mirrors content Merkle (per-cluster subtree + IVF root) and avoids flattening
selected slots into an artificial global leaf order.

**Alignment requirement:** Intra-list leaf index `j` must match content slot index
and `itemss[i][j]` / `valids[i][j]` — same as today.

---

## 8. Security properties

Slot-aligned layout is an **optimization of auth opening topology**. It does **not**
change authorization-view retrieval semantics or weaken:

### 8.1 View Consistency

Each slot label \(\lambda_x\) is still bound by
\(\text{authLeaf}_x = H(\lambda_x.\text{fields})\) opened under `root_auth` (via
list root). Forged or stale labels remain detectable if opening fails or
`root_auth` ≠ checkpoint.

### 8.2 Authorization Soundness

Policy gadget still enforces \(v_x = P(\gamma_U, \lambda_x, \sigma)\) on the same
committed label fields. Merkle binding is a prerequisite, not a substitute.

### 8.3 Retrieval Soundness under Authorization

Masked distance ordering, candidate coverage, and top-k over full \(Cand(q,S,\theta)\)
are unchanged. Slot-aligned auth does not alter \(d_x\), \(\hat d_x\), or sort witness.

**Additional binding (Phase 3B):** Circuit must constrain `list_id[i]` to match
content probe selection so prover cannot attach auth subtrees from unrelated lists.

Properties **not** addressed by this layout (unchanged non-goals): dynamic
checkpoint registry, ACL compression, approximate-NN correctness beyond declared
PQ scoring.

---

## 9. Phase 3B implementation plan

| Step | Deliverable |
|------|-------------|
| **3B-1** | Plaintext `build_slot_aligned_auth_tree` in `auth_reference/auth_commitment.py`: per-list trees + top-level root; openings split into top / intra |
| **3B-2** | `build_slot_aligned_committed_witness` in `auth_reference/v3db_adapter.py` |
| **3B-3** | Rust `slot_aligned_auth_commitment_gadget.rs`: two-level verify, shared list root target |
| **3B-4** | `set_based_auth_ivf_pq_gadget_committed_slot_aligned` + proof wrapper (additive) |
| **3B-5** | PyO3 `py_set_based_auth_committed_slot_aligned_with_merkle` (additive API) |
| **3B-6** | Tests: gadget unit tests, ZK positive/negative, **global vs slot-aligned equivalence** (same labels → same top-k) |
| **3B-7** | Extend `bench_auth_paths.py` with optional slot-aligned path column; compare gates/prove_time vs global committed |
| **3B-8** | `docs/phase3_slot_aligned_implementation_log.md` |

**Freeze from Phase 3A:**

- Leaf hash field order unchanged.
- Two-level tree, power-of-two padding at each level.
- Shared top-level verification per probed list (mandatory for cost model).

---

## 10. Non-goals

- Dynamic checkpoint registry or in-circuit policy updates
- ACL-class compression or role hierarchy encoding
- HNSW / DiskANN or non-IVF-PQ indexes
- Changing V3DB baseline retrieval semantics (`py_set_based_with_merkle`)
- Replacing or removing global committed path (keep for regression / equivalence)
- Conditional Merkle skip for invalid slots
- Production auth label ingestion pipeline

---

## Appendix: notation

| Symbol | Meaning |
|--------|---------|
| \(n_{list}\) | IVF inverted list count |
| \(n_{probe}\) | Probed lists per query |
| \(n_{slot}\) | Fixed capacity per list (`slot_per_list`) |
| \(N_{sel}\) | \(n_{probe} \cdot n_{slot}\) |
| \(L_q\) | Set of probed list ids |
| \(root_{auth}\) | Public top-level auth Merkle root |
| \(root^{auth}_{\ell}\) | Auth root of list \(\ell\) |
