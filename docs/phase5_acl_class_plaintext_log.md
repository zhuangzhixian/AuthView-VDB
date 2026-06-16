# Phase 5A: ACL-Class Compression Plaintext Reference Log

**Status:** plaintext oracle + cost model only (no ZK, no Rust changes)  
**Branch target:** `phase5-acl-class-plaintext`

Related: [next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md),
[attack_matrix_eval.md](attack_matrix_eval.md).

---

## 1. Motivation

Per-slot auth label openings repeat the same dynamic ACL state when many chunks
share document-, project-, or class-level permissions:

$$
N_{acl} = |\{\mathrm{aclClass}(x) : x \in Cand\}| \ll N_{sel}
$$

ACL-class compression evaluates policy **once per unique class** and lets each
candidate slot inherit visibility via a static **object-to-class binding**.

This phase delivers the plaintext oracle and cost model required for Phase 5B ZK
circuit integration and Phase 5C `N_acl/N_sel` evaluation.

---

## 2. Data model

Implemented in `auth_reference/acl_class.py`.

| Type | Fields | Role |
|------|--------|------|
| `ACLClassLabel` | `acl_class_id`, `tenant_id`, `project_id`, `required_clearance`, `state`, `epoch` | Dynamic ACL state at checkpoint σ |
| `ObjectClassBinding` | `cid`, `acl_class_id`, `epoch` | Static binding from content object to class |
| `ACLClassView` | selected candidates, bindings, class labels, per-class/cid visibility | Intermediate compressed view |
| `ACLCompressedReferenceResult` | top-k, scored slots, view, cost counters | Oracle output |

**Separation:** class policy fields are **not** duplicated on each object. Objects
inherit authorization semantics through `cid → acl_class_id`.

---

## 3. Plaintext semantics

For each candidate slot `x ∈ Cand`:

1. Look up binding `(cid, acl_class_id, epoch)`.
2. Load class label `Λ_c` for `acl_class_id`.
3. Compute class visibility once: `v_c = P(γ_U, Λ_c, σ)`.
4. Slot visibility: `v_x = v_c` (inherited).
5. Masked distance: same as object-level reference (`hat_d`, `tilde_d` with `d_max`).

Authorized top-k:

$$
R = \mathrm{TopK}_k(\{(x, \tilde d_x) \mid x \in Cand\})
$$

**Equivalence:** when object-level `AuthLabel` fields are expanded from
`(binding, class_label)`, ACL-class reference equals `run_authorized_reference`.

Key functions:

- `evaluate_acl_class_visibility`
- `build_acl_class_view`
- `authorized_topk_acl_compressed`
- `compare_object_level_vs_acl_class_reference`

---

## 4. Plaintext validation (binding layer)

Before scoring:

- `verify_object_class_bindings` — reject forged `cid → acl_class_id` mappings
  (analogue of label commitment forgery at binding layer).

Future ZK will open binding leaves under a separate commitment tree.

---

## 5. Future commitment layout (Phase 5B)

Not implemented in 5A; documented for circuit design.

### ACL class leaf

```
aclClassLeaf = H(acl_class_id, tenant_id, project_id, required_clearance, state, epoch)
```

### Object-to-class binding leaf

```
objClassLeaf = H(cid, acl_class_id, epoch)
```

### ZK proof obligations (planned)

| Step | Obligation |
|------|------------|
| Per unique class | One Merkle opening of `aclClassLeaf` under `root_auth` |
| Per candidate slot | One binding opening; prove `class_id` matches a selected class |
| Policy | Evaluate `P` once per opened class; slot inherits `v_c` |
| Soundness | Same `acl_class_id` cannot open two different `Λ_c`; slot cannot bind to wrong class |

Compatible with slot-aligned layout: intra-list slot leaf may carry `acl_class_id`;
class state opened once per class per query.

---

## 6. Cost model

Relative unit weights (plaintext counters):

| Component | Object-level | ACL-class |
|-----------|--------------|-----------|
| Policy evals | `N_sel` | `N_acl` |
| Auth openings | `N_sel` label opens | `N_acl` class opens + `N_sel` binding opens |

Counters in `ACLCompressionCost`:

- `N_sel`, `N_acl`, `N_vis`
- `acl_ratio = N_acl / N_sel`
- `visible_ratio = N_vis / N_sel`
- `estimated_policy_eval_saved = N_sel - N_acl`
- `estimated_cost_object_level`, `estimated_cost_acl_class`

**Expected shape:** savings when `N_acl << N_sel`; degenerate case `N_acl = N_sel`
has higher ACL-path opening overhead but **identical semantics**.

---

## 7. Tests

File: `tests/test_acl_class_reference.py`

| # | Test | Property |
|---|------|----------|
| 1 | ACL-class visibility evaluation | Policy parity |
| 2 | Equals object-level reference | Equivalence |
| 3 | Invisible class masks all objects | Masking |
| 4 | Shared class → policy counted once | Deduplication |
| 5 | Mixed visible/invisible classes | Top-k correctness |
| 6 | Forged binding detected | Binding integrity |
| 7 | Stale class epoch invisible | Checkpoint binding |
| 8 | Cost model sanity | `N_acl ≤ N_sel`, savings when compressed |
| 9 | Degenerate `N_acl = N_sel` | Semantics without savings |
| 10 | All same class (`N_acl = 1`) | Maximum savings |

Run:

```bash
PYTHONPATH=. pytest tests/test_acl_class_reference.py -v
```

---

## 8. CSV artifact

`artifacts/acl_class_plaintext_cases.csv` — equivalence + cost snapshots.

Generate:

```bash
PYTHONPATH=. python scripts/write_acl_class_plaintext_cases.py
```

---

## 9. Limitations (Phase 5A)

- No Merkle tree or ZK proof for ACL class / binding leaves.
- Tenant/project encoding uses fixed id maps (`TENANT_ID_TO_NAME`, etc.).
- Cost model is relative (unit weights), not measured gate counts.
- Class deduplication is plaintext-only; circuit witness dedup is Phase 5B.

---

## 10. Next: Phase 5B ZK integration

Recommended order:

1. **`acl_class_commitment.py`** — Merkle trees for class leaves + binding leaves
   (match documented leaf formats).
2. **Rust gadgets** — `acl_class_merkle_verify`, binding verify, class-once policy
   wiring in new additive path `auth_committed_acl_class` (do not modify existing
   `auth_committed` regression path).
3. **PyO3 + witness builder** — extend `v3db_adapter` with ACL-class witness split.
4. **Equivalence tests** — `test_auth_zk_acl_class.py`: ACL-class ZK top-k ==
   committed per-slot on shared fixtures.
5. **Negative tests** — wrong binding, forged class state (extends attack matrix A13).
6. **Phase 5C** — extend `bench_auth_paths.py` with ACL-class path; sweep
   `N_acl/N_sel` for paper Figure 4.
