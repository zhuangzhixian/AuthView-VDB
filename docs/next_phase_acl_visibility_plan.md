# Next Phase Plan: ACL-Class Compression & Visibility-Gated Scoring

**Phase:** 4B (planning only — no implementation in this phase)  
**Prerequisites:** Attack matrix completion (recommended first)  
**Slot-aligned commitment:** appendix / layout optimization only—not a Phase 5–6 dependency

---

## Recommended execution order

```
1. Attack matrix completion     ← security story + paper §5.1
2. Phase 5: ACL-class compression   ← N_acl/N_sel figure
3. Phase 6: Visibility-gated scoring ← N_vis/N_sel figure
4. Paper table/figure generation    ← existing + new CSV
```

Rationale: attacks define **what must not break** before optimizations change the circuit. ACL compression is largely independent of gating, but both need new oracles—sequential reduces design thrash.

---

# Phase 5: ACL-Class Compression

## 5.1 Problem

Today each selected slot opens a **full auth label** under `root_auth` (cid-keyed leaf or slot-aligned intra path). Enterprise corpora often have:

$$
N_{acl} = |\{\mathrm{aclClass}(x) : x \in Cand\}| \ll N_{sel}
$$

Many chunks share document-, project-, or ACL-class-level permissions. Proving per-slot labels repeats the same dynamic state opening.

**Goal:** Prove authorized retrieval while opening **one dynamic ACL record per class** used in \(Cand\), plus a binding proof from each candidate to its class.

## 5.2 Data model

| Entity | Fields | Commitment |
|--------|--------|------------|
| **Static candidate binding** | `(cid, aclClass_id, static fields…)` | Under content or auth-static tree |
| **Dynamic ACL state** | `(tenant, project, level, state, epoch, …)` per class | Under `root_auth` keyed by `aclClass_id` |
| **User context** | \(\gamma_U\) | Public input |

Candidate record:

$$
(x, \lambda_x) \Rightarrow \mathrm{aclClass}(x) = c \Rightarrow \Lambda_c = \text{dynamic ACL state at } \sigma
$$

Policy:

$$
v_x = P(\gamma_U, \Lambda_{\mathrm{aclClass}(x)}, \sigma)
$$

## 5.3 Commitment layout (proposed)

Two-level or parallel trees:

```
root_auth
 ├── aclClass_0 → H(dynamic_state_0)
 ├── aclClass_1 → H(dynamic_state_1)
 └── …
```

Optional static binding tree (per slot or per cid):

```
authLeaf_slot = H(cid, aclClass_id, …static…)
```

**Relation to slot-aligned:** slot-aligned optimizes **where** slot leaves live; ACL-class compresses **what** is opened dynamically. Compatible: intra-list slot leaf binds `aclClass_id`; class state opened once per class per query.

## 5.4 Proof semantics

For each slot \(x \in Cand\):

1. Open content (unchanged V3DB).
2. Open **binding** witness: \(\mathrm{aclClass}(x)\) consistent with committed slot/cid record.
3. For each **distinct** class \(c\) appearing in witness, open \(\Lambda_c\) under `root_auth` (multiset of classes must cover all slots).
4. Compute \(v_x = P(\gamma_U, \Lambda_{\mathrm{aclClass}(x)}, \sigma)\).
5. Mask distance, set equality, top-k (unchanged).

**Soundness obligation:** prover cannot assign two different \(\Lambda_c\) to the same `aclClass_id`, or bind slot to wrong class (candidate↔class forgery attack).

## 5.5 Expected circuit changes

| Area | Change |
|------|--------|
| New gadget | `acl_class_binding_gadget`, `acl_class_merkle_verify` |
| Policy input | Per-slot `aclClass_id` target + shared class state targets |
| Witness dedup | Circuit or prover opens each class once; slots reference class index |
| `set_based_auth.rs` | New path `auth_committed_acl_class` (additive) |
| PyO3 | New API + witness builder |

**Do not modify** existing `auth_committed` path (regression baseline).

## 5.6 Plaintext oracle

Extend `auth_reference/`:

- `build_acl_class_labels(candidates) → Map[class_id, AuthLabel]`
- `build_acl_class_auth_tree(n_classes)`
- `authorized_topk_with_acl_classes(...)` — must match per-slot label oracle when classes map 1:1 to labels

## 5.7 Tests

| Test | Type |
|------|------|
| Class binding correct → proof ok | Positive |
| Wrong class binding for slot | Negative ZK |
| Two slots same class → one class opening | Witness + cost |
| Forged class dynamic state | Negative |
| Equivalence: ACL-class oracle == per-slot label oracle | Regression |

Files: `tests/test_auth_acl_class_commitment.py`, `tests/test_auth_zk_acl_class.py`

## 5.8 Evaluation metrics

| Metric | Source |
|--------|--------|
| `median_gates` vs per-slot committed | `bench_auth_paths.py` new path |
| Auth Merkle hash steps | Plaintext counter |
| `N_acl`, `N_sel`, ratio | Workload generator param |

## 5.9 N_acl / N_sel figure design

**Figure 4 (proposed):** “Proof cost vs ACL compression ratio”

| Axis | Definition |
|------|------------|
| **X** | \(N_{acl}/N_{sel}\) from 1.0 (no compression) down to ~0.05 |
| **Y** | median gates or auth-component gates |
| **Series** | per-slot committed (flat), ACL-class committed |
| **Workloads** | Fix \(N_{sel}=256\); sweep ACL clustering (e.g. 256, 64, 16, 8, 4 classes) |

**Generator idea:** assign slots to `aclClass_id = hash(doc_id) mod C` for varying `C`.

**Expected shape:** monotone decrease in auth-component cost as \(N_{acl}/N_{sel}\) drops; full circuit may plateau due to fixed PQ/set logic.

---

# Phase 6: Visibility-Gated Scoring

## 6.1 Problem

When \(N_{vis} \ll N_{sel}\) (most candidates invisible), evaluating \(P\) on every slot is expensive. **Visibility-gated scoring** skips or batches policy work for slots proven invisible **without changing** authorized top-k result.

**Critical constraint:** gating is a **proof-preserving optimization** only if the partition of \(Cand\) into visible/invisible is correct and complete.

## 6.2 Data model

Partition each probed list or global \(Cand\):

$$
Cand = Cand_{vis} \cup Cand_{inv}, \quad Cand_{vis} \cap Cand_{inv} = \emptyset
$$

Optional **pure block** flag (future): entire IVF list visible for \(U\).

For Phase 6 minimum:

- Per-slot \(v_x\) still computable from committed ACL/label
- **Early demotion:** if slot provably in \(Cand_{inv}\), use \(\hat d_x = d_{max}\) without full policy chain **only if** circuit proves \(v_x=0\) implies same mask

Safer first version: **batch visibility**—compute class-level visibility once per ACL class (synergy with Phase 5).

## 6.3 Proof semantics

**Strong semantics (must preserve):**

$$
R = \mathrm{TopK}_k(\{(x, \hat d_x) \mid x \in Cand\})
$$

**Gating variant:**

1. Prove multiset partition of slots into visible/invisible sets matches committed labels.
2. For invisible set: constrain \(\hat d_x = d_{max}\) (or skip policy after zero visibility bit).
3. For visible set: full policy + distance mask.
4. Set equality over **combined** scored multiset unchanged.

**Forbidden:** skipping slots without coverage proof; gating on server-side pre-filter outside \(Cand\).

## 6.4 Expected circuit changes

| Area | Change |
|------|--------|
| Visibility partition gadget | Prove each slot assigned vis/inv consistently with \(P\) |
| Conditional policy | Evaluate policy only when `gate_bit=1` OR prove class visibility |
| Risk | Accidentally allowing invisible slot with low \(\hat d\) |

Mitigation: always compute \(v_x\) from committed state; “gating” = **deduplicate class-level policy** (Phase 5) before slot-level bypass.

## 6.5 Risks

| Risk | Mitigation |
|------|------------|
| Soundness bug: skip visible slot | Equivalence tests vs ungated path on all workloads |
| Visibility manipulation | Existing attacks + new “bypass gate” attack |
| Circuit complexity from branches | Prefer class-level dedup over per-slot branches |

## 6.6 Plaintext oracle

- `run_authorized_reference_gated(...)` in `auth_reference/reference.py`
- Must match `run_authorized_reference` on all test fixtures
- `run_post_filter_baseline` remains contrast baseline

## 6.7 Tests

| Test | Type |
|------|------|
| Gated == ungated top-k (all fixtures) | Equivalence |
| Partial-visible distribution sweep | Oracle |
| Force gate bypass → ZK fail | Negative |
| Combined with ACL-class | Integration |

## 6.8 Evaluation metrics

| Metric | Definition |
|--------|------------|
| Visible ratio | \(N_{vis}/N_{sel}\) (valid ∧ \(v_x=1\)) |
| Policy gadget count | Estimated from circuit metrics |
| median_gates vs full policy path | Ablation |

## 6.9 N_vis / N_sel figure design

**Figure 5 (proposed):** “Cost vs visible candidate ratio”

| Axis | Definition |
|------|------------|
| **X** | \(N_{vis}/N_{sel}\) or `visible_ratio` (0.1 … 1.0) |
| **Y** | median gates or prove_time |
| **Series** | `auth_committed` (full), `auth_gated` (Phase 6), optional baseline |
| **Fixed** | \(N_{sel}=256\), \(n_{probe}=4\), slot=64 |

**Generator:** extend `build_partial_visible_labels` with tunable invisible fraction.

**Expected shape:** gated path approaches full-path cost as ratio→1; larger savings as ratio→0.

---

# Phase 4B–7: Attack matrix completion (before Phase 5)

| # | Attack | Plaintext | ZK committed | V3DB baseline |
|---|--------|-----------|--------------|---------------|
| 1 | Post-filter vs authorized gap | ✅ | N/A | N/A |
| 2 | Skipped candidate | ✅ | ❌ needed | fails by design (different threat) |
| 3 | Forged tenant/label | ✅ | ✅ | no auth |
| 4 | Wrong Merkle path | ✅ | ✅ | N/A |
| 5 | Visibility manipulation | ✅ | ❌ needed | no auth |
| 6 | Checkpoint mismatch | ✅ | partial | no auth |
| 7 | Cross-list auth graft | ✅ | ✅ slot path | N/A |
| 8 | ACL-class mismatch | — | Phase 5 | — |

Deliverable: `docs/attack_matrix_eval.md` + optional CSV (future phase—not 4B).

---

# Phase 7: Paper table/figure generation (after 5–6)

| Asset | Source |
|-------|--------|
| Table: path overhead | `auth_zk_paper_ready_summary.csv` |
| Figure: scaling | same |
| Figure: N_acl/N_sel | new benchmark grid |
| Figure: N_vis/N_sel | new benchmark grid |
| Table: attack matrix | tests + eval doc |

---

## Module map (future, not implemented)

```
auth_reference/
  acl_class_commitment.py      # Phase 5 plaintext
  visibility_gated_reference.py # Phase 6 plaintext

src/merkle_ver/
  acl_class_gadget.rs          # Phase 5
  visibility_gate_gadget.rs    # Phase 6 (or merge with acl)

scripts/
  bench_auth_paths.py          # extend paths
  bench_acl_vis_sweep.py       # optional dedicated sweeps
```

---

## Success criteria for Phase 5 + 6

- [ ] New paths prove/verify on synthetic workloads
- [ ] Equivalence tests vs `auth_committed` on shared fixtures
- [ ] N_acl/N_sel and N_vis/N_sel curves with ≥5 points each
- [ ] No regression in existing 56+ tests
- [ ] Documented in paper §6 as **algorithm contributions**, slot-aligned in appendix only
