# Phase 6B-2.10: Access-Aware Layout Model Audit (Repaired)

**Phase:** 6B-2.10  
**Prior phase:** 6B-2.9 figures are **exploratory only** — see [phase6_layout_model_failure_analysis.md](phase6_layout_model_failure_analysis.md).

---

## 1. Model Type

Access-signature layout evaluation uses a **plaintext work-unit + storage-unit model**.
Not measured ZK gates or bytes on disk.

---

## 2. Workload: Access Signatures

- Each object has signature `sig(x) ⊆ {0,…,R-1}` (role bitset).
- Query selects one role `r`; object visible iff `r ∈ sig(x)`.
- `effective_selectivity` = measured visible fraction for query role.
- Signatures generated with Zipf skew over `num_signatures` templates.

---

## 3. Physical Layouts (Repaired)

| Layout | Partition | Expected purity (per role query) |
|--------|-----------|----------------------------------|
| `global` | single region | impure |
| `acl_signature` | one region per signature | pure (signature-homogeneous) |
| `merged_k` | k signatures merged by sorted bitset | impure when k > 1 |
| `oracle_authorized_view` | visible / invisible for query | pure |

---

## 4. SA_commit (storage / commitment amplification)

Relative to content-only baseline (= 1.0):

| Layout | Formula (work-unit model) |
|--------|---------------------------|
| global | `1 + C_global_metadata` |
| acl_signature | `1 + C_sig × num_sig/N + C_region × num_regions/N` |
| merged_k | `1 + C_region × num_regions/N` |
| oracle | `1 + C_membership × (memberships/N − 1) + C_header × num_roles/N` |

Oracle SA reflects **per-role authorized-view replication** (objects appear in each role-view they belong to).

---

## 5. PA_plan (proof amplification)

$$
PA_{\mathrm{plan}} = C_{\mathrm{plan}} / C_{\mathrm{oracle\_layout}}
$$

Denominator = planned cost of **oracle authorized-view layout** for the same role query (PA = 1 for oracle by construction).

- Global: PA high (impure fallback).
- ACL-signature: PA > 1 (many region certificates vs oracle's two buckets).
- Merged-k: PA increases with k.

Primary figure y-axis remains `plan_vs_masked_cost`.

---

## 6. Sanity Gate (required before re-plotting)

Run `scripts/audit_proof_planning_layout_model.py` on repaired summary.
All 10 checks must pass before generating new paper figures.

---

## 7. Claim Boundaries

**Can claim:**

- Layout-aware structure creates SA/PA trade-off under cost model.
- Oracle authorized-view replication increases SA but minimizes PA for role query.
- Merged-k interpolates between ACL-signature and global as k increases.

**Cannot claim:**

- ZK gate reduction matches PA_plan ratios.
- Repaired SA units equal production storage bytes.

---

## Related

- [phase6_layout_model_failure_analysis.md](phase6_layout_model_failure_analysis.md)
- [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md)
