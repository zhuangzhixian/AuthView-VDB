# Phase 6B-2.10: Layout Model Failure Analysis

**Phase:** 6B-2.10  
**Status:** Phase 6B-2.9 figures are **exploratory and not paper-ready**.

---

## 1. Why Phase 6B-2.9 Figures Were Unacceptable

The Phase 6B-2.9 layout sweep produced SA/PA scatter and selectivity curves that looked like a **two-level switch**, not a design space:

- Only two PA clusters appeared (low vs baseline≈1.0).
- Merged-k points sat in the wrong quadrant (high SA **and** high PA).
- Oracle and ACL-class overlapped on both axes.
- Selectivity sensitivity lines were flat or degenerate.

These are **model validity failures**, not plotting issues.

---

## 2. Degeneration into Two Extremes

### Global / merged-k → always impure

- **Global:** one region over the full grid mixes visible and invisible objects → `impure_valid_ratio ≈ 1`, `plan_vs_masked_cost ≈ 1`.
- **Merged-k (6B-2.9):** merged **IVF lists**, not access signatures. IVF order is unrelated to visibility → merged regions remain impure → same as global.

### ACL-class / oracle → always pure

- **ACL-class (6B-2.9):** one object ↔ one role label. Each ACL region is homogeneous → always pure for any query.
- **Oracle:** visible/invisible split for current query → always pure, `impure = 0`.

Result: layout choice only toggled between “all impure” and “all pure” — no intermediate trade-off.

---

## 3. Why Merged-k Was a Dominated Design

Phase 6B-2.9 merged-k:

1. Used **wrong merge unit** (IVF lists) → no purity benefit.
2. Inflated **SA** via `C_merge_copy_block × n_lists` regardless of proof benefit.
3. Kept **PA ≈ global** (impure) while charging extra storage.

Thus merged-k was **dominated**: higher SA, no PA improvement — not a meaningful Veda-style copy/merge point.

---

## 4. Why Oracle and ACL-class Coincided

Both layouts achieved `impure_valid_ratio = 0` for every selectivity:

| Layout | Partition | Query-aware? |
|--------|-----------|--------------|
| ACL-class | one region per role label | No (but role ≡ visibility in 6B-2.9) |
| Oracle | visible / invisible | Yes |

Because each object had exactly one role, ACL-class ≡ oracle partition for single-user clearance queries. **Oracle SA** was defined as a small constant (`C_oracle_view_map`) instead of **per-role authorized-view replication**, so SA also collapsed toward ACL-class.

---

## 5. Repair Principles (Phase 6B-2.10)

1. **Access-signature workload:** object visibility = `query_role ∈ signature(x)`; signatures overlap across roles.
2. **ACL-signature layout:** partition by full signature bitset; pure per role query, but SA from signature table + region metadata.
3. **Merged-k:** merge **similar signatures** (sorted bitset), not IVF lists; larger k → fewer regions → higher impure ratio, lower SA.
4. **Oracle authorized-view:** SA = role-view membership replication + per-role view headers; PA ≈ 1 for current role query.
5. **SA and PA** tied to layout storage/proof units, not hand-tuned constants unrelated to structure.

---

## 6. Exit Criteria Before Re-plotting

Repaired model must pass `scripts/audit_proof_planning_layout_model.py` sanity table:

- Oracle highest SA, lowest PA.
- Global low SA, high PA.
- ACL-signature strictly between global and oracle on both axes.
- Merged-k monotone in k; not dominating oracle.
- All cases `planned_equals_masked` and `validation_passed`.

**No new paper figures until sanity passes.**

---

## Related

- [phase6_proof_planning_layout_audit.md](phase6_proof_planning_layout_audit.md)
- [phase6_access_aware_proof_planning.md](phase6_access_aware_proof_planning.md)
