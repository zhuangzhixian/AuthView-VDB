# Remaining Work Gap Analysis

**Phase:** 4B  
**Purpose:** Honest inventory of what exists, what blocks a VLDB/SIGMOD/ICDE submission, and what should come next.

Status labels: **已完成** / **部分完成** / **未完成**

---

## A. Must complete (paper blockers)

### A1. V3DB reproduction

| Field | Assessment |
|-------|------------|
| **Status** | **已完成** |
| **Evidence** | `py_set_based_with_merkle`; `artifacts/v3db_reproduce_metrics.csv`; `docs/v3db_reproduction_log.md`; `tests/test_auth_zk_all_visible.py` (baseline equivalence) |
| **Gap** | Not positioned as contribution—only baseline infrastructure |
| **Blocks paper?** | No (satisfied as reference point) |

---

### A2. Plaintext authorized reference

| Field | Assessment |
|-------|------------|
| **Status** | **已完成** |
| **Evidence** | `auth_reference/reference.py`, `post_filter.py`, `attacks.py`; `tests/test_auth_reference.py` (8 tests); post-filter vs authorized contrast |
| **Gap** | No large-scale semantic eval dataset; attacks are synthetic micro-fixtures |
| **Blocks paper?** | No for kernel; **yes for top-tier eval narrative** without richer scenarios |

---

### A3. ZK auth-static baseline (committed authorization + policy + mask)

| Field | Assessment |
|-------|------------|
| **Status** | **部分完成** |
| **Evidence** | `auth_committed` path; `py_set_based_auth_committed_with_merkle`; gadget tests; `tests/test_auth_zk_committed.py` (4 tests); paper-ready CSV |
| **Gap** | “Static” only—no ACL-class layer; benchmark uses probe-local flat auth tree; no index-wide `root_auth` at corpus scale; formal_statement.md status banners still say “planned” |
| **Blocks paper?** | **Partially**—core path exists, but top-tier paper needs stronger eval + attack matrix on ZK API |

**Interpretation:** Current `auth_committed` **is** the auth-static baseline kernel. Missing pieces are experimental breadth and documentation sync, not the core circuit.

---

### A4. cid-keyed vs slot-aligned auth commitment

| Field | Assessment |
|-------|------------|
| **Status** | **部分完成** |
| **Evidence** | Global flat tree (Phase 2C); slot-aligned two-level tree (Phase 3B); `tests/test_auth_slot_aligned_commitment.py`; `tests/test_auth_zk_slot_aligned.py`; list_id binding |
| **Gap** | Document-level / cid-keyed **dynamic** tree at corpus scale not built; slot-aligned is layout opt only; no paper figure comparing opening counts at production \(N_{list}\) |
| **Blocks paper?** | No as **primary** contribution; **optional** appendix if kept subordinate |

---

### A5. Attack experiments

| Field | Assessment |
|-------|------------|
| **Status** | **部分完成** |
| **Evidence** | **Plaintext:** skipped candidate, forged label, visibility manipulation, post-filter gap, checkpoint mismatch (`tests/test_auth_reference.py`). **ZK:** forged tenant, wrong auth path, list_id graft (`test_auth_zk_committed.py`, `test_auth_zk_slot_aligned.py`) |
| **Gap** | No unified **attack matrix** document/table; several attacks plaintext-only (skipped candidate, visibility manipulation, post-filter) **not** exercised via ZK API; no systematic “attack detected / undetected” eval CSV; no V3DB baseline shown **failing** auth attacks by design |
| **Blocks paper?** | **Yes** for security/systems venues—reviewers expect explicit attack eval, not only unit tests |

**Minimum to unblock:**

1. Attack matrix (≥8 scenarios) × {plaintext oracle, ZK committed path, V3DB baseline N/A}.
2. At least one **quantitative** table: attack name → expected fail → observed fail.
3. Post-filter vs authorized top-k **workload** with measurable result difference (not only toy 3-candidate case).

---

### A6. Basic paper framework

| Field | Assessment |
|-------|------------|
| **Status** | **部分完成** |
| **Evidence** | `docs/paper_outline_draft.md`, `docs/evaluation_plan_paper_tables.md`, `docs/system_milestone_summary.md`, formal/security specs |
| **Gap** | No full draft (intro, related work, eval section prose); positioning still mixed in older docs (`research_scope.md` says “extends V3DB”); no attack section; no ACL/visibility figures |
| **Blocks paper?** | **Yes** for submission; planning docs ≠ paper |

---

## A summary table

| Item | Status | Blocks top-tier? |
|------|--------|------------------|
| V3DB reproduction | 已完成 | No |
| Plaintext reference | 已完成 | No (alone) |
| ZK auth-static baseline | 部分完成 | Partially |
| cid vs slot-aligned | 部分完成 | No (primary) |
| Attack experiments | 部分完成 | **Yes** |
| Paper framework | 部分完成 | **Yes** |

---

## B. Strongly recommended (top-tier eval differentiation)

### B1. ACL-class compression

| Field | Detail |
|-------|--------|
| **Why VLDB/SIGMOD/ICDE care** | Enterprise KBs: many chunks share document/project/ACL-class permissions → \(N_{acl} \ll N_{sel}\). Shows **algorithmic** cost reduction tied to real permission structure, not just Merkle layout tweak. |
| **Technical core** | Map candidate → `aclClass`; commit dynamic state per class; one opening per class per query; prove binding candidate↔class in-circuit |
| **Implementation difficulty** | **High** — new commitment layout, witness, gadget, oracle, tests |
| **Expected experiment benefit** | **N_acl/N_sel** curve: gates/openings drop when ACL classes ≪ candidates |
| **Main contribution?** | **Yes** (algorithm + eval)—co-primary with authorization-view problem after kernel is stable |

---

### B2. Visibility-gated scoring

| Field | Detail |
|-------|--------|
| **Why important** | When most candidates invisible, per-slot policy is wasteful; gated scoring proves equivalence to full scan **only if** partition is correct—classic systems optimization with proof obligation |
| **Technical core** | Partition \(Cand\) into invisible / visible (or pure/impure blocks); skip or batch policy; prove no visible candidate omitted from ranking branch |
| **Implementation difficulty** | **High** — soundness risk if partition wrong; circuit branching or multiset split |
| **Expected benefit** | **N_vis/N_sel** curve: cost vs visible ratio |
| **Main contribution?** | **Yes** as **optimization with correctness proof**—not standalone without auth-view baseline |

---

### B3. N_vis / N_sel figure

| Field | Detail |
|-------|--------|
| **Design** | X: visible ratio or \(N_{vis}/N_{sel}\); Y: median gates / prove time; series: full policy vs gated vs baseline |
| **Data need** | Benchmark grid sweeping label distributions (partial-visible generators exist; need systematic sweep + CSV) |
| **Main contribution?** | **Eval figure** supporting B2—not a standalone contribution |

---

### B4. N_acl / N_sel figure

| Field | Detail |
|-------|--------|
| **Design** | X: \(N_{acl}/N_{sel}\); Y: auth opening cost or gates; compare per-cid vs ACL-class |
| **Data need** | Synthetic datasets with controlled ACL clustering |
| **Main contribution?** | **Eval figure** supporting B1 |

---

## B summary

| Item | Main contribution? | Priority |
|------|-------------------|----------|
| ACL-class compression | Yes (algorithm) | P1 after attacks |
| Visibility-gated scoring | Yes (optimization + proof) | P1 after ACL or parallel |
| N_vis/N_sel figure | Eval (required for B2) | P1 |
| N_acl/N_sel figure | Eval (required for B1) | P1 |

**Slot-aligned commitment:** **not** in this table as main contribution—appendix only (2–5% in current `auth_zk_paper_ready_summary.csv`).

---

## C. Can defer (discussion / future work)

| Topic | Why defer | Future work wording |
|-------|-----------|---------------------|
| **Pure / impure block proof** | Depends on ACL + visibility partition first | “Block-level visibility certificates when entire IVF block is pure for \(U\)” |
| **SA / PA curves** | Needs block model + storage model not in repo | “Storage–proof amplification trade-offs (access-aware indexing literature)” |
| **Access-structure-aligned commitment** | Generalizes ACL-class; larger design space | “Commit auth state by tenant/project/security domain tree” |
| **Private user context** | Different crypto stack (credentials, ZK identity) | “Hide \(\gamma_U\) from verifier while proving policy satisfaction” |
| **Dynamic freshness / transparency log** | Out of prototype scope per formal_statement §15 | “Checkpoint freshness and revocation propagation proofs” |
| **Index-wide global auth tree** | Engineering at scale; current eval uses probe-local tree | “Full corpus auth root vs probe-local commitment in production” |
| **Real datasets (SIFT, enterprise snapshot)** | Phase 3D synthetic only | “Evaluation on public ANN benchmarks with synthetic ACL overlay” |

---

## D. Current proof kernel vs paper endpoint

```
Today                          Target paper
──────                         ────────────
Proof kernel                   Problem + security + eval story
5 paths, 56 tests              Attack matrix + 2 core figures
Synthetic 400×64               Multiple scales + ACL/vis sweeps
V3DB as implementation substrate   V3DB as related work only
```

See [top_tier_readiness_plan.md](top_tier_readiness_plan.md) for venue-specific bars.
