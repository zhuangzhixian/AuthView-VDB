# AuthView-VDB System Milestone Summary

**Phase:** 4A — system milestone and paper planning  
**Branch:** `phase4-milestone-summary`  
**Status:** Phases 0–3D complete; prototype with five ZK proof paths and paper-ready evaluation CSV.

This document summarizes what the repository implements today. For formal definitions see [formal_statement.md](formal_statement.md) and [security_properties.md](security_properties.md).

---

## 1. Current system stage

AuthView-VDB is a **research prototype** built on the imported V3DB IVF-PQ set-based Plonky2 proof stack. The system provides:

1. **V3DB baseline reproduction** — fixed-shape IVF-PQ indexing, Merkle content commitment, set-based top-k proof (`py_set_based_with_merkle`).
2. **Plaintext authorization reference** — oracle for authorized masked top-k over the full candidate set (not post-filter).
3. **Authorization-aware ZK extensions** — policy visibility, distance masking, committed auth labels, and an optional slot-aligned commitment layout.
4. **Evaluation harness** — repeatable CSV benchmarks and median summary for paper tables.

The prototype targets **retrieval soundness under authorization**: the verifier checks that public top-k cids equal top-k over masked distances on the **complete** declared candidate set, with visibility derived from committed labels at checkpoint σ.

---

## 2. Completed module inventory

### Phase 0 — Repository bootstrap

| Module | Location | Role |
|--------|----------|------|
| V3DB IVF-PQ core | `ivf_pq/`, `src/merkle_ver/set_based*.rs` | Baseline ANN + Merkle + set-based proof |
| Build / PyO3 | `Cargo.toml`, `maturin`, `src/lib.rs` | Rust `cdylib` exposed to Python |

### Phase 1 — Plaintext reference & adapter

| Module | Location | Role |
|--------|----------|------|
| Auth reference oracle | `auth_reference/reference.py`, `policy.py`, `records.py` | Authorized top-k semantics |
| Attack cases | `auth_reference/attacks.py`, `tests/test_auth_reference.py` | Coverage / forgery / post-filter gaps |
| V3DB adapter | `auth_reference/v3db_adapter.py`, `tests/test_v3db_adapter.py` | Slot buffers → candidates, labels, ZK witness helpers |

### Phase 2 — Authorization gadgets & proof paths

| Module | Location | Role |
|--------|----------|------|
| Auth mask gadget | `src/merkle_ver/auth_mask_gadget.rs` | \(\hat d_x = v_x d_x + (1-v_x) d_{max}\) (with valid bit) |
| Auth policy gadget | `src/merkle_ver/auth_policy_gadget.rs` | \(v_x = P(\gamma_U, \lambda_x, \sigma)\) |
| Auth commitment gadget | `src/merkle_ver/auth_commitment_gadget.rs` | Auth label leaf hash + Merkle verify |
| Set-based auth paths | `src/merkle_ver/set_based_auth.rs`, `set_based_auth_proof.rs` | All-visible, policy, global committed |
| Plaintext commitment | `auth_reference/auth_commitment.py` | Global auth Merkle tree builder |
| PyO3 APIs | `src/lib.rs` | `py_set_based_auth_*` family |

### Phase 3 — Slot-aligned commitment & evaluation

| Module | Location | Role |
|--------|----------|------|
| Slot-aligned plaintext tree | `auth_reference/slot_aligned_auth_commitment.py` | Two-level auth Merkle layout |
| Slot-aligned gadget | `src/merkle_ver/slot_aligned_auth_commitment_gadget.rs` | Intra + top verify, list_id binding |
| Slot-aligned proof path | `set_based_auth_ivf_pq_gadget_committed_slot_aligned` | Additive ZK path |
| Benchmarks | `scripts/bench_auth_paths.py`, `scripts/summarize_auth_metrics.py` | Overhead, scaling, paper-ready CSV |

---

## 3. Proof paths

All paths share V3DB **content** Merkle commitment (`standalone_commitment_gadget`), fixed-shape candidate enumeration, ADC/PQ distance computation, set equality + sorted top-k public outputs.

| Path | PyO3 entry | Auth Merkle | Policy \(P\) | Mask \(\hat d\) |
|------|------------|-------------|--------------|----------------|
| `baseline` | `py_set_based_with_merkle` | — | — (implicit all visible) | valid bit only |
| `auth_all_visible` | `py_set_based_auth_all_visible_with_merkle` | — | fixed \(v_x \equiv 1\) | auth mask gadget |
| `auth_policy` | `py_set_based_auth_with_merkle` | — | per-slot `auth_policy_visibility_gadget` | auth mask gadget |
| `auth_committed` | `py_set_based_auth_committed_with_merkle` | global flat tree → `root_auth` | same labels as commitment | auth mask gadget |
| `auth_slot_aligned` | `py_set_based_auth_slot_aligned_with_merkle` | two-level tree → `root_auth` | same labels as commitment | auth mask gadget |

### 3.1 `baseline`

**Security semantics (inherits V3DB):**

- **Snapshot binding:** probed slots open under content Merkle root.
- **Candidate coverage:** all \(N_{sel} = n_{probe} \times n\) slots scored and included in set-based top-k witness.
- **No authorization:** ranking uses PQ distance with valid-bit demotion only.

**Use:** regression baseline for content proof cost and top-k correctness.

### 3.2 `auth_all_visible`

**Security semantics:**

- Same as baseline for content binding and coverage.
- **Authorized distance soundness** with \(v_x \equiv 1\): exercises auth mask wiring without policy cost.
- Does **not** bind auth labels to `root_auth`.

**Use:** isolate mask-gadget overhead vs baseline.

### 3.3 `auth_policy`

**Security semantics:**

- **View consistency:** \(v_x = P(\gamma_U, \lambda_x, \sigma)\) computed in-circuit per slot.
- **Authorized distance soundness:** \(\hat d_x\) from visibility and valid bit.
- **Candidate coverage** unchanged.
- Labels are **witness sidecar only** — not Merkle-bound (forger could supply arbitrary label fields if verifier did not also check commitment).

**Use:** partial-visible correctness; policy gadget cost vs all-visible.

### 3.4 `auth_committed`

**Security semantics (target prototype path):**

- **Checkpoint / view consistency:** each slot's label fields hash to `authLeaf_x` and Merkle-open to public `root_auth`.
- **View consistency + authorization soundness:** same label targets feed commitment verify and policy gadget.
- **Authorized distance soundness** and **retrieval soundness under authorization** as in [security_properties.md](security_properties.md) §2.6–2.7.
- Global auth tree: one flat Merkle tree over all selected slots (row-major), depth \(tree\_depth(next\_pow2(N_{sel}))\).

**Use:** primary committed-auth reference implementation.

### 3.5 `auth_slot_aligned`

**Security semantics:**

- Same authorization properties as `auth_committed` when openings are valid.
- **Layout optimization:** intra-list openings (slot → list root) + one top opening per probe row (list root → `root_auth`).
- **list_id binding:** top-path direction bits constrained to match content probe list id (cross-list graft blocked).
- **Not a new authorization model** — commitment layout and circuit cost optimization only.

**Use:** compare Merkle opening cost vs global committed; appendix / engineering result.

---

## 4. Completed test inventory

| Test file | Count | Focus |
|-----------|-------|-------|
| `tests/test_auth_reference.py` | 8 | Plaintext oracle, attacks, coverage |
| `tests/test_v3db_adapter.py` | 4 | Adapter vs V3DB baseline scoring |
| `tests/test_auth_commitment.py` | 7 | Global auth Merkle plaintext |
| `tests/test_auth_slot_aligned_commitment.py` | 11 | Slot-aligned Merkle plaintext + cost model |
| `tests/test_auth_zk_all_visible.py` | 1 | All-visible ZK smoke + baseline match |
| `tests/test_auth_zk_partial_visible.py` | 2 | Partial-visible policy path |
| `tests/test_auth_zk_committed.py` | 4 | Global committed positive/negative |
| `tests/test_auth_zk_slot_aligned.py` | 7 | Slot-aligned positive/negative + list_id graft |
| `tests/test_auth_overhead_script.py` | 7 | Benchmark script smoke |
| `tests/test_auth_metrics_summary.py` | 5 | Summary aggregation smoke |
| **Total (auth stack)** | **56** | |

Rust unit tests additionally cover auth mask, policy, commitment, and slot-aligned gadgets (`cargo test auth_*`, `slot_aligned_auth`).

---

## 5. Artifacts and CSV outputs

| Artifact | Rows / type | Description |
|----------|-------------|-------------|
| `artifacts/auth_zk_paper_ready_metrics.csv` | 90 | Paper-ready raw metrics (repeat=3, 6 workloads × 5 paths) |
| `artifacts/auth_zk_paper_ready_summary.csv` | 30 | Median + ratio aggregation |
| `artifacts/auth_zk_slot_aligned_metrics.csv` | 20 | Phase 3C light snapshot (repeat=1) |
| `artifacts/auth_zk_scaling_metrics.csv` | — | Phase 2E scaling grid |
| `artifacts/auth_zk_path_metrics.csv` | — | Phase 2D overhead snapshot |
| `artifacts/v3db_reproduce_metrics.csv` | — | V3DB baseline reproduction |
| `artifacts/plaintext_attack_cases.json` | — | Phase 1 attack fixtures (pre-existing) |

**Scripts:** `scripts/bench_auth_paths.py`, `scripts/summarize_auth_metrics.py`.

Raw metrics schema (16 columns): `path`, `repeat_id`, `num_vectors`, `dim`, `n_list`, `n_probe`, `slot_per_list`, `top_k`, `N_sel`, `visible_ratio`, `auth_tree_depth`, `build_time`, `prove_time`, `verify_time`, `proof_size`, `memory`, `gates`.

---

## 6. Current limitations

| Area | Limitation |
|------|------------|
| **Data** | Synthetic random IVF-PQ (400×64, 8 lists); no SIFT/GIST production snapshot |
| **Credentials** | Public \(\gamma_U\); no hidden user-attribute proofs |
| **Checkpoint** | Single `checkpoint_epoch` integer; no freshness or revocation propagation proof |
| **ANN recall** | Fixed-shape \(Cand\); probe limit inherited from V3DB |
| **Global committed tree** | Benchmark uses probe-local flat tree over \(N_{sel}\) slots, not full index-wide auth tree |
| **Slot-aligned** | Power-of-two `n_list`; wire format expands shared top paths per probe row |
| **Formal proofs** | No machine-checked proof of Plonky2 circuit ↔ spec equivalence |
| **Policy** | Simplified tenant/project/clearance/epoch predicate for prototype |

---

## 7. Next steps for paper writing

1. **Freeze narrative** around committed authorization-view retrieval (not slot-aligned layout).
2. **Use** `artifacts/auth_zk_paper_ready_summary.csv` for Tables 1–2 and scaling figure (see [evaluation_plan_paper_tables.md](evaluation_plan_paper_tables.md)).
3. **Extend evaluation** to SIFT1M subset or fixed real snapshot (repeat ≥ 5).
4. **Clarify in paper** global committed baseline scope (selected-slot tree) when reporting slot-aligned savings.
5. **Related work** positioning: verifiable vector search (V3DB), authenticated data structures, ZK access control — see [paper_outline_draft.md](paper_outline_draft.md).

---

## 8. Phase map (completed)

| Phase | Deliverable |
|-------|-------------|
| 0 | Repo bootstrap, V3DB import |
| 1 | Formal spec, plaintext reference, V3DB adapter |
| 2A–2B | Mask + policy gadgets, all-visible / policy ZK paths |
| 2C | Global committed auth path |
| 2D–2E | Overhead + scaling benchmarks |
| 3A–3B | Slot-aligned design, plaintext + gadget + ZK path |
| 3C–3D | Slot-aligned eval + paper-ready CSV |
| **4A** | **This milestone summary (docs only)** |
