# Attack Matrix Evaluation (Phase 4C)

Systematic attack experiments for **RQ1**: does proof-carrying authorized vector
retrieval resist realistic prover/server attacks under a pinned verifier context?

Related: [security_properties.md](security_properties.md),
[formal_statement.md](formal_statement.md),
[research_positioning_reset.md](research_positioning_reset.md).

Machine-readable report: [artifacts/auth_attack_matrix.csv](../artifacts/auth_attack_matrix.csv).

---

## 1. Threat model scope

| Actor | Capability |
|-------|------------|
| **Prover / retrieval server** | Malicious: may forge witnesses, substitute Merkle paths, mix trees, omit candidates, or return non-minimal top-k if the API allows injection. |
| **Verifier** | Honest: pins public inputs — query `q`, checkpoint tuple `CP_σ`, policy parameters `θ`, user authorization context `γ_U`, and committed roots (`root_content`, `root_auth`). |
| **Out of scope (prototype)** | Dynamic freshness / latest-root discovery. A prover may present an **old but valid** `root_auth`; local proof only binds to the verifier-pinned root. Freshness is deferred to a checkpoint registry / transparency log (Phase 5+). |

We evaluate two layers:

1. **Plaintext reference** — semantic oracle (`auth_reference/`) without ZK.
2. **Real ZK API** — `py_set_based_auth_committed_with_merkle` and
   `py_set_based_auth_slot_aligned_with_merkle` (no Rust or PyO3 changes in this phase).

---

## 2. Security properties mapped to attacks

| Property | Informal meaning | Representative attacks |
|----------|------------------|------------------------|
| **View Consistency** | Opened auth labels match committed authorization state under `root_auth` and policy `P(γ_U, λ_x, σ)`. | A2, A4, A12 |
| **Authorization Soundness** | Visibility bits `v_x` follow `P(γ_U, λ_x, σ)` on committed labels. | A4, A12 |
| **Retrieval Soundness under Authorization** | Result equals top-k over authorized masked distances on declared candidates, not post-filter. | A1, A9, A10 |
| **Commitment Binding** | Merkle openings match leaf hashes for content and auth fields. | A2, A3, A4, A5, A7, A8 |
| **Layout Binding / list_id binding** | Slot-aligned openings belong to the probed list index. | A6, A7, A8 |
| **Top-k Soundness** | Returned set is the minimal authorized top-k (multiset + sort order). | A9 |
| **Root/Checkpoint Binding (pinned public inputs)** | Proof is verified against verifier-supplied `root_auth` and `checkpoint_epoch`. | A5, A11, A12 |

---

## 3. Attack matrix

| ID | Attack | Layer | Proof path | Expected | Test |
|----|--------|-------|------------|----------|------|
| **A1** | Post-filter insufficiency — retrieve over full index, filter unauthorized results | Plaintext | n/a | Authorized top-k ≠ post-filter top-k | `test_a1_post_filter_insufficiency` |
| **A2** | Unauthorized label forgery (tenant) | ZK API | `auth_committed` | Proof fails | `test_a2_committed_forged_tenant_zk_fails` |
| **A2b** | Unauthorized label forgery (tenant, slot-aligned) | ZK API | `auth_slot_aligned` | Proof fails | `test_a2b_slot_aligned_forged_tenant_zk_fails` |
| **A3** | Auth Merkle path substitution | ZK API | `auth_committed` | Proof fails | `test_a3_committed_wrong_auth_path_zk_fails` |
| **A4** | Visibility / label field forgery (level) | ZK API | `auth_committed` | Proof fails (Merkle ≠ witness) | `test_a4_committed_forged_level_zk_fails` |
| **A5** | Wrong `root_auth` / label-root mixing | ZK API | `auth_committed` | Proof fails under pinned root | `test_a5_committed_root_label_mixing_zk_fails` |
| **A6** | Cross-list graft (content from list A, auth path from list B) | ZK API | `auth_slot_aligned` | Proof fails (`list_id` binding) | `test_a6_slot_aligned_cross_list_graft_zk_fails` |
| **A7** | Wrong intra-list path | ZK API | `auth_slot_aligned` | Proof fails | `test_a7_slot_aligned_wrong_intra_path_zk_fails` |
| **A8** | Wrong top-level path | ZK API | `auth_slot_aligned` | Proof fails | `test_a8_slot_aligned_wrong_top_path_zk_fails` |
| **A9** | Top-k / order manipulation | Circuit | `auth_committed` | Non-minimal or permuted witness fails | **Partially covered** — ordered witness computed inside proof; no PyO3 injection |
| **A10** | Candidate omission / authorized exclusion | Circuit + plaintext | `auth_committed` | Omitted slot breaks witness | **Partially covered** — full buffer shape at API; plaintext oracle in `test_auth_reference` |
| **A11** | Stale root / freshness | Protocol | all | Not prevented by local proof alone | **Out of scope** — checkpoint registry future work |
| **A12** | Pinned user-context mismatch (clearance tamper vs Merkle) | ZK API | `auth_committed` | Proof fails | `test_a12_committed_user_clearance_mismatch_zk_fails` |

### Attack details

**A1 — Post-filter insufficiency.** Service ranks by raw distance, then filters.
Invisible objects in raw top-k can hide closer visible neighbors. Plaintext fixture
`build_post_filter_contrast_candidates()` shows post-filter returns `[]` while
authorized reference returns `[203, 204]`.

**A2 / A2b — Label forgery.** Prover changes `object_tenant_ids` in the witness
without updating Merkle leaves. Global and slot-aligned committed paths reject via
auth opening verification.

**A3 — Path substitution.** Flip one sibling in `auth_path_siblings`; opening no
longer reconstructs `root_auth`.

**A4 — Visibility forgery.** Tamper `object_levels` (or other label fields) in the
witness while Merkle leaf remains unchanged. Policy gadget reads witness fields;
Merkle gadget binds them to the committed leaf.

**A5 — Root/label mixing.** Build witness paths from label set A, substitute
`root_auth` from label set B. Verifier-pinned root does not match reconstructed
root from openings.

**A6 — Cross-list graft.** Replace probe-0 top path with opening from a different
`list_id`. `list_id_top_path_binding_gadget` constrains path bits to match
`list_ids[i]`.

**A7 / A8 — Wrong slot-aligned paths.** Corrupt intra- or top-level siblings;
list root or global `root_auth` reconstruction fails.

**A9 — Top-k manipulation.** Circuit enforces multiset equality and sortedness on
the authorized distance list. The PyO3 API computes the ordered witness inside
Rust; adversaries cannot supply an alternate ordered list directly. Evidence:
existing `set_equal_gadget` + sort constraints in committed proof path.

**A10 — Candidate omission.** Omitting a probed slot would require inconsistent
content/auth buffers; fixed-shape API passes full `n_probe × capacity` grids.
Plaintext coverage check (`test_skipped_candidate_fails_coverage`) detects subset
attacks at the reference layer.

**A11 — Stale root.** Prover reuses an old valid `(root_auth, CP_σ)` pair. Local
verification succeeds relative to pinned inputs; verifier must obtain current root
from an external registry. **Not marked passed** — protocol-layer limitation.

**A12 — User context mismatch.** Verifier pins low clearance in public inputs;
prover tampers witness label level to inflate visibility without Merkle update.
Fails at Merkle binding (same mechanism as A4, under mismatched `γ_U`).

---

## 4. What is tested now vs deferred

| Category | Attacks | Evidence |
|----------|---------|----------|
| **Tested by real ZK API** | A2, A2b, A3, A4, A5, A6, A7, A8, A12 | `tests/test_auth_attack_matrix.py` (+ regressions in `test_auth_zk_committed.py`, `test_auth_zk_slot_aligned.py`) |
| **Tested by plaintext oracle** | A1, A10p, A4p | `tests/test_auth_attack_matrix.py`, `tests/test_auth_reference.py` |
| **Partially covered (circuit / API limit)** | A9, A10 | Documented in registry; circuit constraints cited |
| **Out of scope / future work** | A11 | Checkpoint registry / transparency log |

### Limitations (explicit)

- No direct API to inject adversarial top-k ordering (A9) or partial candidate grids (A10) at the Python boundary.
- Freshness (A11) requires out-of-band root pinning policy, not proof logic changes.
- Policy-only path (`py_set_based_auth_with_merkle`) is regression baseline only; committed paths are the paper-facing guarantee.

---

## 5. Running the evaluation

```bash
source "$HOME/.cargo/env"
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB
maturin develop --release

PYTHONPATH=. pytest tests/test_auth_attack_matrix.py -v

python scripts/write_attack_matrix_summary.py
# → artifacts/auth_attack_matrix.csv
```

---

## 6. Phase 5 pointer

Next recommended work: **ACL-class compression** and `N_acl / N_sel` scaling figure
(see [next_phase_acl_visibility_plan.md](next_phase_acl_visibility_plan.md)).
Slot-aligned layout remains an appendix optimization; attack matrix supports RQ1
without ACL-class mechanisms.
