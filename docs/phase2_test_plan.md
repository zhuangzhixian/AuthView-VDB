# Phase 2 Test Plan

Testing strategy for ZK integration of authorization-view semantics into V3DB
set-based proofs. **Phase 2A:** plan only. Implementation begins in Phase 2B.

**Golden rule:** the plaintext `auth_reference/` implementation is the **oracle**.
Rust circuits and Python prover plumbing must match it slot-by-slot before
performance work.

Related: [phase2_zk_integration_design.md](phase2_zk_integration_design.md),
[phase1_plaintext_reference_log.md](phase1_plaintext_reference_log.md).

---

## 1. Testing principles

| Principle | Detail |
|-----------|--------|
| Oracle | `auth_reference/reference.py` defines $$\hat d_x$$, $$v_x$$, authorized top-k |
| Baseline preservation | All-visible mode must match existing `py_set_based_with_merkle` |
| Additive API | New tests call new functions; old tests unchanged |
| Synthetic first | No SIFT / MS MARCO required for Phase 2B exit |
| Attack inheritance | Phase 1B attack cases remain negative tests at reference layer |

---

## 2. Unit tests

### 2.1 Policy gadget (Rust)

| Test | Oracle | Pass criterion |
|------|--------|----------------|
| Tenant match / mismatch | `auth_reference/policy.py` | Circuit output bit equals Python |
| Project membership | same | same |
| Clearance compare | same | same |
| Active state | same | same |
| Epoch vs checkpoint | same | same |

Run as Rust `#[test]` with small field-native inputs; cross-check Python via
`tests/test_auth_policy_cross.py` (new, Phase 2B).

### 2.2 Masked distance gadget (Rust)

| Input | Expected $$\hat d_x$$ |
|-------|----------------------|
| valid=1, v=1, d=100 | 100 |
| valid=1, v=0, d=100 | $$d_{max}$$ |
| valid=0, v=1, d=100 | $$d_{max}$$ |
| valid=0, v=0, d=100 | $$d_{max}$$ |

Oracle: `auth_reference.reference.compute_masked_distance`.

### 2.3 Python witness builder

| Test | Description |
|------|-------------|
| `test_witness_matches_adapter` | `v3db_adapter` slot rows → witness JSON == manual oracle |
| Label binding | `auth_cid == itemss[i][j]` for all slots |

---

## 3. All-visible regression (critical)

**Requirement:** authorized proof with $$v_x \equiv 1$$ must match V3DB baseline.

| Step | Action |
|------|--------|
| 1 | Build synthetic index (`ivf_pq_learn`, same as `test_v3db_adapter.py`) |
| 2 | Build slot buffers via `v3db_adapter` |
| 3 | Assign all-visible labels |
| 4 | Plaintext oracle: `run_all_visible_authorized_reference` |
| 5 | V3DB baseline: `v3db_baseline_topk` / existing `py_set_based_with_merkle` |
| 6 | Auth ZK: `py_set_based_auth_with_merkle` (Phase 2B) |
| 7 | Assert identical public top-k cids; verify both proofs succeed |

**Existing tests to keep green:**

- `tests/test_v3db_adapter.py::test_all_visible_regression_matches_v3db_baseline`
- `tests/merkle_zk.py` (unchanged baseline)

**New test (Phase 2B):**

- `tests/test_auth_zk_all_visible.py`

---

## 4. Partial-visible tests

Compare ZK public outputs against plaintext reference (not V3DB baseline).

| Test | Setup | Assert |
|------|-------|--------|
| Mixed visibility | 2 invisible + N visible valid slots | ZK top-k == `run_authorized_reference` |
| Invisible demotion | invisible valid slot | $$\hat d_x = d_{max}$$ in witness |
| Top-k exclusion | enough visible candidates | no invisible cid in public top-k |
| Padding slots | valid=0 | $$\hat d_x = d_{max}$$; never in top-k unless k large |

Oracle: `tests/test_auth_reference.py` scenarios + `test_v3db_adapter.py::test_partial_visible_smoke`.

**New test (Phase 2B):**

- `tests/test_auth_zk_partial_visible.py`

---

## 5. Attack tests (carried from auth_reference)

These remain **reference-layer** negative tests in Phase 2B. ZK layer should
reject invalid witnesses that embed the attack (Phase 2C for full proof rejection).

| Attack | Reference test | ZK Phase 2B expectation |
|--------|----------------|-------------------------|
| Skipped candidate | `test_skipped_candidate_fails_coverage` | Prover fails / coverage check |
| Forged label | `test_forged_label_rejected` | With root_auth: reject; without: document gap |
| Visibility manipulation | `test_visibility_manipulation_detected` | Witness inconsistent → proof fail |
| Checkpoint mismatch | `test_checkpoint_mismatch_invisible` | $$v_x=0$$; not in top-k |
| Post-filter contrast | `test_post_filter_missing_authorized_neighbor` | Reference only (no ZK post-filter) |

Artifact: `artifacts/plaintext_attack_cases.json` (from Phase 1C).

---

## 6. Proof generation smoke test

Minimal end-to-end after Phase 2B implementation:

```bash
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB
maturin develop --release
pytest tests/test_auth_zk_all_visible.py -v
```

Smoke parameters (small):

| Param | Value |
|-------|-------|
| N | 400 |
| D | 64 |
| n_list | 8 |
| n_probe | 4 |
| top_k | 5 |
| capacity | power-of-two per cluster |

Success criteria:

- Proof generates without panic
- Verification returns true
- verify_time in low milliseconds (same order as V3DB baseline)

---

## 7. Expected metrics (Phase 2B)

Record in `artifacts/auth_zk_baseline_metrics.csv`:

| Metric | Baseline (V3DB) | Auth all-visible | Auth partial |
|--------|-----------------|------------------|--------------|
| prove_time | from Phase 0 | expect +policy overhead | higher |
| verify_time | ~ms | ~ms | ~ms |
| proof_size | bytes | ≤ baseline + O(N_sel) | similar |
| gate_count | `py_set_based_gate` | `py_set_based_auth_gate` | policy-dependent |
| peak_memory | bytes | compare | compare |

**Not a Phase 2B gate:** beating V3DB performance — correctness first.

---

## 8. CI structure (recommended)

```
tests/test_auth_reference.py          # Phase 1B oracle (no Rust)
tests/test_v3db_adapter.py            # Phase 1C adapter (no Rust)
tests/test_auth_policy_cross.py       # Phase 2B Rust↔Python policy
tests/test_auth_zk_all_visible.py     # Phase 2B ZK regression
tests/test_auth_zk_partial_visible.py # Phase 2B ZK semantics
# existing merkle_zk / bench tests unchanged
```

---

## 9. Non-goals (Phase 2B testing)

| Item | Reason |
|------|--------|
| SIFT / GIST / MS MARCO benchmarks | Phase 3+ |
| root_auth Merkle forgery tests in ZK | Phase 2C |
| Proving privacy of $$\gamma_U$$ | Out of scope |
| Post-filter ZK equivalence | Intentionally different semantics |
| Replacing `py_set_based_with_merkle` | Baseline must remain |

---

## 10. Exit criteria (Phase 2B)

Phase 2B testing is complete when:

1. All Phase 1B + 1C tests still pass unchanged
2. All-visible ZK top-k matches `py_set_based_with_merkle` on synthetic data
3. Partial-visible ZK top-k matches `auth_reference` oracle
4. Policy + masking unit tests pass Rust and Python cross-check
5. Metrics CSV recorded for at least one small configuration
6. No modifications to existing baseline pyo3 entry points' behavior

---

## Related documents

- [phase2_zk_integration_design.md](phase2_zk_integration_design.md)
- [phase2_witness_layout.md](phase2_witness_layout.md)
- [v3db_reproduction_log.md](v3db_reproduction_log.md)
