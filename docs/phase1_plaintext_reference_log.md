# Phase 1B Plaintext Reference Log

Recorded on branch `phase1-plaintext-reference`.

## Implemented modules

| Module | Purpose |
|--------|---------|
| `auth_reference/records.py` | `ContentSlotRecord`, `AuthLabel`, `UserContext`, `Checkpoint`, `CandidateRecord`, `ScoredCandidate` |
| `auth_reference/policy.py` | `evaluate_policy`, `compute_visibility` — $$P(\gamma_U,\lambda_x,\sigma)$$ |
| `auth_reference/reference.py` | Masking, top-k, coverage check, `run_authorized_reference` |
| `auth_reference/post_filter.py` | `run_post_filter_baseline` — weak comparator |
| `auth_reference/attacks.py` | Synthetic compliant and attack scenarios |
| `auth_reference/__init__.py` | Public exports |

No Rust, `ivf_pq/`, or `src/` files were modified.

## Semantics implemented

- Visibility: $$v_x = P(\gamma_U,\lambda_x,\sigma)$$
- Masked distance: $$\hat d_x = v_x d_x + (1-v_x) d_{max}$$; $$\tilde d_x = f_x \hat d_x + (1-f_x) d_{max}$$
- Authorized top-k: sort by $$(\tilde d_x, cid)$$, take first $$k$$
- Coverage: fixed-shape check over `(list_id, slot_id)` with optional $$n_{probe} \cdot n$$ count
- $$d_{max} = 2^{62}-1$$ (V3DB sentinel)

## Test cases (`tests/test_auth_reference.py`)

| Test | Category |
|------|----------|
| `test_compliant_case` | Compliant authorized top-k |
| `test_skipped_candidate_fails_coverage` | Skipped candidate |
| `test_forged_label_rejected` | Forged label |
| `test_visibility_manipulation_detected` | Visibility manipulation |
| `test_checkpoint_mismatch_invisible` | Checkpoint / epoch mismatch |
| `test_post_filter_missing_authorized_neighbor` | Post-filter vs authorized |
| `test_per_item_authorized_insufficient` | Weak per-item auth check |
| `test_invalid_slot_demoted` | Valid-bit demotion |

Run:

```bash
source .venv/bin/activate   # if using project venv
export PYTHONPATH=/home/zhixian/AuthView-VDB
pytest tests/test_auth_reference.py -v
```

## Post-filter comparison

Example from `build_post_filter_contrast_candidates()` with $$k=2$$:

| cid | list | slot | raw $$d_x$$ | visible | authorized rank |
|-----|------|------|------------|---------|-----------------|
| 201 | 0 | 0 | 5 | no | demoted ($$d_{max}$$) |
| 202 | 0 | 1 | 7 | no | demoted |
| 203 | 1 | 0 | 18 | yes | 1st |
| 204 | 1 | 1 | 20 | yes | 2nd |

- **Authorized top-k:** `[203, 204]`
- **Post-filter top-k:** `[]` (raw top-2 are invisible; filtered set empty)
- **Per-item auth on post-filter result:** vacuously true — illustrates insufficiency

## Semantic checks

Reference-level validators in `reference.py`:

- `check_candidate_coverage` — candidate enumeration
- `verify_label_commitment` — forged label detection
- `verify_visibility_consistency` — visibility manipulation detection

Policy rules in `policy.py`: tenant, project, clearance, active state, epoch, optional roles.

## Limitations

- Candidates are **pre-constructed**; not yet wired to `ivf_pq/merkle_zk.py` slot buffers
- No Merkle / ZK proof of $$root_{auth}$$ or $$CP_\sigma$$
- Single static policy version (`policy_id` in `Checkpoint` not branched)
- Post-filter baseline uses valid slots only for raw ranking (matches test harness)

## Next integration point

Connect to V3DB Python candidate buffer per [v3db_code_map.md](v3db_code_map.md):

1. After ADC scoring in `ivf_pq/merkle_zk.py` (read-only adapter), map `(valid, item, distance, list_id, slot_id)` → `CandidateRecord`
2. Attach `AuthLabel` from synthetic or committed auth sidecar
3. Call `run_authorized_reference` and compare with `proof=False` top-k when all $$v_x=1$$
4. Phase 2: encode same witness trace in `merkle_ver/set_based.rs`

## Related documents

- [formal_statement.md](formal_statement.md)
- [security_properties.md](security_properties.md)
- [phase1_plaintext_reference_plan.md](phase1_plaintext_reference_plan.md)
