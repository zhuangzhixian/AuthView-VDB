# Phase 1C V3DB Adapter Log

Branch: `phase1-v3db-adapter`.

## V3DB candidate structures

From `ivf_pq/merkle_zk.py` (proof=True / fixed-shape path):

| Structure | Shape | Meaning |
|-----------|-------|---------|
| `vpqss` | `(n_probe, capacity, M)` | PQ code indices per slot |
| `valids` | `(n_probe, capacity)` | 1 = real vector, 0 = padding |
| `itemss` | `(n_probe, capacity)` | Vector / item id (used as cid) |
| `cluster_idxes` | `(n_probe,)` | Selected inverted-list ids |

Distances are **not** stored in buffers. They are computed at step 3–4 via ADC/PQ
lookup (residual query × codebooks). The safe adapter conversion point is **after**
that scoring loop.

`proof=False` fast path uses variable-length clusters without padding; the adapter
targets the fixed-shape path only.

## Adapter mapping

Module: `auth_reference/v3db_adapter.py`

| V3DB field | CandidateRecord field |
|------------|----------------------|
| `itemss[probe, slot]` | `cid` |
| `cluster_idxes[probe]` | `list_id` |
| slot index `j` | `slot_id` |
| `valids[probe, slot]` | `valid` |
| ADC/PQ `curr_dis` | `distance` (int; `d_max` if invalid) |
| external auth sidecar | `label` |

Key functions:

- `build_fixed_shape_slot_buffers` — slot construction without Merkle/Rust
- `compute_v3db_slot_distances` — mirrors merkle_zk scoring
- `candidate_records_from_slot_buffers` — row → `CandidateRecord`
- `v3db_baseline_topk` — stable sort by distance (V3DB tie-break)
- `authorized_topk_v3db_tiebreak` — same tie-break for all-visible regression
- `run_all_visible_authorized_reference` — end-to-end comparison helper

## All-visible regression result

Test: `test_all_visible_regression_matches_v3db_baseline`

When every valid candidate has `P(...)=1`:

- `masked_distance == distance` for valid slots
- `authorized_topk_v3db_tiebreak == v3db_baseline_topk`

Authorization-view retrieval **degenerates** to V3DB retrieval semantics.

Synthetic setup: `ivf_pq_learn` on 400×64 vectors, `n_list=8`, `n_probe=4`, `top_k=5`.

## Partial-visible smoke result

Test: `test_partial_visible_smoke`

- Two closest valid cids assigned invisible labels (`tenant=other-tenant`)
- Invisible valid candidates: `visibility=0`, `masked_distance=d_max`
- Authorized top-k contains no invisible cids
- Visible cids in top-k pass `P(...)=1`

## Tie-breaking note

Formal reference (`authorized_topk`) uses `(masked_distance, cid)`.
V3DB uses stable sort by distance only with slot iteration order on ties.
All-visible regression uses `authorized_topk_v3db_tiebreak` to match V3DB.

## Limitations

- No integration with Rust `py_set_based_with_merkle` proof path
- Auth labels are synthetic sidecar data, not from committed `root_auth`
- Does not call `merkle_zk.zk_ivf_pq_query(proof=True)` (avoids Rust in unit tests)
- `proof=False` V3DB query path not adapted (different candidate universe)

## Next integration (Phase 2 ZK)

1. Wire adapter output into witness layout for `merkle_ver/set_based.rs`
2. Add `root_auth` and `CP_sigma` public inputs
3. Extend valid-bit masking gadget with visibility bit per slot
4. Use plaintext reference as oracle for circuit regression tests

## Tests

```bash
source .venv/bin/activate
export PYTHONPATH=/home/zhixian/AuthView-VDB
pytest tests/test_auth_reference.py tests/test_v3db_adapter.py -v
```

## Related

- [phase1_plaintext_reference_log.md](phase1_plaintext_reference_log.md)
- [v3db_code_map.md](v3db_code_map.md)
- [formal_statement.md](formal_statement.md)
