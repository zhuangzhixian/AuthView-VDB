# Public-Trace to ZK Proof Pilot Plan (Phase 11)

**Phase:** 10 (plan) → **Phase 11 (implementation target)**  
**Purpose:** Minimal but **real** bridge from public benchmark evaluation artifacts to existing ZK proof paths  
**Prerequisite audit:** [phase10_zk_implementation_gap_audit.md](phase10_zk_implementation_gap_audit.md)

---

## 1. What this is not

- **Not** a claim that Phase 8C/9A/9B already produce ZK proofs.
- **Not** a full re-proof of all 11k public queries.
- **Not** a replacement for Phase 7 controlled parameterized proof workloads (those remain the primary overhead evidence).
- **Not** base truncation — queries come from public benchmarks; candidates come from **Phase 8C trace prefixes** on the **full 1M-indexed** retrieval run.

---

## 2. Pilot goal

Construct **public-trace-derived ZK proof instances** where:

1. **Query** = public benchmark query_id from SIFT1M/GIST1M.
2. **Candidates** = Phase 8C `pred[query_id, :N_sel]` (IVF-PQ top prefix from full-base index).
3. **Visibility** = Phase 9A generated ACL overlay mask for matching `(dataset, policy_mode, selectivity)`.
4. **Relation** = existing **`auth_committed`** (primary), plus **`auth_slot_aligned`** and **`auth_acl_class`** on subset.
5. **N_sel** = proof-feasible fixed value (default **256**, aligned with Phase 7 paper workload), taken from trace prefix — **not** an artificial candidate set.

Output per instance: `prove_time`, `verify_time`, `proof_size`, `num_gates`, `success`/`failure`, path name, query metadata.

---

## 3. Query selection (from Phase 9B)

**Source:** `artifacts/auth_calibration/calibration_queries.csv` (~572 stratified rows).

**Pilot size:** **24 queries** (6 case types × 2 datasets × 2 configs) — expandable to 48 after smoke.

| Case type | Selection filter | Count | Purpose |
|-----------|------------------|-------|---------|
| **C1 visible-dominant** | `gap_bucket=low`, `underfill_bucket=filled`, `selectivity≥0.5` | 4 | Baseline where post-filter ≈ candidate; proof should succeed |
| **C2 low-selectivity underfill** | `gap_bucket=high`, `underfill_bucket=underfill`, `selectivity=0.1` | 4 | Phase 9A semantic stress; proof over visible subset of prefix |
| **C3 ACL-class sharing** | `policy_mode=clustered_acl`, `selectivity=0.25`, mixed gap buckets | 4 | Exercise `auth_acl_class` with structured class visibility |
| **C4 candidate vs full gap** | Rows where Phase 9B `candidate_full_recall_gap < 0` at k=10 | 4 | Proof instance where trace prefix is strict subset of authorized view |
| **C5 committed vs policy** | Same query, prove `auth_committed` + `auth_policy` | 4 | Show Merkle binding overhead on public-derived witness |
| **C6 attack / failure** | Forge label or wrong `root_auth` (from `auth_reference/attacks.py` patterns) | 4 | Verifier rejects; document failure mode |

**Stratification:** balance SIFT1M / GIST1M; include both `high-acc` and `zk-opt` configs where case allows.

**Seed:** 42 (reuse `select_authorized_calibration_queries.py` bucket logic).

---

## 4. Candidate and witness construction

### 4.1 Trace prefix → slot buffers

```text
Load trace NPZ (dataset, config)
  → pred_row = pred[query_id]
  → candidate_ids = pred_row[:N_sel]   # N_sel=256 default; must match circuit
  → gt = gt[query_id, 0]

Load visibility NPZ (dataset, policy_mode, selectivity)
  → visible[candidate_ids]
  → build auth labels per policy_mode (reuse auth_overlay_lib ACL classes where applicable)

Map to V3DBSlotBuffers:
  → slot assignment from IVF list structure OR simplified list=0 bucket for pilot v1
  → distances: recompute ADC from existing index metadata OR use rank-proxy from pred order
```

**Pilot v1 simplification (allowed):** treat `N_sel` candidates as a **single synthetic list** with slot order = pred order. Document that list geometry comes from **public trace ranking**, not random IDs. Full IVF list alignment is **Phase 11b** refinement.

### 4.2 Witness builders (existing)

| Path | Builder |
|------|---------|
| `auth_committed` | `auth_reference/auth_commitment.py` → `build_committed_auth_witness` |
| `auth_slot_aligned` | `auth_reference/slot_aligned_auth_commitment.py` |
| `auth_acl_class` | `auth_reference/acl_class_commitment.py` |

User context: `auth_reference/v3db_adapter.py` → `build_synthetic_user_context` / `encode_user_context_for_zk` (checkpoint epoch from overlay seed).

### 4.3 Proof invocation (existing)

```python
from zk_IVF_PQ.zk_IVF_PQ import (
    py_set_based_auth_committed_with_merkle,
    py_set_based_auth_slot_aligned_with_merkle,
    py_set_based_auth_acl_class_with_merkle,
)
# Returns: build_time, prove_time, verify_time, proof_size, memory, num_gates
```

Cross-check: `auth_reference/reference.py` → `run_authorized_reference` on same candidate records (plaintext oracle match before prove).

---

## 5. Case-specific expectations

| Case | Expected prove | Expected verify | Notes |
|------|----------------|-----------------|-------|
| C1 visible-dominant | Success | Pass | Top-k matches plaintext authorized reference on prefix |
| C2 underfill | Success | Pass | Proof binds **authorized** top-k, not post-filter output |
| C3 ACL-class | Success | Pass | Gate count ↓ vs committed when N_acl ≪ N_sel |
| C4 candidate gap | Success | Pass | Plaintext reference may differ from 9A candidate recall; proof matches committed semantics |
| C5 policy vs committed | Both succeed | Pass | Policy path lacks Merkle bind — document security delta |
| C6 attack | Prove may complete | **Fail verify** | Wrong label / root / visibility manipulation |

---

## 6. Outputs (Phase 11 artifacts)

| Artifact | Description | Git |
|----------|-------------|-----|
| `artifacts/public_zk_pilot/pilot_query_manifest.csv` | Selected 24 queries + case tags | Commit |
| `artifacts/public_zk_pilot/public_trace_zk_metrics.csv` | Per (query, path) metrics | Commit |
| `artifacts/public_zk_pilot/public_trace_zk_summary.csv` | Aggregated by case × path | Commit |
| `artifacts/public_zk_pilot/checkpoint_*.csv` | Resume checkpoints | Ignore |
| `docs/phase11_public_trace_zk_pilot_log.md` | Run log + limitations | Commit |

**CSV columns (metrics):**

`dataset`, `config`, `query_id`, `policy_mode`, `selectivity`, `case_type`, `path`, `N_sel`, `num_candidates`, `visible_count`, `prove_time_s`, `verify_time_s`, `proof_size_bytes`, `num_gates`, `build_time_s`, `peak_memory_bytes`, `success`, `verify_pass`, `reference_scope=public_trace_derived`, `source_trace`, `source_overlay`

No JSON.

---

## 7. Implementation tasks (Phase 11)

| Task | File (proposed) | Depends on |
|------|-----------------|------------|
| P11-1 | `scripts/select_public_zk_pilot_queries.py` | `calibration_queries.csv`, 9B summary |
| P11-2 | `auth_reference/public_trace_adapter.py` | trace NPZ, overlay NPZ |
| P11-3 | `scripts/run_public_trace_zk_pilot.py` | P11-1, P11-2, PyO3 paths |
| P11-4 | `tests/test_public_trace_zk_pilot.py` | mock trace + mock overlay |
| P11-5 | `docs/phase11_public_trace_zk_pilot_log.md` | pilot run |

**Constraints (carry forward):**

- No MS MARCO in pilot v1.
- No IVF-PQ index retrain — reuse Phase 8C index parameters; distances from trace order or loaded index.
- No Rust/PyO3 circuit changes in pilot v1 (witness bridge only).
- Screen/tmux for full 24×3 path run (~1–2 hours estimated).

---

## 8. Success criteria

1. ≥1 **successful prove+verify** per case type C1–C5 on real SIFT/GIST public queries.
2. ≥1 **verify failure** documented for C6 attack case.
3. Plaintext `run_authorized_reference` top-k **matches** proof semantics for committed path on same candidate set.
4. Metrics CSV joinable to Phase 9A row `(dataset, config, policy_mode, selectivity, query_id)`.
5. Paper text can honestly say: **“We report a public-trace-derived proof pilot (N=24); primary overhead evidence remains controlled parameterized workloads (Phase 7).”**

---

## 9. Risk controls (do not exaggerate)

| Risk | Control |
|------|---------|
| “Public benchmarks are fully ZK-proven” | Pilot N=24; appendix only; separate from Phase 7 main overhead |
| “N_sel=256 is arbitrary” | Document extraction from `pred[:256]` of full-base trace |
| “Pilot uses toy candidates” | Candidates are IVF-PQ outputs on 1M index, not random IDs |
| “9B full L2 in circuit” | Pilot proves **prefix authorized top-k** under committed auth; full-base L2 remains plaintext calibration |

---

## 10. Commands (Phase 11 preview)

```bash
# Phase 11 — not run in Phase 10
PYTHONPATH=. .venv/bin/python scripts/select_public_zk_pilot_queries.py \
  --calibration-queries artifacts/auth_calibration/calibration_queries.csv \
  --auth-calibration-summary artifacts/auth_calibration/full_authorized_reference_summary.csv \
  --output artifacts/public_zk_pilot/pilot_query_manifest.csv \
  --cases visible_dominant,underfill,acl_class,candidate_gap,attack \
  --max-per-case 4 --seed 42

PYTHONPATH=. .venv/bin/python scripts/run_public_trace_zk_pilot.py \
  --manifest artifacts/public_zk_pilot/pilot_query_manifest.csv \
  --trace-dir artifacts/public_utility/traces \
  --overlay-dir artifacts/auth_overlay \
  --paths auth_committed,auth_slot_aligned,auth_acl_class \
  --N-sel 256 \
  --output-dir artifacts/public_zk_pilot \
  --resume --skip-existing
```

Phase 10 delivers this plan only; implementation is Phase 11.
