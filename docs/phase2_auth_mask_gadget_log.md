# Phase 2B-1: Authorization Mask Gadget Log

Minimal Plonky2 gadget for authorization-aware distance masking. Standalone
module only — **not wired into `set_based.rs` or Python APIs** in this phase.

**Branch:** `phase2-auth-mask-gadget`  
**Related:** [phase2_zk_integration_design.md](phase2_zk_integration_design.md),
[phase2_witness_layout.md](phase2_witness_layout.md),
[phase2_test_plan.md](phase2_test_plan.md),
[phase1_plaintext_reference_log.md](phase1_plaintext_reference_log.md).

---

## 1. New files

| File | Purpose |
|------|---------|
| `src/merkle_ver/auth_mask_gadget.rs` | Gadget + unit tests |
| `docs/phase2_auth_mask_gadget_log.md` | This log |

## 2. Modified files

| File | Change |
|------|--------|
| `src/merkle_ver/mod.rs` | `pub mod auth_mask_gadget;` |

**Not modified:** `set_based.rs`, `set_based_proof.rs`, `lib.rs`, Python
baseline paths, `py_set_based_with_merkle`.

---

## 3. Gadget semantics

Form B from Phase 2A design (equivalent to two-stage masking in the formal
statement):

$$
g_x = valid_x \cdot v_x
$$

$$
\hat d_x = g_x \cdot d_x + (1 - g_x) \cdot d_{max}
$$

| Symbol | Meaning |
|--------|---------|
| `valid` | V3DB slot valid bit |
| `visibility` | Authorization visibility bit `v_x` |
| `distance` | Raw ADC/PQ distance `d_x` |
| `d_max` | Sentinel `2^62 - 1` = `4611686018427387903` (`AUTH_MASK_D_MAX`) |

Truth table (distance = 123):

| valid | visibility | hat_d |
|-------|------------|-------|
| 1 | 1 | 123 |
| 1 | 0 | d_max |
| 0 | 1 | d_max |
| 0 | 0 | d_max |

### API

- `AUTH_MASK_D_MAX` — shared sentinel constant
- `constrain_boolean_gadget` — `{0,1}` via `static_lookup_gadget`
- `auth_gate_gadget` — boolean product `valid * visibility`
- `auth_mask_distance_gadget` — full masked distance

Implementation mirrors the valid-bit pattern in `set_based.rs` lines 91–96,
replacing `vld` with combined gate `g = valid * visibility`.

---

## 4. Module placement

Placed under `src/merkle_ver/` (not `src/utils/`) because:

- Phase 2A insertion point is `set_based_ivf_pq_gadget` in `set_based.rs`
- Gadget is specific to set-based Merkle IVF-PQ auth extension
- `utils/common_gadgets.rs` supplies shared primitives (`static_lookup_gadget`);
  domain logic stays next to `set_based.rs`

---

## 5. Test coverage

Rust unit tests in `auth_mask_gadget.rs` (`#[cfg(test)]`):

| Test | Case |
|------|------|
| `auth_mask_valid1_vis1_passes_through_distance` | (1, 1, 123) → 123 |
| `auth_mask_valid1_vis0_uses_d_max` | (1, 0, 123) → d_max |
| `auth_mask_valid0_vis1_uses_d_max` | (0, 1, 123) → d_max |
| `auth_mask_valid0_vis0_uses_d_max` | (0, 0, 123) → d_max |

Each test builds a minimal circuit, connects `hat_d` to the expected constant,
generates a Plonky2 proof, and verifies it.

**Command:**

```bash
source "$HOME/.cargo/env"
cargo test auth_mask --release
```

---

## 6. Correspondence with plaintext reference

`auth_reference/reference.py` — `compute_masked_distance`:

```python
hat = visibility * distance + (1 - visibility) * d_max
masked = valid_bit * hat + (1 - valid_bit) * d_max
```

Algebraically identical to Form B:

```python
g = valid_bit * visibility
masked = g * distance + (1 - g) * d_max
```

Same sentinel as V3DB baseline and reference default (`DEFAULT_D_MAX`).

---

## 7. Next step: Phase 2B-2 (wire into set-based auth circuit)

1. Add **`auth_policy_gadget`** — compute `visibility` from policy witness
   (see `auth_reference/policy.py`, `phase2_witness_layout.md`).
2. Add **`set_based_auth_ivf_pq_gadget`** — copy of `set_based_ivf_pq_gadget`
   with one change at the distance loop (~lines 91–96):

   ```rust
   // replace valid-only mask with:
   let hat_d = auth_mask_distance_gadget(
       builder, valids[i][j], visibility[i][j], curr_dis, AUTH_MASK_D_MAX,
   );
   vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
   ```

3. Add **`set_based_auth_ivf_pq_proof`** + witness builder (adapter-driven).
4. Add **`py_set_based_auth_with_merkle`** (new Python entry; keep baseline
   unchanged).
5. Run Phase 2 tests: all-visible regression, partial-visible cases per
   [phase2_test_plan.md](phase2_test_plan.md).

**Still deferred:** `root_auth` Merkle commitment (Phase 2C).

---

## 8. Constraints honored

- V3DB baseline proof API unchanged
- `py_set_based_with_merkle` unchanged
- No `root_auth` implementation
- No Python API additions in Phase 2B-1
