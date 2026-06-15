# Phase 2B-2: Authorization Policy Gadget Log

Minimal Plonky2 gadget for computing authorization visibility
$$v_x = P(\gamma_U, \lambda_x, \sigma)$$ under a first-version integerized
policy. Standalone module only — **not wired into `set_based.rs` or Python
APIs**.

**Branch:** `phase2-auth-policy-gadget`  
**Related:** [phase2_auth_mask_gadget_log.md](phase2_auth_mask_gadget_log.md),
[phase2_zk_integration_design.md](phase2_zk_integration_design.md),
[phase2_witness_layout.md](phase2_witness_layout.md),
[phase2_test_plan.md](phase2_test_plan.md),
[formal_statement.md](formal_statement.md).

---

## 1. New files

| File | Purpose |
|------|---------|
| `src/merkle_ver/auth_policy_gadget.rs` | Policy gadget + unit tests |
| `docs/phase2_auth_policy_gadget_log.md` | This log |

## 2. Modified files

| File | Change |
|------|--------|
| `src/merkle_ver/mod.rs` | `pub mod auth_policy_gadget;` |

**Not modified:** `set_based.rs`, `set_based_proof.rs`, `lib.rs`, Python
baseline paths, `py_set_based_with_merkle`, `auth_mask_gadget.rs`.

---

## 3. Policy semantics

$$
v_x =
tenant\_match
\land project\_member
\land clearance\_ok
\land state\_active
\land epoch\_match
$$

| Sub-predicate | Definition |
|---------------|------------|
| `tenant_match` | `[user_tenant_id = object_tenant_id]` |
| `project_member` | $$\bigvee_i (user\_project\_valid_i \land [user\_project\_ids_i = object\_project\_id])$$ |
| `clearance_ok` | `[user_clearance \ge object_level]` |
| `state_active` | `[object_state = 1]` (`ACTIVE_STATE`) |
| `epoch_match` | `[user_epoch = checkpoint_epoch] \land [object_epoch = checkpoint_epoch]` |

Visibility is **computed in-circuit** from user context, object label, and
checkpoint epoch; it is not accepted as an unconstrained witness.

All intermediate boolean targets are constrained to `{0, 1}` via
`constrain_boolean_gadget` (from `auth_mask_gadget`).

### API

| Symbol | Role |
|--------|------|
| `MAX_PROJECTS` | Fixed project slot count (`4`) |
| `ACTIVE_STATE` | Integer active state (`1`) |
| `UserContextTargets` | $$\gamma_U$$ target bundle |
| `ObjectLabelTargets` | $$\lambda_x$$ target bundle |
| `equality_gadget` | Plonky2 `is_equal` wrapper |
| `boolean_and_gadget` / `boolean_or_gadget` | Boolean combinators |
| `clearance_ok_gadget` | `user_clearance >= object_level` via `comp_gadget` |
| `auth_policy_visibility_gadget(user, label, checkpoint_epoch)` | Full visibility bit |

`checkpoint_epoch` binds $$\sigma.epoch$$: both $$\gamma_U$$ and $$\lambda_x$$
must belong to the same authorization checkpoint for visibility to hold.

### Clearance comparison assumption

`clearance_ok_gadget` reuses `comp_gadget` from `utils/nn_gadgets.rs`, which
assumes both operands lie in `[0, 2^62)` (same domain as V3DB distance
comparisons). Clearance and level are small integers in practice; this is
sufficient for Phase 2B.

---

## 4. Supported fields (Phase 2B-2)

| Circuit field | Plaintext reference | Notes |
|---------------|---------------------|-------|
| `user_tenant_id` | `UserContext.tenant` | Integer tag, not string |
| `user_project_ids[i]` | `UserContext.projects` | Fixed `MAX_PROJECTS=4` slots |
| `user_project_valids[i]` | (padding for fixed shape) | `1` = slot occupied |
| `user_clearance` | `UserContext.clearance` | |
| `user_epoch` | `UserContext.epoch` | Must equal `checkpoint_epoch` |
| `checkpoint_epoch` | `Checkpoint.epoch` ($$\sigma.epoch$$) | Circuit input; future public input |
| `object_tenant_id` | `AuthLabel.tenant` | Integer tag |
| `object_project_id` | `AuthLabel.project` | Integer tag |
| `object_level` | `AuthLabel.level` | |
| `object_state` | `AuthLabel.state` | `1` = active |
| `object_epoch` | `AuthLabel.epoch` | Must equal `checkpoint_epoch` |

---

## 5. Not supported (deferred)

| Field / rule | Plaintext reference | Phase 2B-2 status |
|--------------|---------------------|-------------------|
| `UserContext.roles` | `roles` set | **Not implemented** — future extension |
| `AuthLabel.roles` | required role intersection | **Not implemented** |
| Full `CP_sigma` public binding | `Checkpoint` tuple as public input | **Not implemented** — gadget accepts `checkpoint_epoch` target only |
| String tenant/project | Python uses `str` | Integer tags only |
| `policy_id` | `Checkpoint.policy_id` | Not in gadget (future public input) |
| `root_auth` Merkle | Phase 2C | Not implemented |

### Epoch / checkpoint semantics

`epoch_match` aligns with formal semantics $$P(\gamma_U, \lambda_x, \sigma)$$:

$$
epoch\_match =
[user\_epoch = checkpoint\_epoch]
\land
[object\_epoch = checkpoint\_epoch]
$$

- `user_epoch` — epoch of the user authorization context $$\gamma_U$$
- `object_epoch` — epoch stamped on object label $$\lambda_x$$
- `checkpoint_epoch` — accepted authorization checkpoint $$\sigma.epoch$$

Phase 2B-2 does **not** register `checkpoint_epoch` as a full public
`CP_sigma` input; the gadget accepts it as a circuit target so
`set_based_auth_ivf_pq_gadget` (Phase 2B-3) can wire it from public inputs per
[phase2_witness_layout.md](phase2_witness_layout.md).

Compared to `auth_reference/policy.py`: Python skips epoch check when
`label.epoch == 0`; the integer gadget requires explicit equality to
`checkpoint_epoch` on both sides. Phase 2B-3 adapter fixtures should set
`object_epoch = checkpoint_epoch` for compliant cases.

---

## 6. Test coverage

Rust unit tests in `auth_policy_gadget.rs`:

| Test | Expected visibility |
|------|---------------------|
| `auth_policy_all_conditions_satisfied` | 1 (both epochs match checkpoint) |
| `auth_policy_tenant_mismatch` | 0 |
| `auth_policy_project_not_member` | 0 |
| `auth_policy_clearance_too_low` | 0 |
| `auth_policy_inactive_state` | 0 |
| `auth_policy_object_epoch_mismatch_checkpoint` | 0 |
| `auth_policy_user_epoch_mismatch_checkpoint` | 0 |
| `auth_policy_multiple_project_slots_second_matches` | 1 |
| `auth_policy_matching_project_but_slot_invalid` | 0 |

Each test builds a minimal circuit, connects visibility to the expected
constant, proves, and verifies.

**Command:**

```bash
source "$HOME/.cargo/env"
cargo test auth_policy --release
```

---

## 7. Relationship to `auth_reference/policy.py`

The gadget implements the **integerized subset** of `evaluate_policy`:

| Python rule | Gadget |
|-------------|--------|
| `label.tenant == user.tenant` | `tenant_match` |
| `label.project in user.projects` | `project_member` over fixed slots |
| `label.level <= user.clearance` | `clearance_ok` |
| `label.state == "active"` | `state_active` (`object_state == 1`) |
| epoch / checkpoint | `epoch_match` (user and object epochs vs `checkpoint_epoch`) |
| role intersection | **skipped** |

To align Python regression tests with the circuit in Phase 2B-3, add an
integer policy helper mirroring this subset (or map string fixtures to integer
tags in the adapter).

---

## 8. Next step: Phase 2B-3 (`set_based_auth_ivf_pq_gadget`)

1. Copy `set_based_ivf_pq_gadget` → `set_based_auth_ivf_pq_gadget` (new function,
   **do not modify** existing baseline gadget).
2. Per slot `(i, j)`:
   - Build `UserContextTargets` from public / witness user fields.
   - Build `ObjectLabelTargets` from per-slot auth witness.
   - `visibility = auth_policy_visibility_gadget(..., checkpoint_epoch)`.
   - `hat_d = auth_mask_distance_gadget(..., valid, visibility, curr_dis, D_MAX)`.
3. Add `set_based_auth_ivf_pq_proof` + witness builder (adapter-driven).
4. Add `py_set_based_auth_with_merkle` (additive Python entry).
5. Run all-visible regression + partial-visible tests per
   [phase2_test_plan.md](phase2_test_plan.md).

Chain: **policy gadget → mask gadget → set-based auth circuit → proof API**.

**Still deferred:** `root_auth` Merkle (Phase 2C).

---

## 9. Constraints honored

- V3DB baseline proof API unchanged
- `set_based.rs` / `set_based_proof.rs` / `lib.rs` unchanged
- No Python API additions
- No `root_auth` implementation
