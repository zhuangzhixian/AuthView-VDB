use crate::merkle_ver::auth_mask_gadget::constrain_boolean_gadget;
use crate::prelude::*;
use crate::utils::nn_gadgets::comp_gadget;

/// Fixed number of project membership slots in user context.
pub const MAX_PROJECTS: usize = 4;

/// Integer encoding of active object state (plaintext `ACTIVE_STATE = "active"`).
pub const ACTIVE_STATE: u64 = 1;

/// User authorization context $$\gamma_U$$ as circuit targets (integerized).
pub struct UserContextTargets {
    pub user_tenant_id: Target,
    pub user_project_ids: [Target; MAX_PROJECTS],
    pub user_project_valids: [Target; MAX_PROJECTS],
    pub user_clearance: Target,
    pub user_epoch: Target,
}

/// Object access label $$\lambda_x$$ as circuit targets (integerized).
pub struct ObjectLabelTargets {
    pub object_tenant_id: Target,
    pub object_project_id: Target,
    pub object_level: Target,
    pub object_state: Target,
    pub object_epoch: Target,
}

/// Boolean equality: returns `1` iff `a == b`, `0` otherwise.
pub fn equality_gadget(builder: &mut CircuitBuilder<F, D>, a: Target, b: Target) -> Target {
    builder.is_equal(a, b).target
}

/// Boolean AND for `{0,1}` targets.
pub fn boolean_and_gadget(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    constrain_boolean_gadget(builder, a);
    constrain_boolean_gadget(builder, b);
    builder.mul(a, b)
}

/// Boolean OR for `{0,1}` targets: `a + b - a*b`.
pub fn boolean_or_gadget(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    constrain_boolean_gadget(builder, a);
    constrain_boolean_gadget(builder, b);
    let sum = builder.add(a, b);
    let prod = builder.mul(a, b);
    builder.sub(sum, prod)
}

/// `clearance_ok = [user_clearance >= object_level]`.
///
/// Reuses `comp_gadget`: returns `1` iff `src > dst`, `0` iff `src <= dst`.
/// Assumes both values lie in `[0, 2^62)` (same domain as V3DB distance gadgets).
pub fn clearance_ok_gadget(
    builder: &mut CircuitBuilder<F, D>,
    user_clearance: Target,
    object_level: Target,
) -> Target {
    let level_too_high = comp_gadget(builder, object_level, user_clearance);
    constrain_boolean_gadget(builder, level_too_high);
    let one = builder.one();
    let ok = builder.sub(one, level_too_high);
    constrain_boolean_gadget(builder, ok);
    ok
}

/// Compute authorization visibility bit:
///
/// $$v_x = tenant\_match \land project\_member \land clearance\_ok \land state\_active \land epoch\_match$$
///
/// where
/// $$epoch\_match = [user\_epoch = checkpoint\_epoch] \land [object\_epoch = checkpoint\_epoch]$$
pub fn auth_policy_visibility_gadget(
    builder: &mut CircuitBuilder<F, D>,
    user: &UserContextTargets,
    label: &ObjectLabelTargets,
    checkpoint_epoch: Target,
) -> Target {
    for i in 0..MAX_PROJECTS {
        constrain_boolean_gadget(builder, user.user_project_valids[i]);
    }

    let tenant_match =
        equality_gadget(builder, user.user_tenant_id, label.object_tenant_id);
    constrain_boolean_gadget(builder, tenant_match);

    let mut project_member = builder.zero();
    for i in 0..MAX_PROJECTS {
        let eq_proj = equality_gadget(
            builder,
            user.user_project_ids[i],
            label.object_project_id,
        );
        constrain_boolean_gadget(builder, eq_proj);
        let slot_match = boolean_and_gadget(builder, user.user_project_valids[i], eq_proj);
        project_member = boolean_or_gadget(builder, project_member, slot_match);
    }
    constrain_boolean_gadget(builder, project_member);

    let clearance_ok =
        clearance_ok_gadget(builder, user.user_clearance, label.object_level);

    let active_const = builder.constant(F::from_canonical_u64(ACTIVE_STATE));
    let state_active = equality_gadget(builder, label.object_state, active_const);
    constrain_boolean_gadget(builder, state_active);

    let user_epoch_ok = equality_gadget(builder, user.user_epoch, checkpoint_epoch);
    constrain_boolean_gadget(builder, user_epoch_ok);
    let object_epoch_ok = equality_gadget(builder, label.object_epoch, checkpoint_epoch);
    constrain_boolean_gadget(builder, object_epoch_ok);
    let epoch_match = boolean_and_gadget(builder, user_epoch_ok, object_epoch_ok);

    let v1 = boolean_and_gadget(builder, tenant_match, project_member);
    let v2 = boolean_and_gadget(builder, v1, clearance_ok);
    let v3 = boolean_and_gadget(builder, v2, state_active);
    let visibility = boolean_and_gadget(builder, v3, epoch_match);
    constrain_boolean_gadget(builder, visibility);
    visibility
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct UserFields {
        tenant: u64,
        project_ids: [u64; MAX_PROJECTS],
        project_valids: [u64; MAX_PROJECTS],
        clearance: u64,
        epoch: u64,
    }

    #[derive(Clone, Copy)]
    struct LabelFields {
        tenant: u64,
        project: u64,
        level: u64,
        state: u64,
        epoch: u64,
    }

    fn default_user() -> UserFields {
        UserFields {
            tenant: 10,
            project_ids: [100, 200, 0, 0],
            project_valids: [1, 0, 0, 0],
            clearance: 5,
            epoch: 7,
        }
    }

    fn default_label() -> LabelFields {
        LabelFields {
            tenant: 10,
            project: 100,
            level: 3,
            state: ACTIVE_STATE,
            epoch: 7,
        }
    }

    fn run_policy_case(
        user: UserFields,
        label: LabelFields,
        checkpoint_epoch: u64,
        expected: u64,
    ) {
        let mut builder = make_builder();

        let user_tenant = builder.add_virtual_target();
        let user_project_ids: [Target; MAX_PROJECTS] =
            std::array::from_fn(|_| builder.add_virtual_target());
        let user_project_valids: [Target; MAX_PROJECTS] =
            std::array::from_fn(|_| builder.add_virtual_target());
        let user_clearance = builder.add_virtual_target();
        let user_epoch = builder.add_virtual_target();

        let object_tenant = builder.add_virtual_target();
        let object_project = builder.add_virtual_target();
        let object_level = builder.add_virtual_target();
        let object_state = builder.add_virtual_target();
        let object_epoch = builder.add_virtual_target();
        let checkpoint_epoch_t = builder.add_virtual_target();

        let user_targets = UserContextTargets {
            user_tenant_id: user_tenant,
            user_project_ids,
            user_project_valids,
            user_clearance,
            user_epoch,
        };
        let label_targets = ObjectLabelTargets {
            object_tenant_id: object_tenant,
            object_project_id: object_project,
            object_level,
            object_state,
            object_epoch,
        };

        let visibility = auth_policy_visibility_gadget(
            &mut builder,
            &user_targets,
            &label_targets,
            checkpoint_epoch_t,
        );
        let expected_t = builder.constant(F::from_canonical_u64(expected));
        builder.connect(visibility, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(user_tenant, F::from_canonical_u64(user.tenant))
            .expect("set user tenant");
        for i in 0..MAX_PROJECTS {
            pw.set_target(
                user_project_ids[i],
                F::from_canonical_u64(user.project_ids[i]),
            )
            .expect("set project id");
            pw.set_target(
                user_project_valids[i],
                F::from_canonical_u64(user.project_valids[i]),
            )
            .expect("set project valid");
        }
        pw.set_target(user_clearance, F::from_canonical_u64(user.clearance))
            .expect("set clearance");
        pw.set_target(user_epoch, F::from_canonical_u64(user.epoch))
            .expect("set user epoch");

        pw.set_target(object_tenant, F::from_canonical_u64(label.tenant))
            .expect("set object tenant");
        pw.set_target(object_project, F::from_canonical_u64(label.project))
            .expect("set object project");
        pw.set_target(object_level, F::from_canonical_u64(label.level))
            .expect("set object level");
        pw.set_target(object_state, F::from_canonical_u64(label.state))
            .expect("set object state");
        pw.set_target(object_epoch, F::from_canonical_u64(label.epoch))
            .expect("set object epoch");
        pw.set_target(checkpoint_epoch_t, F::from_canonical_u64(checkpoint_epoch))
            .expect("set checkpoint epoch");

        let proof = data.prove(pw).expect("prove");
        data.verify(proof).expect("verify");
    }

    #[test]
    fn auth_policy_all_conditions_satisfied() {
        // user_epoch and object_epoch both match checkpoint (7).
        run_policy_case(default_user(), default_label(), 7, 1);
    }

    #[test]
    fn auth_policy_tenant_mismatch() {
        let label = LabelFields {
            tenant: 99,
            ..default_label()
        };
        run_policy_case(default_user(), label, 7, 0);
    }

    #[test]
    fn auth_policy_project_not_member() {
        let label = LabelFields {
            project: 999,
            ..default_label()
        };
        run_policy_case(default_user(), label, 7, 0);
    }

    #[test]
    fn auth_policy_clearance_too_low() {
        let user = UserFields {
            clearance: 2,
            ..default_user()
        };
        let label = LabelFields {
            level: 3,
            ..default_label()
        };
        run_policy_case(user, label, 7, 0);
    }

    #[test]
    fn auth_policy_inactive_state() {
        let label = LabelFields {
            state: 0,
            ..default_label()
        };
        run_policy_case(default_user(), label, 7, 0);
    }

    #[test]
    fn auth_policy_object_epoch_mismatch_checkpoint() {
        let label = LabelFields {
            epoch: 8,
            ..default_label()
        };
        run_policy_case(default_user(), label, 7, 0);
    }

    #[test]
    fn auth_policy_user_epoch_mismatch_checkpoint() {
        let user = UserFields {
            epoch: 8,
            ..default_user()
        };
        run_policy_case(user, default_label(), 7, 0);
    }

    #[test]
    fn auth_policy_multiple_project_slots_second_matches() {
        let user = UserFields {
            project_ids: [100, 200, 0, 0],
            project_valids: [1, 1, 0, 0],
            ..default_user()
        };
        let label = LabelFields {
            project: 200,
            ..default_label()
        };
        run_policy_case(user, label, 7, 1);
    }

    #[test]
    fn auth_policy_matching_project_but_slot_invalid() {
        let user = UserFields {
            project_ids: [100, 0, 0, 0],
            project_valids: [0, 0, 0, 0],
            ..default_user()
        };
        run_policy_case(user, default_label(), 7, 0);
    }
}
