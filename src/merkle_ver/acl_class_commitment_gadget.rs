use crate::hash_gadgets::{hash_gadget, hash_u64, merkle_back_gadget};
use crate::merkle_ver::auth_mask_gadget::constrain_boolean_gadget;
use crate::merkle_ver::auth_policy_gadget::{
    auth_policy_visibility_gadget, boolean_and_gadget, equality_gadget, ObjectLabelTargets,
    UserContextTargets,
};
use crate::prelude::*;

/// Number of scalar fields in an ACL class leaf.
pub const ACL_CLASS_LEAF_FIELDS: usize = 6;

/// Number of scalar fields in an object-to-class binding leaf.
pub const OBJECT_CLASS_BINDING_LEAF_FIELDS: usize = 3;

/// Dummy ACL class id for padding rows (matches Python `DUMMY_ACL_CLASS_ID`).
pub const DUMMY_ACL_CLASS_ID: u64 = 0;

/// Dynamic ACL state at checkpoint, keyed by `acl_class_id`.
#[derive(Clone)]
pub struct ACLClassLabelTargets {
    pub acl_class_id: Target,
    pub tenant_id: Target,
    pub project_id: Target,
    pub required_clearance: Target,
    pub state: Target,
    pub epoch: Target,
}

/// Static binding from content object to ACL class.
#[derive(Clone)]
pub struct ObjectClassBindingTargets {
    pub cid: Target,
    pub acl_class_id: Target,
    pub epoch: Target,
}

/// Leaf field vector: `H(acl_class_id, tenant_id, project_id, required_clearance, state, epoch)`.
pub fn acl_class_leaf_fields(label: &ACLClassLabelTargets) -> Vec<Target> {
    vec![
        label.acl_class_id,
        label.tenant_id,
        label.project_id,
        label.required_clearance,
        label.state,
        label.epoch,
    ]
}

/// Leaf field vector: `H(cid, acl_class_id, epoch)`.
pub fn object_class_binding_leaf_fields(binding: &ObjectClassBindingTargets) -> Vec<Target> {
    vec![binding.cid, binding.acl_class_id, binding.epoch]
}

pub fn acl_class_leaf_hash_gadget(
    builder: &mut CircuitBuilder<F, D>,
    label: &ACLClassLabelTargets,
) -> Target {
    hash_gadget(builder, acl_class_leaf_fields(label))
}

pub fn object_class_binding_leaf_hash_gadget(
    builder: &mut CircuitBuilder<F, D>,
    binding: &ObjectClassBindingTargets,
) -> Target {
    hash_gadget(builder, object_class_binding_leaf_fields(binding))
}

/// Merkle opening for ACL class leaf → `root_acl_class`.
pub fn verify_acl_class_opening_gadget(
    builder: &mut CircuitBuilder<F, D>,
    label: &ACLClassLabelTargets,
    path: Vec<Vec<Target>>,
) -> Target {
    merkle_back_gadget(builder, acl_class_leaf_fields(label), path)
}

/// Merkle opening for object-to-class binding leaf → `root_object_class_binding`.
pub fn verify_object_class_binding_opening_gadget(
    builder: &mut CircuitBuilder<F, D>,
    binding: &ObjectClassBindingTargets,
    path: Vec<Vec<Target>>,
) -> Target {
    merkle_back_gadget(builder, object_class_binding_leaf_fields(binding), path)
}

/// Map ACL class label fields to object-level policy label targets.
pub fn acl_class_to_object_label(label: &ACLClassLabelTargets) -> ObjectLabelTargets {
    ObjectLabelTargets {
        object_tenant_id: label.tenant_id,
        object_project_id: label.project_id,
        object_level: label.required_clearance,
        object_state: label.state,
        object_epoch: label.epoch,
    }
}

/// Plaintext ACL class leaf hash (witness / test helper).
pub fn acl_class_leaf_hash_u64(
    acl_class_id: u64,
    tenant_id: u64,
    project_id: u64,
    required_clearance: u64,
    state: u64,
    epoch: u64,
) -> u64 {
    hash_u64(vec![
        acl_class_id,
        tenant_id,
        project_id,
        required_clearance,
        state,
        epoch,
    ])
}

/// Plaintext object-to-class binding leaf hash.
pub fn object_class_binding_leaf_hash_u64(cid: u64, acl_class_id: u64, epoch: u64) -> u64 {
    hash_u64(vec![cid, acl_class_id, epoch])
}

/// Selected class table matching for one slot.
///
/// Convention (invalid slots):
/// - `slot_valid = 1` → selector bits sum to exactly 1; selected row must have `valid = 1`.
/// - `slot_valid = 0` → all selector bits are 0 (no class selected).
///
/// When `selector_j = 1`, constrains `binding_acl_class_id == selected_class_ids[j]`.
pub fn acl_class_table_match_gadget(
    builder: &mut CircuitBuilder<F, D>,
    slot_valid: Target,
    binding_acl_class_id: Target,
    selected_class_ids: &[Target],
    selected_class_valids: &[Target],
    selector_bits: &[Target],
) {
    let n = selected_class_ids.len();
    assert_eq!(n, selected_class_valids.len());
    assert_eq!(n, selector_bits.len());

    constrain_boolean_gadget(builder, slot_valid);

    let mut selector_sum = builder.zero();
    for j in 0..n {
        constrain_boolean_gadget(builder, selector_bits[j]);
        constrain_boolean_gadget(builder, selected_class_valids[j]);

        // selector_j => selected_class_valids[j]
        let valid_when_selected = boolean_and_gadget(builder, selector_bits[j], selected_class_valids[j]);
        builder.connect(valid_when_selected, selector_bits[j]);

        // selector_j => binding_acl_class_id == selected_class_ids[j]
        let eq_class = equality_gadget(builder, binding_acl_class_id, selected_class_ids[j]);
        let class_ok = boolean_and_gadget(builder, selector_bits[j], eq_class);
        builder.connect(class_ok, selector_bits[j]);

        selector_sum = builder.add(selector_sum, selector_bits[j]);
    }

    builder.connect(selector_sum, slot_valid);
}

/// Policy evaluated once per selected class row; dummy rows forced to visibility 0.
pub fn acl_class_policy_once_gadget(
    builder: &mut CircuitBuilder<F, D>,
    user: &UserContextTargets,
    selected_class_labels: &[ACLClassLabelTargets],
    selected_class_valids: &[Target],
    checkpoint_epoch: Target,
) -> Vec<Target> {
    let n = selected_class_labels.len();
    assert_eq!(n, selected_class_valids.len());

    let mut class_visibilities = Vec::with_capacity(n);
    for j in 0..n {
        constrain_boolean_gadget(builder, selected_class_valids[j]);
        let object_label = acl_class_to_object_label(&selected_class_labels[j]);
        let raw_vis = auth_policy_visibility_gadget(
            builder,
            user,
            &object_label,
            checkpoint_epoch,
        );
        let vis = boolean_and_gadget(builder, raw_vis, selected_class_valids[j]);
        constrain_boolean_gadget(builder, vis);
        class_visibilities.push(vis);
    }
    class_visibilities
}

/// Slot visibility inherits from selected class: `sum(selector_j * class_vis_j)`, zeroed if invalid.
pub fn inherit_slot_visibility_from_class_gadget(
    builder: &mut CircuitBuilder<F, D>,
    slot_valid: Target,
    selector_bits: &[Target],
    class_visibilities: &[Target],
) -> Target {
    assert_eq!(selector_bits.len(), class_visibilities.len());
    constrain_boolean_gadget(builder, slot_valid);

    let mut inherited = builder.zero();
    for j in 0..selector_bits.len() {
        constrain_boolean_gadget(builder, selector_bits[j]);
        constrain_boolean_gadget(builder, class_visibilities[j]);
        let term = boolean_and_gadget(builder, selector_bits[j], class_visibilities[j]);
        inherited = builder.add(inherited, term);
    }

    let gated = boolean_and_gadget(builder, slot_valid, inherited);
    constrain_boolean_gadget(builder, gated);
    gated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_gadgets::{hash_tree_gen, hash_tree_path, tree_depth};
    use crate::merkle_ver::auth_policy_gadget::{ACTIVE_STATE, MAX_PROJECTS};

    const N_ACL_MAX: usize = 4;

    fn acl_leaf_row(
        acl_class_id: u64,
        tenant_id: u64,
        project_id: u64,
        required_clearance: u64,
        state: u64,
        epoch: u64,
    ) -> u64 {
        acl_class_leaf_hash_u64(
            acl_class_id,
            tenant_id,
            project_id,
            required_clearance,
            state,
            epoch,
        )
    }

    fn binding_leaf_row(cid: u64, acl_class_id: u64, epoch: u64) -> u64 {
        object_class_binding_leaf_hash_u64(cid, acl_class_id, epoch)
    }

    fn run_acl_class_opening(
        acl_class_id: u64,
        tenant_id: u64,
        project_id: u64,
        required_clearance: u64,
        state: u64,
        epoch: u64,
        leaf_idx: u64,
        leaves: Vec<u64>,
        expected_root: u64,
        expect_ok: bool,
    ) {
        let hash_tree = hash_tree_gen(leaves.clone());
        let path_u64 = hash_tree_path(leaf_idx, hash_tree);
        let depth = tree_depth(leaves.len());

        let mut builder = make_builder();
        let label = ACLClassLabelTargets {
            acl_class_id: builder.add_virtual_target(),
            tenant_id: builder.add_virtual_target(),
            project_id: builder.add_virtual_target(),
            required_clearance: builder.add_virtual_target(),
            state: builder.add_virtual_target(),
            epoch: builder.add_virtual_target(),
        };
        let mut path_targets: Vec<Vec<Target>> = Vec::with_capacity(depth);
        for _ in 0..depth {
            path_targets.push(builder.add_virtual_targets(2));
        }
        let root = verify_acl_class_opening_gadget(&mut builder, &label, path_targets.clone());
        let expected_t = builder.constant(F::from_canonical_u64(expected_root));
        builder.connect(root, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(label.acl_class_id, F::from_canonical_u64(acl_class_id))
            .unwrap();
        pw.set_target(label.tenant_id, F::from_canonical_u64(tenant_id))
            .unwrap();
        pw.set_target(label.project_id, F::from_canonical_u64(project_id))
            .unwrap();
        pw.set_target(
            label.required_clearance,
            F::from_canonical_u64(required_clearance),
        )
        .unwrap();
        pw.set_target(label.state, F::from_canonical_u64(state)).unwrap();
        pw.set_target(label.epoch, F::from_canonical_u64(epoch)).unwrap();
        for i in 0..depth {
            pw.set_target(path_targets[i][0], F::from_canonical_u64(path_u64[i][0]))
                .unwrap();
            pw.set_target(path_targets[i][1], F::from_canonical_u64(path_u64[i][1]))
                .unwrap();
        }

        if expect_ok {
            let proof = data.prove(pw).expect("prove");
            data.verify(proof).expect("verify");
        } else {
            assert!(data.prove(pw).is_err());
        }
    }

    fn run_binding_opening(
        cid: u64,
        acl_class_id: u64,
        epoch: u64,
        leaf_idx: u64,
        leaves: Vec<u64>,
        expected_root: u64,
        expect_ok: bool,
    ) {
        let hash_tree = hash_tree_gen(leaves.clone());
        let path_u64 = hash_tree_path(leaf_idx, hash_tree);
        let depth = tree_depth(leaves.len());

        let mut builder = make_builder();
        let binding = ObjectClassBindingTargets {
            cid: builder.add_virtual_target(),
            acl_class_id: builder.add_virtual_target(),
            epoch: builder.add_virtual_target(),
        };
        let mut path_targets: Vec<Vec<Target>> = Vec::with_capacity(depth);
        for _ in 0..depth {
            path_targets.push(builder.add_virtual_targets(2));
        }
        let root =
            verify_object_class_binding_opening_gadget(&mut builder, &binding, path_targets.clone());
        let expected_t = builder.constant(F::from_canonical_u64(expected_root));
        builder.connect(root, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(binding.cid, F::from_canonical_u64(cid)).unwrap();
        pw.set_target(binding.acl_class_id, F::from_canonical_u64(acl_class_id))
            .unwrap();
        pw.set_target(binding.epoch, F::from_canonical_u64(epoch)).unwrap();
        for i in 0..depth {
            pw.set_target(path_targets[i][0], F::from_canonical_u64(path_u64[i][0]))
                .unwrap();
            pw.set_target(path_targets[i][1], F::from_canonical_u64(path_u64[i][1]))
                .unwrap();
        }

        if expect_ok {
            let proof = data.prove(pw).expect("prove");
            data.verify(proof).expect("verify");
        } else {
            assert!(data.prove(pw).is_err());
        }
    }

    #[derive(Clone, Copy)]
    struct UserFields {
        tenant: u64,
        project_ids: [u64; MAX_PROJECTS],
        project_valids: [u64; MAX_PROJECTS],
        clearance: u64,
        epoch: u64,
    }

    fn default_user() -> UserFields {
        UserFields {
            tenant: 1,
            project_ids: [10, 11, 0, 0],
            project_valids: [1, 0, 0, 0],
            clearance: 5,
            epoch: 1,
        }
    }

    fn set_user_pw(pw: &mut PartialWitness<F>, user: UserFields, targets: &UserContextTargets) {
        pw.set_target(targets.user_tenant_id, F::from_canonical_u64(user.tenant))
            .unwrap();
        for i in 0..MAX_PROJECTS {
            pw.set_target(
                targets.user_project_ids[i],
                F::from_canonical_u64(user.project_ids[i]),
            )
            .unwrap();
            pw.set_target(
                targets.user_project_valids[i],
                F::from_canonical_u64(user.project_valids[i]),
            )
            .unwrap();
        }
        pw.set_target(targets.user_clearance, F::from_canonical_u64(user.clearance))
            .unwrap();
        pw.set_target(targets.user_epoch, F::from_canonical_u64(user.epoch))
            .unwrap();
    }

    fn add_user_targets(builder: &mut CircuitBuilder<F, D>) -> UserContextTargets {
        UserContextTargets {
            user_tenant_id: builder.add_virtual_target(),
            user_project_ids: std::array::from_fn(|_| builder.add_virtual_target()),
            user_project_valids: std::array::from_fn(|_| builder.add_virtual_target()),
            user_clearance: builder.add_virtual_target(),
            user_epoch: builder.add_virtual_target(),
        }
    }

    fn run_table_match_case(
        slot_valid: u64,
        binding_class_id: u64,
        class_ids: [u64; N_ACL_MAX],
        class_valids: [u64; N_ACL_MAX],
        selectors: [u64; N_ACL_MAX],
        expect_ok: bool,
    ) {
        let mut builder = make_builder();
        let slot_valid_t = builder.add_virtual_target();
        let binding_id_t = builder.add_virtual_target();
        let class_ids_t: Vec<Target> = (0..N_ACL_MAX)
            .map(|_| builder.add_virtual_target())
            .collect();
        let class_valids_t: Vec<Target> = (0..N_ACL_MAX)
            .map(|_| builder.add_virtual_target())
            .collect();
        let selectors_t: Vec<Target> = (0..N_ACL_MAX)
            .map(|_| builder.add_virtual_target())
            .collect();

        acl_class_table_match_gadget(
            &mut builder,
            slot_valid_t,
            binding_id_t,
            &class_ids_t,
            &class_valids_t,
            &selectors_t,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(slot_valid_t, F::from_canonical_u64(slot_valid))
            .unwrap();
        pw.set_target(binding_id_t, F::from_canonical_u64(binding_class_id))
            .unwrap();
        for j in 0..N_ACL_MAX {
            pw.set_target(class_ids_t[j], F::from_canonical_u64(class_ids[j]))
                .unwrap();
            pw.set_target(class_valids_t[j], F::from_canonical_u64(class_valids[j]))
                .unwrap();
            pw.set_target(selectors_t[j], F::from_canonical_u64(selectors[j]))
                .unwrap();
        }

        if expect_ok {
            let proof = data.prove(pw).expect("prove");
            data.verify(proof).expect("verify");
        } else {
            assert!(data.prove(pw).is_err());
        }
    }

    fn run_policy_once_case(
        class_rows: [(u64, u64, u64, u64, u64, u64); N_ACL_MAX],
        class_valids: [u64; N_ACL_MAX],
        checkpoint_epoch: u64,
        expected: [u64; N_ACL_MAX],
        expect_ok: bool,
    ) {
        let mut builder = make_builder();
        let user = add_user_targets(&mut builder);
        let checkpoint_t = builder.add_virtual_target();

        let mut labels = Vec::with_capacity(N_ACL_MAX);
        for _ in 0..N_ACL_MAX {
            labels.push(ACLClassLabelTargets {
                acl_class_id: builder.add_virtual_target(),
                tenant_id: builder.add_virtual_target(),
                project_id: builder.add_virtual_target(),
                required_clearance: builder.add_virtual_target(),
                state: builder.add_virtual_target(),
                epoch: builder.add_virtual_target(),
            });
        }
        let valids_t: Vec<Target> = (0..N_ACL_MAX)
            .map(|_| builder.add_virtual_target())
            .collect();

        let vis = acl_class_policy_once_gadget(
            &mut builder,
            &user,
            &labels,
            &valids_t,
            checkpoint_t,
        );
        for j in 0..N_ACL_MAX {
            let expected_t = builder.constant(F::from_canonical_u64(expected[j]));
            builder.connect(vis[j], expected_t);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        set_user_pw(&mut pw, default_user(), &user);
        pw.set_target(checkpoint_t, F::from_canonical_u64(checkpoint_epoch))
            .unwrap();
        for j in 0..N_ACL_MAX {
            let (id, tenant, project, clearance, state, epoch) = class_rows[j];
            pw.set_target(labels[j].acl_class_id, F::from_canonical_u64(id))
                .unwrap();
            pw.set_target(labels[j].tenant_id, F::from_canonical_u64(tenant))
                .unwrap();
            pw.set_target(labels[j].project_id, F::from_canonical_u64(project))
                .unwrap();
            pw.set_target(
                labels[j].required_clearance,
                F::from_canonical_u64(clearance),
            )
            .unwrap();
            pw.set_target(labels[j].state, F::from_canonical_u64(state))
                .unwrap();
            pw.set_target(labels[j].epoch, F::from_canonical_u64(epoch))
                .unwrap();
            pw.set_target(valids_t[j], F::from_canonical_u64(class_valids[j]))
                .unwrap();
        }

        if expect_ok {
            let proof = data.prove(pw).expect("prove");
            data.verify(proof).expect("verify");
        } else {
            assert!(data.prove(pw).is_err());
        }
    }

    fn run_inherit_visibility_case(
        slot_valid: u64,
        selectors: [u64; N_ACL_MAX],
        class_vis: [u64; N_ACL_MAX],
        expected_slot_vis: u64,
        expect_ok: bool,
    ) {
        let mut builder = make_builder();
        let slot_valid_t = builder.add_virtual_target();
        let selectors_t: Vec<Target> = (0..N_ACL_MAX)
            .map(|_| builder.add_virtual_target())
            .collect();
        let class_vis_t: Vec<Target> = (0..N_ACL_MAX)
            .map(|_| builder.add_virtual_target())
            .collect();

        let slot_vis = inherit_slot_visibility_from_class_gadget(
            &mut builder,
            slot_valid_t,
            &selectors_t,
            &class_vis_t,
        );
        let expected_t = builder.constant(F::from_canonical_u64(expected_slot_vis));
        builder.connect(slot_vis, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(slot_valid_t, F::from_canonical_u64(slot_valid))
            .unwrap();
        for j in 0..N_ACL_MAX {
            pw.set_target(selectors_t[j], F::from_canonical_u64(selectors[j]))
                .unwrap();
            pw.set_target(class_vis_t[j], F::from_canonical_u64(class_vis[j]))
                .unwrap();
        }

        if expect_ok {
            let proof = data.prove(pw).expect("prove");
            data.verify(proof).expect("verify");
        } else {
            assert!(data.prove(pw).is_err());
        }
    }

    #[test]
    fn acl_class_leaf_hash_deterministic() {
        let h1 = acl_class_leaf_hash_u64(42, 1, 10, 3, 1, 7);
        let h2 = acl_class_leaf_hash_u64(42, 1, 10, 3, 1, 7);
        assert_eq!(h1, h2);
        assert_ne!(h1, acl_class_leaf_hash_u64(42, 2, 10, 3, 1, 7));
    }

    #[test]
    fn acl_class_object_binding_leaf_hash_deterministic() {
        let h1 = binding_leaf_row(101, 42, 7);
        let h2 = binding_leaf_row(101, 42, 7);
        assert_eq!(h1, h2);
        assert_ne!(h1, binding_leaf_row(101, 43, 7));
    }

    #[test]
    fn acl_class_valid_merkle_opening_succeeds() {
        let leaves = vec![
            acl_leaf_row(1, 1, 10, 2, 1, 1),
            acl_leaf_row(2, 2, 10, 1, 1, 1),
            acl_leaf_row(0, 0, 0, 0, 0, 0),
            acl_leaf_row(3, 1, 11, 3, 1, 1),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_acl_class_opening(1, 1, 10, 2, 1, 1, 0, leaves, root, true);
    }

    #[test]
    fn acl_class_forged_label_fails() {
        let leaves = vec![
            acl_leaf_row(1, 1, 10, 2, 1, 1),
            acl_leaf_row(2, 2, 10, 1, 1, 1),
            acl_leaf_row(0, 0, 0, 0, 0, 0),
            acl_leaf_row(3, 1, 11, 3, 1, 1),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_acl_class_opening(1, 99, 10, 2, 1, 1, 0, leaves, root, false);
    }

    #[test]
    fn acl_class_valid_object_binding_opening_succeeds() {
        let leaves = vec![
            binding_leaf_row(101, 1, 1),
            binding_leaf_row(102, 1, 1),
            binding_leaf_row(103, 2, 1),
            binding_leaf_row(104, 2, 1),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_binding_opening(101, 1, 1, 0, leaves, root, true);
    }

    #[test]
    fn acl_class_forged_object_binding_fails() {
        let leaves = vec![
            binding_leaf_row(101, 1, 1),
            binding_leaf_row(102, 1, 1),
            binding_leaf_row(103, 2, 1),
            binding_leaf_row(104, 2, 1),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_binding_opening(101, 99, 1, 0, leaves, root, false);
    }

    #[test]
    fn acl_class_table_match_valid_slot_succeeds() {
        run_table_match_case(
            1,
            42,
            [42, 99, 0, 0],
            [1, 1, 0, 0],
            [1, 0, 0, 0],
            true,
        );
    }

    #[test]
    fn acl_class_table_match_class_id_mismatch_fails() {
        run_table_match_case(
            1,
            42,
            [99, 42, 0, 0],
            [1, 1, 0, 0],
            [1, 0, 0, 0],
            false,
        );
    }

    #[test]
    fn acl_class_table_match_not_one_hot_fails() {
        run_table_match_case(
            1,
            42,
            [42, 42, 0, 0],
            [1, 1, 0, 0],
            [1, 1, 0, 0],
            false,
        );
    }

    #[test]
    fn acl_class_table_match_invalid_selected_row_fails() {
        run_table_match_case(
            1,
            42,
            [42, 99, 0, 0],
            [0, 1, 0, 0],
            [1, 0, 0, 0],
            false,
        );
    }

    #[test]
    fn acl_class_table_match_invalid_slot_zero_selector_succeeds() {
        run_table_match_case(
            0,
            0,
            [42, 99, 0, 0],
            [1, 1, 0, 0],
            [0, 0, 0, 0],
            true,
        );
    }

    #[test]
    fn acl_class_policy_once_matches_object_level_fields() {
        let visible = (1, 1, 10, 2, ACTIVE_STATE, 1);
        let invisible = (2, 2, 10, 1, ACTIVE_STATE, 1);
        run_policy_once_case(
            [visible, invisible, (0, 0, 0, 0, 0, 0), (0, 0, 0, 0, 0, 0)],
            [1, 1, 0, 0],
            1,
            [1, 0, 0, 0],
            true,
        );
    }

    #[test]
    fn acl_class_policy_once_dummy_class_visibility_zero() {
        let dummy = (DUMMY_ACL_CLASS_ID, 1, 10, 2, ACTIVE_STATE, 1);
        run_policy_once_case(
            [dummy, (0, 0, 0, 0, 0, 0), (0, 0, 0, 0, 0, 0), (0, 0, 0, 0, 0, 0)],
            [0, 0, 0, 0],
            1,
            [0, 0, 0, 0],
            true,
        );
    }

    #[test]
    fn acl_class_slot_visibility_inheritance_succeeds() {
        run_inherit_visibility_case(1, [1, 0, 0, 0], [1, 0, 0, 0], 1, true);
    }

    #[test]
    fn acl_class_slot_visibility_wrong_class_fails() {
        run_inherit_visibility_case(1, [0, 1, 0, 0], [1, 0, 0, 0], 1, false);
    }

    #[test]
    fn acl_class_all_same_class_reuses_visibility() {
        run_inherit_visibility_case(1, [1, 0, 0, 0], [1, 1, 0, 0], 1, true);
        run_inherit_visibility_case(1, [1, 0, 0, 0], [1, 1, 0, 0], 1, true);
    }

    #[test]
    fn acl_class_degenerate_n_acl_equals_n_sel_table_match() {
        run_table_match_case(1, 10, [10, 20, 30, 40], [1, 1, 1, 1], [1, 0, 0, 0], true);
        run_table_match_case(1, 40, [10, 20, 30, 40], [1, 1, 1, 1], [0, 0, 0, 1], true);
    }
}
