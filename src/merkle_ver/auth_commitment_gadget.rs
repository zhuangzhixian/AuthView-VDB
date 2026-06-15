use crate::hash_gadgets::{hash_gadget, hash_u64, merkle_back_gadget};
use crate::prelude::*;

/// Number of scalar fields in an auth label leaf.
pub const AUTH_LABEL_LEAF_FIELDS: usize = 6;

/// Per-slot auth label fields for commitment:
/// `H(cid, tenant, project, level, state, epoch)`.
#[derive(Clone)]
pub struct AuthLabelCommitmentTargets {
    pub cid: Target,
    pub tenant: Target,
    pub project: Target,
    pub level: Target,
    pub state: Target,
    pub epoch: Target,
}

/// Leaf field vector in commitment order.
pub fn auth_label_leaf_fields(label: &AuthLabelCommitmentTargets) -> Vec<Target> {
    vec![
        label.cid,
        label.tenant,
        label.project,
        label.level,
        label.state,
        label.epoch,
    ]
}

/// Poseidon leaf hash matching `hash_u64([cid, tenant, project, level, state, epoch])`.
pub fn auth_label_leaf_hash_gadget(
    builder: &mut CircuitBuilder<F, D>,
    label: &AuthLabelCommitmentTargets,
) -> Target {
    hash_gadget(builder, auth_label_leaf_fields(label))
}

/// Merkle opening: recompute root from label fields and `(direction, sibling)` path.
///
/// Path format matches `merkle_back_gadget` / `hash_tree_path`: each row is
/// `[direction, sibling_hash]` where `direction=0` means current node is left child.
pub fn auth_label_merkle_verify_gadget(
    builder: &mut CircuitBuilder<F, D>,
    label: &AuthLabelCommitmentTargets,
    path: Vec<Vec<Target>>,
) -> Target {
    merkle_back_gadget(builder, auth_label_leaf_fields(label), path)
}

/// Plaintext leaf hash (witness / test helper).
pub fn auth_label_leaf_hash_u64(
    cid: u64,
    tenant: u64,
    project: u64,
    level: u64,
    state: u64,
    epoch: u64,
) -> u64 {
    hash_u64(vec![cid, tenant, project, level, state, epoch])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_gadgets::{hash_tree_gen, hash_tree_path, tree_depth};

    fn leaf_row(
        cid: u64,
        tenant: u64,
        project: u64,
        level: u64,
        state: u64,
        epoch: u64,
    ) -> u64 {
        auth_label_leaf_hash_u64(cid, tenant, project, level, state, epoch)
    }

    fn run_opening_case(
        cid: u64,
        tenant: u64,
        project: u64,
        level: u64,
        state: u64,
        epoch: u64,
        leaf_idx: u64,
        leaves: Vec<u64>,
        expected_root: u64,
    ) {
        let hash_tree = hash_tree_gen(leaves.clone());
        let path_u64 = hash_tree_path(leaf_idx, hash_tree);
        let depth = tree_depth(leaves.len());

        let mut builder = make_builder();
        let cid_t = builder.add_virtual_target();
        let tenant_t = builder.add_virtual_target();
        let project_t = builder.add_virtual_target();
        let level_t = builder.add_virtual_target();
        let state_t = builder.add_virtual_target();
        let epoch_t = builder.add_virtual_target();

        let mut path_targets: Vec<Vec<Target>> = Vec::with_capacity(depth);
        for _ in 0..depth {
            path_targets.push(builder.add_virtual_targets(2));
        }

        let label = AuthLabelCommitmentTargets {
            cid: cid_t,
            tenant: tenant_t,
            project: project_t,
            level: level_t,
            state: state_t,
            epoch: epoch_t,
        };
        let root = auth_label_merkle_verify_gadget(&mut builder, &label, path_targets.clone());
        let expected_t = builder.constant(F::from_canonical_u64(expected_root));
        builder.connect(root, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(cid_t, F::from_canonical_u64(cid)).unwrap();
        pw.set_target(tenant_t, F::from_canonical_u64(tenant)).unwrap();
        pw.set_target(project_t, F::from_canonical_u64(project)).unwrap();
        pw.set_target(level_t, F::from_canonical_u64(level)).unwrap();
        pw.set_target(state_t, F::from_canonical_u64(state)).unwrap();
        pw.set_target(epoch_t, F::from_canonical_u64(epoch)).unwrap();
        for i in 0..depth {
            pw.set_target(path_targets[i][0], F::from_canonical_u64(path_u64[i][0]))
                .unwrap();
            pw.set_target(path_targets[i][1], F::from_canonical_u64(path_u64[i][1]))
                .unwrap();
        }

        let proof = data.prove(pw).expect("prove");
        data.verify(proof).expect("verify");
    }

    fn run_opening_case_expect_fail(
        cid: u64,
        tenant: u64,
        project: u64,
        level: u64,
        state: u64,
        epoch: u64,
        leaf_idx: u64,
        leaves: Vec<u64>,
        expected_root: u64,
    ) {
        let hash_tree = hash_tree_gen(leaves.clone());
        let path_u64 = hash_tree_path(leaf_idx, hash_tree);
        let depth = tree_depth(leaves.len());

        let mut builder = make_builder();
        let cid_t = builder.add_virtual_target();
        let tenant_t = builder.add_virtual_target();
        let project_t = builder.add_virtual_target();
        let level_t = builder.add_virtual_target();
        let state_t = builder.add_virtual_target();
        let epoch_t = builder.add_virtual_target();

        let mut path_targets: Vec<Vec<Target>> = Vec::with_capacity(depth);
        for _ in 0..depth {
            path_targets.push(builder.add_virtual_targets(2));
        }

        let label = AuthLabelCommitmentTargets {
            cid: cid_t,
            tenant: tenant_t,
            project: project_t,
            level: level_t,
            state: state_t,
            epoch: epoch_t,
        };
        let root = auth_label_merkle_verify_gadget(&mut builder, &label, path_targets.clone());
        let expected_t = builder.constant(F::from_canonical_u64(expected_root));
        builder.connect(root, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(cid_t, F::from_canonical_u64(cid)).unwrap();
        pw.set_target(tenant_t, F::from_canonical_u64(tenant)).unwrap();
        pw.set_target(project_t, F::from_canonical_u64(project)).unwrap();
        pw.set_target(level_t, F::from_canonical_u64(level)).unwrap();
        pw.set_target(state_t, F::from_canonical_u64(state)).unwrap();
        pw.set_target(epoch_t, F::from_canonical_u64(epoch)).unwrap();
        for i in 0..depth {
            pw.set_target(path_targets[i][0], F::from_canonical_u64(path_u64[i][0]))
                .unwrap();
            pw.set_target(path_targets[i][1], F::from_canonical_u64(path_u64[i][1]))
                .unwrap();
        }

        assert!(data.prove(pw).is_err());
    }

    #[test]
    fn auth_commitment_valid_opening_succeeds() {
        let leaves = vec![
            leaf_row(101, 1, 10, 3, 1, 7),
            leaf_row(102, 1, 10, 2, 1, 7),
            leaf_row(103, 1, 11, 1, 1, 7),
            leaf_row(104, 2, 10, 1, 1, 7),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_opening_case(101, 1, 10, 3, 1, 7, 0, leaves.clone(), root);
    }

    #[test]
    fn auth_commitment_forged_tenant_fails() {
        let leaves = vec![
            leaf_row(101, 1, 10, 3, 1, 7),
            leaf_row(102, 1, 10, 2, 1, 7),
            leaf_row(103, 1, 11, 1, 1, 7),
            leaf_row(104, 2, 10, 1, 1, 7),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_opening_case_expect_fail(101, 99, 10, 3, 1, 7, 0, leaves, root);
    }

    #[test]
    fn auth_commitment_forged_project_fails() {
        let leaves = vec![
            leaf_row(101, 1, 10, 3, 1, 7),
            leaf_row(102, 1, 10, 2, 1, 7),
            leaf_row(103, 1, 11, 1, 1, 7),
            leaf_row(104, 2, 10, 1, 1, 7),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_opening_case_expect_fail(101, 1, 99, 3, 1, 7, 0, leaves, root);
    }

    #[test]
    fn auth_commitment_forged_level_state_epoch_fails() {
        let leaves = vec![
            leaf_row(101, 1, 10, 3, 1, 7),
            leaf_row(102, 1, 10, 2, 1, 7),
            leaf_row(103, 1, 11, 1, 1, 7),
            leaf_row(104, 2, 10, 1, 1, 7),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_opening_case_expect_fail(101, 1, 10, 99, 1, 7, 0, leaves.clone(), root);
        run_opening_case_expect_fail(101, 1, 10, 3, 0, 7, 0, leaves.clone(), root);
        run_opening_case_expect_fail(101, 1, 10, 3, 1, 8, 0, leaves, root);
    }

    #[test]
    fn auth_commitment_forged_cid_fails() {
        let leaves = vec![
            leaf_row(101, 1, 10, 3, 1, 7),
            leaf_row(102, 1, 10, 2, 1, 7),
            leaf_row(103, 1, 11, 1, 1, 7),
            leaf_row(104, 2, 10, 1, 1, 7),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        run_opening_case_expect_fail(999, 1, 10, 3, 1, 7, 0, leaves, root);
    }

    #[test]
    fn auth_commitment_wrong_merkle_path_fails() {
        let leaves = vec![
            leaf_row(101, 1, 10, 3, 1, 7),
            leaf_row(102, 1, 10, 2, 1, 7),
            leaf_row(103, 1, 11, 1, 1, 7),
            leaf_row(104, 2, 10, 1, 1, 7),
        ];
        let root = hash_tree_gen(leaves.clone())[0];
        let hash_tree = hash_tree_gen(leaves.clone());
        let mut path_u64 = hash_tree_path(0, hash_tree);
        path_u64[0][1] ^= 1;

        let depth = tree_depth(leaves.len());
        let mut builder = make_builder();
        let label = AuthLabelCommitmentTargets {
            cid: builder.add_virtual_target(),
            tenant: builder.add_virtual_target(),
            project: builder.add_virtual_target(),
            level: builder.add_virtual_target(),
            state: builder.add_virtual_target(),
            epoch: builder.add_virtual_target(),
        };
        let mut path_targets: Vec<Vec<Target>> = Vec::with_capacity(depth);
        for _ in 0..depth {
            path_targets.push(builder.add_virtual_targets(2));
        }
        let computed = auth_label_merkle_verify_gadget(&mut builder, &label, path_targets.clone());
        let expected_t = builder.constant(F::from_canonical_u64(root));
        builder.connect(computed, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(label.cid, F::from_canonical_u64(101)).unwrap();
        pw.set_target(label.tenant, F::from_canonical_u64(1)).unwrap();
        pw.set_target(label.project, F::from_canonical_u64(10)).unwrap();
        pw.set_target(label.level, F::from_canonical_u64(3)).unwrap();
        pw.set_target(label.state, F::from_canonical_u64(1)).unwrap();
        pw.set_target(label.epoch, F::from_canonical_u64(7)).unwrap();
        for i in 0..depth {
            pw.set_target(path_targets[i][0], F::from_canonical_u64(path_u64[i][0]))
                .unwrap();
            pw.set_target(path_targets[i][1], F::from_canonical_u64(path_u64[i][1]))
                .unwrap();
        }
        assert!(data.prove(pw).is_err());
    }
}
