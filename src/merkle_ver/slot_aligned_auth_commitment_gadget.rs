use crate::hash_gadgets::hash_gadget;
use crate::merkle_ver::auth_commitment_gadget::{
    auth_label_leaf_hash_gadget, auth_label_merkle_verify_gadget, AuthLabelCommitmentTargets,
};
use crate::prelude::*;
use crate::utils::common_gadgets::static_lookup_gadget;

/// Re-export: `H(cid, tenant, project, level, state, epoch)`.
pub fn slot_auth_leaf_hash_gadget(
    builder: &mut CircuitBuilder<F, D>,
    label: &AuthLabelCommitmentTargets,
) -> Target {
    auth_label_leaf_hash_gadget(builder, label)
}

/// Verify slot auth label opens to `list_auth_root` via intra-list Merkle path.
pub fn intra_list_auth_verify_gadget(
    builder: &mut CircuitBuilder<F, D>,
    label: &AuthLabelCommitmentTargets,
    intra_path: Vec<Vec<Target>>,
) -> Target {
    auth_label_merkle_verify_gadget(builder, label, intra_path)
}

/// Merkle back starting from an already-hashed leaf (list auth root at top level).
fn merkle_back_from_hash_gadget(
    builder: &mut CircuitBuilder<F, D>,
    leaf_hash: Target,
    path: Vec<Vec<Target>>,
) -> Target {
    let mut curr_target = leaf_hash;
    let one = builder.one();
    for i in 0..path.len() {
        static_lookup_gadget(builder, path[i][0], vec![0, 1]);
        let b0 = path[i][0];
        let b1 = builder.sub(one, path[i][0]);

        let v00 = builder.mul(b0, path[i][1]);
        let v01 = builder.mul(b1, path[i][1]);
        let v10 = builder.mul(b0, curr_target);
        let v11 = builder.mul(b1, curr_target);

        let left = builder.add(v11, v00);
        let right = builder.add(v01, v10);

        curr_target = hash_gadget(builder, vec![left, right]);
    }
    curr_target
}

/// Verify `list_auth_root` opens to `root_auth` via top-level Merkle path.
pub fn top_list_auth_verify_gadget(
    builder: &mut CircuitBuilder<F, D>,
    list_auth_root: Target,
    top_path: Vec<Vec<Target>>,
) -> Target {
    merkle_back_from_hash_gadget(builder, list_auth_root, top_path)
}

/// Per-slot witness for one probed IVF list row.
pub struct SlotAlignedSlotWitness {
    pub label: AuthLabelCommitmentTargets,
    pub intra_path: Vec<Vec<Target>>,
}

/// Verify one probed list: shared `list_auth_root`, one top path, multiple slots.
///
/// Each slot intra opening is constrained to the same `list_auth_root` target
/// (fan-out). Top-level opening is verified once against `root_auth`.
pub fn slot_aligned_probe_row_verify_gadget(
    builder: &mut CircuitBuilder<F, D>,
    list_auth_root: Target,
    top_path: Vec<Vec<Target>>,
    root_auth: Target,
    slots: &[SlotAlignedSlotWitness],
) {
    for slot in slots {
        let intra_root =
            intra_list_auth_verify_gadget(builder, &slot.label, slot.intra_path.clone());
        builder.connect(intra_root, list_auth_root);
    }
    let top_root = top_list_auth_verify_gadget(builder, list_auth_root, top_path);
    builder.connect(top_root, root_auth);
}

/// Decompose `value` into `num_bits` little-endian bits constrained to `{0,1}`.
fn u64_bit_decompose_gadget(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    num_bits: usize,
) -> Vec<Target> {
    let bits: Vec<Target> = (0..num_bits)
        .map(|_| builder.add_virtual_target())
        .collect();
    let two = builder.two();
    let mut pow = builder.one();
    let mut sum = builder.zero();
    for bit in &bits {
        static_lookup_gadget(builder, *bit, vec![0, 1]);
        let term = builder.mul(*bit, pow);
        sum = builder.add(sum, term);
        pow = builder.mul(pow, two);
    }
    builder.connect(sum, value);
    bits
}

/// Bind top-level Merkle path directions to `list_id` (LSB-first path order).
///
/// `path[level][0]` must equal bit `level` of `list_id` (bit 0 = LSB), matching
/// `hash_tree_path` / `open_auth_label` direction order.
pub fn list_id_top_path_binding_gadget(
    builder: &mut CircuitBuilder<F, D>,
    list_id: Target,
    top_path: &[Vec<Target>],
    top_depth: usize,
) {
    let bits = u64_bit_decompose_gadget(builder, list_id, top_depth);
    for level in 0..top_depth {
        static_lookup_gadget(builder, top_path[level][0], vec![0, 1]);
        builder.connect(top_path[level][0], bits[level]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_gadgets::{hash_tree_gen, hash_tree_path, tree_depth};
    use crate::merkle_ver::auth_commitment_gadget::auth_label_leaf_hash_u64;

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

    fn dummy_leaf() -> u64 {
        leaf_row(0, 0, 0, 0, 0, 0)
    }

    fn list_intra_leaves() -> Vec<u64> {
        vec![
            leaf_row(101, 1, 10, 3, 1, 7),
            leaf_row(102, 1, 10, 2, 1, 7),
            dummy_leaf(),
            dummy_leaf(),
        ]
    }

    fn list2_intra_leaves() -> Vec<u64> {
        vec![
            leaf_row(201, 2, 10, 1, 1, 7),
            dummy_leaf(),
            dummy_leaf(),
            dummy_leaf(),
        ]
    }

    struct TwoLevelFixture {
        root_auth: u64,
        list1_root: u64,
        list2_root: u64,
        list1_leaves: Vec<u64>,
        list2_leaves: Vec<u64>,
        top_tree: Vec<u64>,
    }

    fn two_level_fixture() -> TwoLevelFixture {
        let list1_leaves = list_intra_leaves();
        let list2_leaves = list2_intra_leaves();
        let list0_root = dummy_leaf();
        let list3_root = dummy_leaf();
        let list1_root = hash_tree_gen(list1_leaves.clone())[0];
        let list2_root = hash_tree_gen(list2_leaves.clone())[0];
        let top_leaves = vec![list0_root, list1_root, list2_root, list3_root];
        let top_tree = hash_tree_gen(top_leaves.clone());
        let root_auth = top_tree[0];
        TwoLevelFixture {
            root_auth,
            list1_root,
            list2_root,
            list1_leaves,
            list2_leaves,
            top_tree,
        }
    }

    fn add_label_targets(builder: &mut CircuitBuilder<F, D>) -> AuthLabelCommitmentTargets {
        AuthLabelCommitmentTargets {
            cid: builder.add_virtual_target(),
            tenant: builder.add_virtual_target(),
            project: builder.add_virtual_target(),
            level: builder.add_virtual_target(),
            state: builder.add_virtual_target(),
            epoch: builder.add_virtual_target(),
        }
    }

    fn add_path_targets(builder: &mut CircuitBuilder<F, D>, depth: usize) -> Vec<Vec<Target>> {
        (0..depth)
            .map(|_| builder.add_virtual_targets(2))
            .collect()
    }

    fn set_label(
        pw: &mut PartialWitness<F>,
        label: &AuthLabelCommitmentTargets,
        cid: u64,
        tenant: u64,
        project: u64,
        level: u64,
        state: u64,
        epoch: u64,
    ) {
        pw.set_target(label.cid, F::from_canonical_u64(cid)).unwrap();
        pw.set_target(label.tenant, F::from_canonical_u64(tenant)).unwrap();
        pw.set_target(label.project, F::from_canonical_u64(project))
            .unwrap();
        pw.set_target(label.level, F::from_canonical_u64(level)).unwrap();
        pw.set_target(label.state, F::from_canonical_u64(state)).unwrap();
        pw.set_target(label.epoch, F::from_canonical_u64(epoch)).unwrap();
    }

    fn set_path(pw: &mut PartialWitness<F>, path_t: &[Vec<Target>], path_u64: &[Vec<u64>]) {
        for i in 0..path_t.len() {
            pw.set_target(path_t[i][0], F::from_canonical_u64(path_u64[i][0]))
                .unwrap();
            pw.set_target(path_t[i][1], F::from_canonical_u64(path_u64[i][1]))
                .unwrap();
        }
    }

    fn run_probe_row(
        fx: &TwoLevelFixture,
        list_id: u64,
        list_root: u64,
        intra_leaves: &[u64],
        slots: &[(u64, u64, u64, u64, u64, u64, u64)], // cid..epoch, slot_idx
        expect_ok: bool,
    ) {
        let intra_depth = tree_depth(intra_leaves.len());
        let top_depth = tree_depth(4);
        let top_path_u64 = hash_tree_path(list_id, fx.top_tree.clone());

        let mut builder = make_builder();
        let list_auth_root = builder.add_virtual_target();
        let root_auth_t = builder.add_virtual_target();
        let top_path = add_path_targets(&mut builder, top_depth);

        let mut slot_witnesses: Vec<SlotAlignedSlotWitness> = Vec::with_capacity(slots.len());
        for (_cid, _tenant, _project, _level, _state, _epoch, _slot_idx) in slots.iter() {
            let label = add_label_targets(&mut builder);
            let intra_path = add_path_targets(&mut builder, intra_depth);
            slot_witnesses.push(SlotAlignedSlotWitness { label, intra_path });
        }

        slot_aligned_probe_row_verify_gadget(
            &mut builder,
            list_auth_root,
            top_path.clone(),
            root_auth_t,
            &slot_witnesses,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(list_auth_root, F::from_canonical_u64(list_root))
            .unwrap();
        pw.set_target(root_auth_t, F::from_canonical_u64(fx.root_auth))
            .unwrap();
        set_path(&mut pw, &top_path, &top_path_u64);

        let intra_tree = hash_tree_gen(intra_leaves.to_vec());
        for (i, (cid, tenant, project, level, state, epoch, slot_idx)) in slots.iter().enumerate()
        {
            set_label(
                &mut pw,
                &slot_witnesses[i].label,
                *cid,
                *tenant,
                *project,
                *level,
                *state,
                *epoch,
            );
            let intra_path_u64 = hash_tree_path(*slot_idx, intra_tree.clone());
            set_path(&mut pw, &slot_witnesses[i].intra_path, &intra_path_u64);
        }

        let result = data.prove(pw);
        if expect_ok {
            let proof = result.expect("prove should succeed");
            data.verify(proof).expect("verify should succeed");
        } else {
            assert!(result.is_err(), "prove should fail");
        }
    }

    #[test]
    fn slot_aligned_auth_valid_two_level_opening_succeeds() {
        let fx = two_level_fixture();
        run_probe_row(
            &fx,
            1,
            fx.list1_root,
            &fx.list1_leaves,
            &[(101, 1, 10, 3, 1, 7, 0)],
            true,
        );
    }

    #[test]
    fn slot_aligned_auth_forged_tenant_fails() {
        let fx = two_level_fixture();
        run_probe_row(
            &fx,
            1,
            fx.list1_root,
            &fx.list1_leaves,
            &[(101, 99, 10, 3, 1, 7, 0)],
            false,
        );
    }

    #[test]
    fn slot_aligned_auth_forged_cid_fails() {
        let fx = two_level_fixture();
        run_probe_row(
            &fx,
            1,
            fx.list1_root,
            &fx.list1_leaves,
            &[(999, 1, 10, 3, 1, 7, 0)],
            false,
        );
    }

    #[test]
    fn slot_aligned_auth_wrong_intra_list_path_fails() {
        let fx = two_level_fixture();
        let intra_depth = tree_depth(fx.list1_leaves.len());
        let top_depth = tree_depth(4);
        let top_path_u64 = hash_tree_path(1, fx.top_tree.clone());
        let intra_tree = hash_tree_gen(fx.list1_leaves.clone());
        let mut intra_path_u64 = hash_tree_path(0, intra_tree);
        intra_path_u64[0][1] ^= 1;

        let mut builder = make_builder();
        let list_auth_root = builder.add_virtual_target();
        let root_auth_t = builder.add_virtual_target();
        let top_path = add_path_targets(&mut builder, top_depth);
        let label = add_label_targets(&mut builder);
        let intra_path = add_path_targets(&mut builder, intra_depth);
        let witnesses = vec![SlotAlignedSlotWitness {
            label,
            intra_path: intra_path.clone(),
        }];
        slot_aligned_probe_row_verify_gadget(
            &mut builder,
            list_auth_root,
            top_path.clone(),
            root_auth_t,
            &witnesses,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(list_auth_root, F::from_canonical_u64(fx.list1_root))
            .unwrap();
        pw.set_target(root_auth_t, F::from_canonical_u64(fx.root_auth))
            .unwrap();
        set_path(&mut pw, &top_path, &top_path_u64);
        set_label(&mut pw, &witnesses[0].label, 101, 1, 10, 3, 1, 7);
        set_path(&mut pw, &witnesses[0].intra_path, &intra_path_u64);
        assert!(data.prove(pw).is_err());
    }

    #[test]
    fn slot_aligned_auth_wrong_top_level_path_fails() {
        let fx = two_level_fixture();
        let intra_depth = tree_depth(fx.list1_leaves.len());
        let top_depth = tree_depth(4);
        let mut top_path_u64 = hash_tree_path(1, fx.top_tree.clone());
        top_path_u64[0][1] ^= 1;
        let intra_tree = hash_tree_gen(fx.list1_leaves.clone());
        let intra_path_u64 = hash_tree_path(0, intra_tree);

        let mut builder = make_builder();
        let list_auth_root = builder.add_virtual_target();
        let root_auth_t = builder.add_virtual_target();
        let top_path = add_path_targets(&mut builder, top_depth);
        let label = add_label_targets(&mut builder);
        let intra_path = add_path_targets(&mut builder, intra_depth);
        let witnesses = vec![SlotAlignedSlotWitness {
            label,
            intra_path: intra_path.clone(),
        }];
        slot_aligned_probe_row_verify_gadget(
            &mut builder,
            list_auth_root,
            top_path.clone(),
            root_auth_t,
            &witnesses,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(list_auth_root, F::from_canonical_u64(fx.list1_root))
            .unwrap();
        pw.set_target(root_auth_t, F::from_canonical_u64(fx.root_auth))
            .unwrap();
        set_path(&mut pw, &top_path, &top_path_u64);
        set_label(&mut pw, &witnesses[0].label, 101, 1, 10, 3, 1, 7);
        set_path(&mut pw, &witnesses[0].intra_path, &intra_path_u64);
        assert!(data.prove(pw).is_err());
    }

    #[test]
    fn slot_aligned_auth_cross_list_graft_fails() {
        let fx = two_level_fixture();
        let intra_depth = tree_depth(fx.list1_leaves.len());
        let top_depth = tree_depth(4);
        // Top path for list 2, intra opening for list 1 slot 0
        let top_path_u64 = hash_tree_path(2, fx.top_tree.clone());
        let intra_tree = hash_tree_gen(fx.list1_leaves.clone());
        let intra_path_u64 = hash_tree_path(0, intra_tree);

        let mut builder = make_builder();
        let list_auth_root = builder.add_virtual_target();
        let root_auth_t = builder.add_virtual_target();
        let top_path = add_path_targets(&mut builder, top_depth);
        let label = add_label_targets(&mut builder);
        let intra_path = add_path_targets(&mut builder, intra_depth);
        let witnesses = vec![SlotAlignedSlotWitness {
            label,
            intra_path: intra_path.clone(),
        }];
        slot_aligned_probe_row_verify_gadget(
            &mut builder,
            list_auth_root,
            top_path.clone(),
            root_auth_t,
            &witnesses,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        // Witness supplies list1 root but top path is for list2 index
        pw.set_target(list_auth_root, F::from_canonical_u64(fx.list1_root))
            .unwrap();
        pw.set_target(root_auth_t, F::from_canonical_u64(fx.root_auth))
            .unwrap();
        set_path(&mut pw, &top_path, &top_path_u64);
        set_label(&mut pw, &witnesses[0].label, 101, 1, 10, 3, 1, 7);
        set_path(&mut pw, &witnesses[0].intra_path, &intra_path_u64);
        assert!(data.prove(pw).is_err());
    }

    #[test]
    fn slot_aligned_auth_shared_list_root_fanout_succeeds() {
        let fx = two_level_fixture();
        run_probe_row(
            &fx,
            1,
            fx.list1_root,
            &fx.list1_leaves,
            &[
                (101, 1, 10, 3, 1, 7, 0),
                (102, 1, 10, 2, 1, 7, 1),
            ],
            true,
        );
    }

    #[test]
    fn slot_aligned_auth_fanout_mismatch_fails() {
        let fx = two_level_fixture();
        let intra_depth = tree_depth(fx.list1_leaves.len());
        let top_depth = tree_depth(4);
        let top_path_u64 = hash_tree_path(1, fx.top_tree.clone());

        let mut builder = make_builder();
        let list_auth_root = builder.add_virtual_target();
        let root_auth_t = builder.add_virtual_target();
        let top_path = add_path_targets(&mut builder, top_depth);

        let label0 = add_label_targets(&mut builder);
        let intra_path0 = add_path_targets(&mut builder, intra_depth);
        let label1 = add_label_targets(&mut builder);
        let intra_path1 = add_path_targets(&mut builder, intra_depth);

        let witnesses = vec![
            SlotAlignedSlotWitness {
                label: label0,
                intra_path: intra_path0.clone(),
            },
            SlotAlignedSlotWitness {
                label: label1,
                intra_path: intra_path1.clone(),
            },
        ];
        slot_aligned_probe_row_verify_gadget(
            &mut builder,
            list_auth_root,
            top_path.clone(),
            root_auth_t,
            &witnesses,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        // Single shared target cannot equal both list1_root and list2_root
        pw.set_target(list_auth_root, F::from_canonical_u64(fx.list1_root))
            .unwrap();
        pw.set_target(root_auth_t, F::from_canonical_u64(fx.root_auth))
            .unwrap();
        set_path(&mut pw, &top_path, &top_path_u64);

        let intra1 = hash_tree_gen(fx.list1_leaves.clone());
        let intra2 = hash_tree_gen(fx.list2_leaves.clone());
        set_label(&mut pw, &witnesses[0].label, 101, 1, 10, 3, 1, 7);
        set_path(&mut pw, &witnesses[0].intra_path, &hash_tree_path(0, intra1.clone()));
        set_label(&mut pw, &witnesses[1].label, 201, 2, 10, 1, 1, 7);
        set_path(&mut pw, &witnesses[1].intra_path, &hash_tree_path(0, intra2));

        assert!(data.prove(pw).is_err());
    }

    #[test]
    fn list_id_top_path_binding_accepts_matching_bits() {
        let fx = two_level_fixture();
        let top_depth = tree_depth(4);
        let list_id = 1u64;
        let top_path_u64 = hash_tree_path(list_id, fx.top_tree.clone());

        let mut builder = make_builder();
        let list_id_t = builder.add_virtual_target();
        let top_path = add_path_targets(&mut builder, top_depth);
        list_id_top_path_binding_gadget(&mut builder, list_id_t, &top_path, top_depth);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(list_id_t, F::from_canonical_u64(list_id))
            .unwrap();
        set_path(&mut pw, &top_path, &top_path_u64);
        assert!(data.prove(pw).is_ok());
    }

    #[test]
    fn list_id_top_path_binding_rejects_mismatched_bits() {
        let fx = two_level_fixture();
        let top_depth = tree_depth(4);
        let list_id = 1u64;
        let wrong_path = hash_tree_path(2, fx.top_tree.clone());

        let mut builder = make_builder();
        let list_id_t = builder.add_virtual_target();
        let top_path = add_path_targets(&mut builder, top_depth);
        list_id_top_path_binding_gadget(&mut builder, list_id_t, &top_path, top_depth);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(list_id_t, F::from_canonical_u64(list_id))
            .unwrap();
        set_path(&mut pw, &top_path, &wrong_path);
        assert!(data.prove(pw).is_err());
    }
}
