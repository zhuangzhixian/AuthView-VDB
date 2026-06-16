use crate::ivf_pq::gadgets::vec_sub_gadget;
use crate::ivf_pq_verify::gadgets::const_gen_gadget;
use crate::merkle_ver::acl_class_commitment_gadget::{
    acl_class_policy_once_gadget, acl_class_table_match_gadget,
    inherit_slot_visibility_from_class_gadget, verify_acl_class_opening_gadget,
    verify_object_class_binding_opening_gadget, ACLClassLabelTargets,
    ObjectClassBindingTargets,
};
use crate::merkle_ver::auth_commitment_gadget::{
    auth_label_merkle_verify_gadget, AuthLabelCommitmentTargets,
};
use crate::merkle_ver::auth_mask_gadget::{auth_mask_distance_gadget, AUTH_MASK_D_MAX};
use crate::merkle_ver::auth_policy_gadget::{
    auth_policy_visibility_gadget, ObjectLabelTargets, UserContextTargets,
};
use crate::merkle_ver::slot_aligned_auth_commitment_gadget::{
    list_id_top_path_binding_gadget, slot_aligned_probe_row_verify_gadget,
    SlotAlignedSlotWitness,
};
use crate::merkle_ver::standalone_commitment::standalone_commitment_gadget;
use crate::pq_flat::gadgets::codebooks_query_gadget;
use crate::pq_flat_verify::gadgets::set_belong_gedget;
use crate::prelude::*;
use crate::utils::nn_gadgets::{comp_gadget, static_nn_gadget};
use crate::utils::set_gadgets::set_equal_gadget;
use std::cmp::max;

/// AuthView set-based IVF-PQ gadget with all-visible authorization ($$v_x \equiv 1$$).
///
/// Identical to `set_based_ivf_pq_gadget` except valid-bit masking uses
/// `auth_mask_distance_gadget` with visibility fixed to constant one.
pub fn set_based_auth_ivf_pq_gadget_all_visible(
    builder: &mut CircuitBuilder<F, D>,
    fs_hash: Vec<Target>,                     // 挑战, (7,)
    query: Vec<Target>,                       // 查询向量 (D,)
    top_k: usize,                             // 最终返回top_k个
    root: Target,                             // 总的根
    codebooks_root: Target,                   // codebooks对应的根
    codebooks: Vec<Vec<Vec<Target>>>,         // codebooks (M,K,d)
    ivf_center: Vec<Vec<Target>>,             // cluster的中心, 注意排序过程需要mut (n_list, D)
    ivf_roots: Vec<Target>,                   // cluster对应的merkle根 (n_list,)
    cluster_center: Vec<Vec<Target>>,         // cluster中心也要提供 (n_probe,D)
    valids: Vec<Vec<Target>>,                 // 对应的vpqs是否valid (n_probe,n)
    itemss: Vec<Vec<Target>>,                 // 需要取出的内容 (n_probe,n)
    cluster_pairs: Vec<Vec<Vec<Target>>>,     // merkle树的路径
    vpqss: Vec<Vec<Vec<Target>>>,             // 量化后的向量 (n_probe,n,M)
    vpqss_dis: Vec<Vec<Vec<Target>>>,         // vpqss中的每一个索引号对应的LUT距离 (n_probe,n,M)
    ordered_vpqss_item_dis: Vec<Vec<Target>>, // vpqss中计算的距离和item集合 (n_probe*n,2)
    cluster_idx_dis: Vec<Vec<Target>>,        // cluster对应的索引号以及距离 (n_list,2)
    f_: Vec<Target>,
    t_: Vec<Target>,
    merkled: bool,
) {
    let M = codebooks.len();
    let K = codebooks[0].len();
    let n = valids[0].len();
    let n_probe = cluster_center.len();
    let cluster_idxes: Vec<Target> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();
    let const_list = const_gen_gadget(
        builder,
        max(max(n_probe as u64, n as u64), max(M as u64, K as u64)),
    );

    static_nn_gadget(
        builder,
        fs_hash[0],
        fs_hash[1],
        ivf_center.clone(),
        query.clone(),
        cluster_idx_dis.clone(),
    );

    let mut luts: Vec<Vec<Vec<Target>>> = Vec::with_capacity(n_probe);
    for i in 0..n_probe {
        let sub_val = vec_sub_gadget(builder, query.clone(), cluster_center[i].clone());
        luts.push(codebooks_query_gadget(builder, codebooks.clone(), sub_val));
    }

    let mut lut_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![
                    const_list[i],
                    const_list[j],
                    const_list[k],
                    luts[i][j][k],
                ]);
            }
        }
    }

    let visibility = builder.one();
    let mut vpqss_item_dis: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n);
    let mut vpqss_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        for j in 0..n {
            for k in 0..M {
                vpqss_set.push(vec![
                    const_list[i],
                    const_list[k],
                    vpqss[i][j][k],
                    vpqss_dis[i][j][k],
                ]);
            }
            let curr_dis = builder.add_many(vpqss_dis[i][j].clone());
            let hat_d = auth_mask_distance_gadget(
                builder,
                valids[i][j],
                visibility,
                curr_dis,
                AUTH_MASK_D_MAX,
            );
            vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
        }
    }

    set_equal_gadget(
        builder,
        fs_hash[2],
        fs_hash[3],
        vpqss_item_dis,
        ordered_vpqss_item_dis.clone(),
    );
    for i in 0..(n_probe * n - 1) {
        let flag = comp_gadget(
            builder,
            ordered_vpqss_item_dis[i][1].clone(),
            ordered_vpqss_item_dis[i + 1][1].clone(),
        );
        builder.connect(flag, const_list[0]);
    }
    set_belong_gedget(builder, fs_hash[4..].to_vec(), vpqss_set, lut_set, f_, t_);
    for i in 0..top_k {
        builder.register_public_input(ordered_vpqss_item_dis[i][0]);
    }

    if merkled {
        standalone_commitment_gadget(
            builder,
            query.clone(),
            root.clone(),
            codebooks_root.clone(),
            codebooks.clone(),
            ivf_center.clone(),
            ivf_roots.clone(),
            cluster_idxes,
            cluster_center.clone(),
            valids.clone(),
            itemss.clone(),
            cluster_pairs.clone(),
            vpqss.clone(),
        );
    }
}

/// Per-slot auth label targets aligned with `[n_probe][n]` slot buffers.
pub struct SlotAuthLabelTargets {
    pub object_tenant_ids: Vec<Vec<Target>>,
    pub object_project_ids: Vec<Vec<Target>>,
    pub object_levels: Vec<Vec<Target>>,
    pub object_states: Vec<Vec<Target>>,
    pub object_epochs: Vec<Vec<Target>>,
}

/// AuthView set-based IVF-PQ gadget with per-slot policy visibility.
///
/// $$v_x = P(\gamma_U, \lambda_x, \sigma)$$ via `auth_policy_visibility_gadget`,
/// then $$\hat d_x$$ via `auth_mask_distance_gadget`.
pub fn set_based_auth_ivf_pq_gadget_policy(
    builder: &mut CircuitBuilder<F, D>,
    fs_hash: Vec<Target>,
    query: Vec<Target>,
    top_k: usize,
    root: Target,
    codebooks_root: Target,
    codebooks: Vec<Vec<Vec<Target>>>,
    ivf_center: Vec<Vec<Target>>,
    ivf_roots: Vec<Target>,
    cluster_center: Vec<Vec<Target>>,
    valids: Vec<Vec<Target>>,
    itemss: Vec<Vec<Target>>,
    cluster_pairs: Vec<Vec<Vec<Target>>>,
    vpqss: Vec<Vec<Vec<Target>>>,
    vpqss_dis: Vec<Vec<Vec<Target>>>,
    ordered_vpqss_item_dis: Vec<Vec<Target>>,
    cluster_idx_dis: Vec<Vec<Target>>,
    user: &UserContextTargets,
    checkpoint_epoch: Target,
    slot_labels: &SlotAuthLabelTargets,
    f_: Vec<Target>,
    t_: Vec<Target>,
    merkled: bool,
) {
    let M = codebooks.len();
    let K = codebooks[0].len();
    let n = valids[0].len();
    let n_probe = cluster_center.len();
    let cluster_idxes: Vec<Target> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();
    let const_list = const_gen_gadget(
        builder,
        max(max(n_probe as u64, n as u64), max(M as u64, K as u64)),
    );

    static_nn_gadget(
        builder,
        fs_hash[0],
        fs_hash[1],
        ivf_center.clone(),
        query.clone(),
        cluster_idx_dis.clone(),
    );

    let mut luts: Vec<Vec<Vec<Target>>> = Vec::with_capacity(n_probe);
    for i in 0..n_probe {
        let sub_val = vec_sub_gadget(builder, query.clone(), cluster_center[i].clone());
        luts.push(codebooks_query_gadget(builder, codebooks.clone(), sub_val));
    }

    let mut lut_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![
                    const_list[i],
                    const_list[j],
                    const_list[k],
                    luts[i][j][k],
                ]);
            }
        }
    }

    let mut vpqss_item_dis: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n);
    let mut vpqss_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        for j in 0..n {
            for k in 0..M {
                vpqss_set.push(vec![
                    const_list[i],
                    const_list[k],
                    vpqss[i][j][k],
                    vpqss_dis[i][j][k],
                ]);
            }
            let curr_dis = builder.add_many(vpqss_dis[i][j].clone());
            let label = ObjectLabelTargets {
                object_tenant_id: slot_labels.object_tenant_ids[i][j],
                object_project_id: slot_labels.object_project_ids[i][j],
                object_level: slot_labels.object_levels[i][j],
                object_state: slot_labels.object_states[i][j],
                object_epoch: slot_labels.object_epochs[i][j],
            };
            let visibility =
                auth_policy_visibility_gadget(builder, user, &label, checkpoint_epoch);
            let hat_d = auth_mask_distance_gadget(
                builder,
                valids[i][j],
                visibility,
                curr_dis,
                AUTH_MASK_D_MAX,
            );
            vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
        }
    }

    set_equal_gadget(
        builder,
        fs_hash[2],
        fs_hash[3],
        vpqss_item_dis,
        ordered_vpqss_item_dis.clone(),
    );
    for i in 0..(n_probe * n - 1) {
        let flag = comp_gadget(
            builder,
            ordered_vpqss_item_dis[i][1].clone(),
            ordered_vpqss_item_dis[i + 1][1].clone(),
        );
        builder.connect(flag, const_list[0]);
    }
    set_belong_gedget(builder, fs_hash[4..].to_vec(), vpqss_set, lut_set, f_, t_);
    for i in 0..top_k {
        builder.register_public_input(ordered_vpqss_item_dis[i][0]);
    }

    if merkled {
        standalone_commitment_gadget(
            builder,
            query.clone(),
            root.clone(),
            codebooks_root.clone(),
            codebooks.clone(),
            ivf_center.clone(),
            ivf_roots.clone(),
            cluster_idxes,
            cluster_center.clone(),
            valids.clone(),
            itemss.clone(),
            cluster_pairs.clone(),
            vpqss.clone(),
        );
    }
}

/// Per-slot Merkle opening witness: `[n_probe][n][depth]`.
pub struct SlotAuthMerkleWitnessTargets {
    pub directions: Vec<Vec<Vec<Target>>>,
    pub siblings: Vec<Vec<Vec<Target>>>,
}

/// AuthView set-based IVF-PQ gadget with committed auth labels under `root_auth`.
pub fn set_based_auth_ivf_pq_gadget_committed(
    builder: &mut CircuitBuilder<F, D>,
    fs_hash: Vec<Target>,
    query: Vec<Target>,
    top_k: usize,
    root: Target,
    codebooks_root: Target,
    codebooks: Vec<Vec<Vec<Target>>>,
    ivf_center: Vec<Vec<Target>>,
    ivf_roots: Vec<Target>,
    cluster_center: Vec<Vec<Target>>,
    valids: Vec<Vec<Target>>,
    itemss: Vec<Vec<Target>>,
    cluster_pairs: Vec<Vec<Vec<Target>>>,
    vpqss: Vec<Vec<Vec<Target>>>,
    vpqss_dis: Vec<Vec<Vec<Target>>>,
    ordered_vpqss_item_dis: Vec<Vec<Target>>,
    cluster_idx_dis: Vec<Vec<Target>>,
    root_auth: Target,
    user: &UserContextTargets,
    checkpoint_epoch: Target,
    slot_labels: &SlotAuthLabelTargets,
    auth_paths: &SlotAuthMerkleWitnessTargets,
    auth_depth: usize,
    f_: Vec<Target>,
    t_: Vec<Target>,
    merkled: bool,
) {
    builder.register_public_input(root_auth);

    let M = codebooks.len();
    let K = codebooks[0].len();
    let n = valids[0].len();
    let n_probe = cluster_center.len();
    let cluster_idxes: Vec<Target> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();
    let const_list = const_gen_gadget(
        builder,
        max(max(n_probe as u64, n as u64), max(M as u64, K as u64)),
    );

    static_nn_gadget(
        builder,
        fs_hash[0],
        fs_hash[1],
        ivf_center.clone(),
        query.clone(),
        cluster_idx_dis.clone(),
    );

    let mut luts: Vec<Vec<Vec<Target>>> = Vec::with_capacity(n_probe);
    for i in 0..n_probe {
        let sub_val = vec_sub_gadget(builder, query.clone(), cluster_center[i].clone());
        luts.push(codebooks_query_gadget(builder, codebooks.clone(), sub_val));
    }

    let mut lut_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![
                    const_list[i],
                    const_list[j],
                    const_list[k],
                    luts[i][j][k],
                ]);
            }
        }
    }

    let mut vpqss_item_dis: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n);
    let mut vpqss_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        for j in 0..n {
            for k in 0..M {
                vpqss_set.push(vec![
                    const_list[i],
                    const_list[k],
                    vpqss[i][j][k],
                    vpqss_dis[i][j][k],
                ]);
            }
            let commitment_label = AuthLabelCommitmentTargets {
                cid: itemss[i][j],
                tenant: slot_labels.object_tenant_ids[i][j],
                project: slot_labels.object_project_ids[i][j],
                level: slot_labels.object_levels[i][j],
                state: slot_labels.object_states[i][j],
                epoch: slot_labels.object_epochs[i][j],
            };
            let mut path_row: Vec<Vec<Target>> = Vec::with_capacity(auth_depth);
            for d in 0..auth_depth {
                path_row.push(vec![
                    auth_paths.directions[i][j][d],
                    auth_paths.siblings[i][j][d],
                ]);
            }
            let slot_root =
                auth_label_merkle_verify_gadget(builder, &commitment_label, path_row);
            builder.connect(slot_root, root_auth);

            let policy_label = ObjectLabelTargets {
                object_tenant_id: slot_labels.object_tenant_ids[i][j],
                object_project_id: slot_labels.object_project_ids[i][j],
                object_level: slot_labels.object_levels[i][j],
                object_state: slot_labels.object_states[i][j],
                object_epoch: slot_labels.object_epochs[i][j],
            };
            let curr_dis = builder.add_many(vpqss_dis[i][j].clone());
            let visibility =
                auth_policy_visibility_gadget(builder, user, &policy_label, checkpoint_epoch);
            let hat_d = auth_mask_distance_gadget(
                builder,
                valids[i][j],
                visibility,
                curr_dis,
                AUTH_MASK_D_MAX,
            );
            vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
        }
    }

    set_equal_gadget(
        builder,
        fs_hash[2],
        fs_hash[3],
        vpqss_item_dis,
        ordered_vpqss_item_dis.clone(),
    );
    for i in 0..(n_probe * n - 1) {
        let flag = comp_gadget(
            builder,
            ordered_vpqss_item_dis[i][1].clone(),
            ordered_vpqss_item_dis[i + 1][1].clone(),
        );
        builder.connect(flag, const_list[0]);
    }
    set_belong_gedget(builder, fs_hash[4..].to_vec(), vpqss_set, lut_set, f_, t_);
    for i in 0..top_k {
        builder.register_public_input(ordered_vpqss_item_dis[i][0]);
    }

    if merkled {
        standalone_commitment_gadget(
            builder,
            query.clone(),
            root.clone(),
            codebooks_root.clone(),
            codebooks.clone(),
            ivf_center.clone(),
            ivf_roots.clone(),
            cluster_idxes,
            cluster_center.clone(),
            valids.clone(),
            itemss.clone(),
            cluster_pairs.clone(),
            vpqss.clone(),
        );
    }
}

/// Per-probe-row top-level slot-aligned auth Merkle witness: `[n_probe][depth_top]`.
pub struct SlotAlignedTopWitnessTargets {
    pub list_ids: Vec<Target>,
    pub list_auth_roots: Vec<Target>,
    pub directions: Vec<Vec<Target>>,
    pub siblings: Vec<Vec<Target>>,
}

/// Per-slot intra-list Merkle witness: `[n_probe][n][depth_slot]`.
pub struct SlotAlignedIntraWitnessTargets {
    pub directions: Vec<Vec<Vec<Target>>>,
    pub siblings: Vec<Vec<Vec<Target>>>,
}

/// AuthView set-based IVF-PQ gadget with slot-aligned committed auth labels.
pub fn set_based_auth_ivf_pq_gadget_committed_slot_aligned(
    builder: &mut CircuitBuilder<F, D>,
    fs_hash: Vec<Target>,
    query: Vec<Target>,
    top_k: usize,
    root: Target,
    codebooks_root: Target,
    codebooks: Vec<Vec<Vec<Target>>>,
    ivf_center: Vec<Vec<Target>>,
    ivf_roots: Vec<Target>,
    cluster_center: Vec<Vec<Target>>,
    valids: Vec<Vec<Target>>,
    itemss: Vec<Vec<Target>>,
    cluster_pairs: Vec<Vec<Vec<Target>>>,
    vpqss: Vec<Vec<Vec<Target>>>,
    vpqss_dis: Vec<Vec<Vec<Target>>>,
    ordered_vpqss_item_dis: Vec<Vec<Target>>,
    cluster_idx_dis: Vec<Vec<Target>>,
    root_auth: Target,
    user: &UserContextTargets,
    checkpoint_epoch: Target,
    slot_labels: &SlotAuthLabelTargets,
    top_witness: &SlotAlignedTopWitnessTargets,
    intra_witness: &SlotAlignedIntraWitnessTargets,
    top_depth: usize,
    intra_depth: usize,
    f_: Vec<Target>,
    t_: Vec<Target>,
    merkled: bool,
) {
    builder.register_public_input(root_auth);

    let M = codebooks.len();
    let K = codebooks[0].len();
    let n = valids[0].len();
    let n_probe = cluster_center.len();
    let cluster_idxes: Vec<Target> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();
    let const_list = const_gen_gadget(
        builder,
        max(max(n_probe as u64, n as u64), max(M as u64, K as u64)),
    );

    static_nn_gadget(
        builder,
        fs_hash[0],
        fs_hash[1],
        ivf_center.clone(),
        query.clone(),
        cluster_idx_dis.clone(),
    );

    let mut luts: Vec<Vec<Vec<Target>>> = Vec::with_capacity(n_probe);
    for i in 0..n_probe {
        let sub_val = vec_sub_gadget(builder, query.clone(), cluster_center[i].clone());
        luts.push(codebooks_query_gadget(builder, codebooks.clone(), sub_val));
    }

    let mut lut_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![
                    const_list[i],
                    const_list[j],
                    const_list[k],
                    luts[i][j][k],
                ]);
            }
        }
    }

    let mut vpqss_item_dis: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n);
    let mut vpqss_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        builder.connect(top_witness.list_ids[i], cluster_idxes[i]);

        let mut top_path: Vec<Vec<Target>> = Vec::with_capacity(top_depth);
        for d in 0..top_depth {
            top_path.push(vec![
                top_witness.directions[i][d],
                top_witness.siblings[i][d],
            ]);
        }
        list_id_top_path_binding_gadget(
            builder,
            top_witness.list_ids[i],
            &top_path,
            top_depth,
        );

        let mut slots: Vec<SlotAlignedSlotWitness> = Vec::with_capacity(n);
        for j in 0..n {
            for k in 0..M {
                vpqss_set.push(vec![
                    const_list[i],
                    const_list[k],
                    vpqss[i][j][k],
                    vpqss_dis[i][j][k],
                ]);
            }

            let commitment_label = AuthLabelCommitmentTargets {
                cid: itemss[i][j],
                tenant: slot_labels.object_tenant_ids[i][j],
                project: slot_labels.object_project_ids[i][j],
                level: slot_labels.object_levels[i][j],
                state: slot_labels.object_states[i][j],
                epoch: slot_labels.object_epochs[i][j],
            };
            let mut intra_path: Vec<Vec<Target>> = Vec::with_capacity(intra_depth);
            for d in 0..intra_depth {
                intra_path.push(vec![
                    intra_witness.directions[i][j][d],
                    intra_witness.siblings[i][j][d],
                ]);
            }
            slots.push(SlotAlignedSlotWitness {
                label: commitment_label,
                intra_path,
            });

            let policy_label = ObjectLabelTargets {
                object_tenant_id: slot_labels.object_tenant_ids[i][j],
                object_project_id: slot_labels.object_project_ids[i][j],
                object_level: slot_labels.object_levels[i][j],
                object_state: slot_labels.object_states[i][j],
                object_epoch: slot_labels.object_epochs[i][j],
            };
            let curr_dis = builder.add_many(vpqss_dis[i][j].clone());
            let visibility =
                auth_policy_visibility_gadget(builder, user, &policy_label, checkpoint_epoch);
            let hat_d = auth_mask_distance_gadget(
                builder,
                valids[i][j],
                visibility,
                curr_dis,
                AUTH_MASK_D_MAX,
            );
            vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
        }

        slot_aligned_probe_row_verify_gadget(
            builder,
            top_witness.list_auth_roots[i],
            top_path,
            root_auth,
            &slots,
        );
    }

    set_equal_gadget(
        builder,
        fs_hash[2],
        fs_hash[3],
        vpqss_item_dis,
        ordered_vpqss_item_dis.clone(),
    );
    for i in 0..(n_probe * n - 1) {
        let flag = comp_gadget(
            builder,
            ordered_vpqss_item_dis[i][1].clone(),
            ordered_vpqss_item_dis[i + 1][1].clone(),
        );
        builder.connect(flag, const_list[0]);
    }
    set_belong_gedget(builder, fs_hash[4..].to_vec(), vpqss_set, lut_set, f_, t_);
    for i in 0..top_k {
        builder.register_public_input(ordered_vpqss_item_dis[i][0]);
    }

    if merkled {
        standalone_commitment_gadget(
            builder,
            query.clone(),
            root.clone(),
            codebooks_root.clone(),
            codebooks.clone(),
            ivf_center.clone(),
            ivf_roots.clone(),
            cluster_idxes,
            cluster_center.clone(),
            valids.clone(),
            itemss.clone(),
            cluster_pairs.clone(),
            vpqss.clone(),
        );
    }
}

/// Fixed-length selected ACL class table witness: `[n_acl_max]`.
pub struct ACLClassTableWitnessTargets {
    pub acl_class_ids: Vec<Target>,
    pub tenant_ids: Vec<Target>,
    pub project_ids: Vec<Target>,
    pub required_clearances: Vec<Target>,
    pub states: Vec<Target>,
    pub epochs: Vec<Target>,
    pub valids: Vec<Target>,
    pub directions: Vec<Vec<Target>>,
    pub siblings: Vec<Vec<Target>>,
}

/// Per-slot object-to-class binding Merkle witness: `[n_probe][n]`.
pub struct SlotBindingWitnessTargets {
    pub acl_class_ids: Vec<Vec<Target>>,
    pub epochs: Vec<Vec<Target>>,
    pub directions: Vec<Vec<Vec<Target>>>,
    pub siblings: Vec<Vec<Vec<Target>>>,
}

/// Per-slot one-hot class selector: `[n_probe][n][n_acl_max]`.
pub struct SlotClassSelectorTargets {
    pub selectors: Vec<Vec<Vec<Target>>>,
}

/// AuthView set-based IVF-PQ gadget with ACL-class committed authorization.
pub fn set_based_auth_ivf_pq_gadget_committed_acl_class(
    builder: &mut CircuitBuilder<F, D>,
    fs_hash: Vec<Target>,
    query: Vec<Target>,
    top_k: usize,
    root: Target,
    codebooks_root: Target,
    codebooks: Vec<Vec<Vec<Target>>>,
    ivf_center: Vec<Vec<Target>>,
    ivf_roots: Vec<Target>,
    cluster_center: Vec<Vec<Target>>,
    valids: Vec<Vec<Target>>,
    itemss: Vec<Vec<Target>>,
    cluster_pairs: Vec<Vec<Vec<Target>>>,
    vpqss: Vec<Vec<Vec<Target>>>,
    vpqss_dis: Vec<Vec<Vec<Target>>>,
    ordered_vpqss_item_dis: Vec<Vec<Target>>,
    cluster_idx_dis: Vec<Vec<Target>>,
    root_acl_class: Target,
    root_object_class_binding: Target,
    user: &UserContextTargets,
    checkpoint_epoch: Target,
    acl_table: &ACLClassTableWitnessTargets,
    bindings: &SlotBindingWitnessTargets,
    selectors: &SlotClassSelectorTargets,
    class_depth: usize,
    binding_depth: usize,
    f_: Vec<Target>,
    t_: Vec<Target>,
    merkled: bool,
) {
    builder.register_public_input(root_acl_class);
    builder.register_public_input(root_object_class_binding);

    let n_acl_max = acl_table.acl_class_ids.len();
    assert_eq!(n_acl_max, acl_table.valids.len());
    assert_eq!(n_acl_max, acl_table.directions.len());

    let M = codebooks.len();
    let K = codebooks[0].len();
    let n = valids[0].len();
    let n_probe = cluster_center.len();
    let cluster_idxes: Vec<Target> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();
    let const_list = const_gen_gadget(
        builder,
        max(max(n_probe as u64, n as u64), max(M as u64, K as u64)),
    );

    static_nn_gadget(
        builder,
        fs_hash[0],
        fs_hash[1],
        ivf_center.clone(),
        query.clone(),
        cluster_idx_dis.clone(),
    );

    let mut luts: Vec<Vec<Vec<Target>>> = Vec::with_capacity(n_probe);
    for i in 0..n_probe {
        let sub_val = vec_sub_gadget(builder, query.clone(), cluster_center[i].clone());
        luts.push(codebooks_query_gadget(builder, codebooks.clone(), sub_val));
    }

    let mut lut_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![
                    const_list[i],
                    const_list[j],
                    const_list[k],
                    luts[i][j][k],
                ]);
            }
        }
    }

    let mut class_labels: Vec<ACLClassLabelTargets> = Vec::with_capacity(n_acl_max);
    for j in 0..n_acl_max {
        class_labels.push(ACLClassLabelTargets {
            acl_class_id: acl_table.acl_class_ids[j],
            tenant_id: acl_table.tenant_ids[j],
            project_id: acl_table.project_ids[j],
            required_clearance: acl_table.required_clearances[j],
            state: acl_table.states[j],
            epoch: acl_table.epochs[j],
        });
    }

    for j in 0..n_acl_max {
        let mut path_row: Vec<Vec<Target>> = Vec::with_capacity(class_depth);
        for d in 0..class_depth {
            path_row.push(vec![
                acl_table.directions[j][d],
                acl_table.siblings[j][d],
            ]);
        }
        let class_root =
            verify_acl_class_opening_gadget(builder, &class_labels[j], path_row);
        builder.connect(class_root, root_acl_class);
    }

    let class_visibilities = acl_class_policy_once_gadget(
        builder,
        user,
        &class_labels,
        &acl_table.valids,
        checkpoint_epoch,
    );

    let mut vpqss_item_dis: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n);
    let mut vpqss_set: Vec<Vec<Target>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        for j in 0..n {
            for k in 0..M {
                vpqss_set.push(vec![
                    const_list[i],
                    const_list[k],
                    vpqss[i][j][k],
                    vpqss_dis[i][j][k],
                ]);
            }

            let binding_label = ObjectClassBindingTargets {
                cid: itemss[i][j],
                acl_class_id: bindings.acl_class_ids[i][j],
                epoch: bindings.epochs[i][j],
            };
            let mut bind_path: Vec<Vec<Target>> = Vec::with_capacity(binding_depth);
            for d in 0..binding_depth {
                bind_path.push(vec![
                    bindings.directions[i][j][d],
                    bindings.siblings[i][j][d],
                ]);
            }
            let bind_root =
                verify_object_class_binding_opening_gadget(builder, &binding_label, bind_path);
            builder.connect(bind_root, root_object_class_binding);

            acl_class_table_match_gadget(
                builder,
                valids[i][j],
                bindings.acl_class_ids[i][j],
                &acl_table.acl_class_ids,
                &acl_table.valids,
                &selectors.selectors[i][j],
            );

            let slot_visibility = inherit_slot_visibility_from_class_gadget(
                builder,
                valids[i][j],
                &selectors.selectors[i][j],
                &class_visibilities,
            );

            let curr_dis = builder.add_many(vpqss_dis[i][j].clone());
            let hat_d = auth_mask_distance_gadget(
                builder,
                valids[i][j],
                slot_visibility,
                curr_dis,
                AUTH_MASK_D_MAX,
            );
            vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
        }
    }

    set_equal_gadget(
        builder,
        fs_hash[2],
        fs_hash[3],
        vpqss_item_dis,
        ordered_vpqss_item_dis.clone(),
    );
    for i in 0..(n_probe * n - 1) {
        let flag = comp_gadget(
            builder,
            ordered_vpqss_item_dis[i][1].clone(),
            ordered_vpqss_item_dis[i + 1][1].clone(),
        );
        builder.connect(flag, const_list[0]);
    }
    set_belong_gedget(builder, fs_hash[4..].to_vec(), vpqss_set, lut_set, f_, t_);
    for i in 0..top_k {
        builder.register_public_input(ordered_vpqss_item_dis[i][0]);
    }

    if merkled {
        standalone_commitment_gadget(
            builder,
            query.clone(),
            root.clone(),
            codebooks_root.clone(),
            codebooks.clone(),
            ivf_center.clone(),
            ivf_roots.clone(),
            cluster_idxes,
            cluster_center.clone(),
            valids.clone(),
            itemss.clone(),
            cluster_pairs.clone(),
            vpqss.clone(),
        );
    }
}
