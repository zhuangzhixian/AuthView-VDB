use crate::hash_gadgets::fs_oracle;
use crate::hash_gadgets::tree_depth;
use crate::ivf_pq_verify::proof::{convert_ft_set_i64, luts_gen_i64};
use crate::merkle_ver::auth_policy_gadget::{ACTIVE_STATE, MAX_PROJECTS, UserContextTargets};
use crate::merkle_ver::set_based_auth::{
    set_based_auth_ivf_pq_gadget_all_visible, set_based_auth_ivf_pq_gadget_committed,
    set_based_auth_ivf_pq_gadget_policy, SlotAuthLabelTargets, SlotAuthMerkleWitnessTargets,
};
use crate::merkle_ver::standalone_commitment::commitment_relevant_gen;
use crate::prelude::*;
use crate::utils::metrics::metrics_eval;

/// AuthView all-visible set-based IVF-PQ proof ($$v_x \equiv 1$$).
///
/// Witness layout and public outputs match `set_based_ivf_pq_proof`; distance
/// masking uses `auth_mask_distance_gadget` with visibility fixed to one.
pub fn set_based_auth_ivf_pq_proof_all_visible(
    query: Vec<i64>,
    ivf_center: Vec<Vec<i64>>,
    vpqss: Vec<Vec<Vec<i64>>>,
    valids: Vec<Vec<i64>>,
    itemss: Vec<Vec<i64>>,
    codebooks: Vec<Vec<Vec<i64>>>,
    ivf_roots: Vec<u64>,
    top_k: i64,
    cluster_idx_dis: Vec<Vec<i64>>,
    _ordered_vpqss_item_dis: Vec<Vec<i64>>,
    merkled: bool,
) -> Result<(f64, f64, f64, u64, u64, u64), Box<dyn std::error::Error>> {
    let d = codebooks[0][0].len();
    let D_ = query.len();
    let n_list = ivf_center.len();
    let n_probe = vpqss.len();
    let n = vpqss[0].len();
    let M = vpqss[0][0].len();
    let K = codebooks[0].len();

    let cluster_idxes: Vec<i64> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();

    let (depth, root, codebooks_root, cluster_center, cluster_pairs) = commitment_relevant_gen(
        ivf_center.clone(),
        cluster_idxes,
        vpqss.clone(),
        codebooks.clone(),
        ivf_roots.clone(),
    );

    let fs_hash = fs_oracle(
        query.clone().into_iter().map(|item| item as u64).collect(),
        7,
    );

    let centers: Vec<Vec<i64>> = (0..n_probe)
        .map(|i| ivf_center[cluster_idx_dis[i][0] as usize].clone())
        .collect();
    let luts = luts_gen_i64(&codebooks, &query, &centers);

    let mut vpqss_dis: Vec<Vec<Vec<i64>>> = Vec::with_capacity(n_probe);
    let mut vpqss_set: Vec<Vec<i64>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        let mut mat: Vec<Vec<i64>> = Vec::with_capacity(n);
        for j in 0..n {
            let mut row: Vec<i64> = Vec::with_capacity(M);
            for k in 0..M {
                let k_idx = vpqss[i][j][k];
                let curr_dis = luts[i][k][k_idx as usize];
                row.push(curr_dis);
                vpqss_set.push(vec![i as i64, k as i64, k_idx, curr_dis]);
            }
            mat.push(row);
        }
        vpqss_dis.push(mat);
    }

    let max_dis: i64 = (1_i64 << 62) - 1;
    let mut ordered_vpqss_item_dis: Vec<Vec<i64>> = Vec::with_capacity(n_probe * n);
    for i in 0..n_probe {
        for j in 0..n {
            let mut curr_dis: i64 = 0;
            for k in 0..M {
                curr_dis += vpqss_dis[i][j][k];
            }
            if valids[i][j] == 0 {
                curr_dis = max_dis;
            }
            ordered_vpqss_item_dis.push(vec![itemss[i][j], curr_dis]);
        }
    }
    ordered_vpqss_item_dis.sort_by_key(|row| row[1]);

    let mut lut_set: Vec<Vec<i64>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![i as i64, j as i64, k as i64, luts[i][j][k]]);
            }
        }
    }
    let (f_, t_) = convert_ft_set_i64(vpqss_set, lut_set, fs_hash[4]);
    let f_t_sz = f_.len();

    let mut builder = make_builder();
    let fs_hash_targets = builder.add_virtual_targets(7);
    let query_targets = builder.add_virtual_targets(D_);
    let root_targets = builder.add_virtual_target();
    let codebooks_root_targets = builder.add_virtual_target();
    let codebooks_targets = add_targets_3d(&mut builder, vec![M, K, d]);
    let ivf_center_targets = add_targets_2d(&mut builder, vec![n_list, D_]);
    let ivf_roots_targets = builder.add_virtual_targets(n_list);
    let cluster_center_targets = add_targets_2d(&mut builder, vec![n_probe, D_]);
    let valids_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let itemss_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let cluster_pairs_targets = add_targets_3d(&mut builder, vec![n_probe, depth, 2]);
    let vpqss_targets = add_targets_3d(&mut builder, vec![n_probe, n, M]);
    let vpqss_dis_targets = add_targets_3d(&mut builder, vec![n_probe, n, M]);
    let ordered_vpqss_item_dis_targets = add_targets_2d(&mut builder, vec![n_probe * n, 2]);
    let cluster_idx_dis_targets = add_targets_2d(&mut builder, vec![n_list, 2]);
    let f__targets = builder.add_virtual_targets(f_t_sz);
    let t__targets = builder.add_virtual_targets(f_t_sz);

    set_based_auth_ivf_pq_gadget_all_visible(
        &mut builder,
        fs_hash_targets.clone(),
        query_targets.clone(),
        top_k as usize,
        root_targets.clone(),
        codebooks_root_targets.clone(),
        codebooks_targets.clone(),
        ivf_center_targets.clone(),
        ivf_roots_targets.clone(),
        cluster_center_targets.clone(),
        valids_targets.clone(),
        itemss_targets.clone(),
        cluster_pairs_targets.clone(),
        vpqss_targets.clone(),
        vpqss_dis_targets.clone(),
        ordered_vpqss_item_dis_targets.clone(),
        cluster_idx_dis_targets.clone(),
        f__targets.clone(),
        t__targets.clone(),
        merkled,
    );

    public_targets_1d(&mut builder, query_targets.clone());

    let curr_time = Instant::now();
    let mut pw = PartialWitness::new();
    input_targets_1d(&mut pw, fs_hash_targets, fs_hash)?;
    input_targets_1d_sign(&mut pw, query_targets, query)?;
    input_targets_0d(&mut pw, root_targets, root)?;
    input_targets_0d(&mut pw, codebooks_root_targets, codebooks_root)?;
    input_targets_3d_sign(&mut pw, codebooks_targets, codebooks)?;
    input_targets_2d_sign(&mut pw, ivf_center_targets, ivf_center)?;
    input_targets_1d(&mut pw, ivf_roots_targets, ivf_roots)?;
    input_targets_2d_sign(&mut pw, cluster_center_targets, cluster_center)?;
    input_targets_2d_sign(&mut pw, valids_targets, valids)?;
    input_targets_2d_sign(&mut pw, itemss_targets, itemss)?;
    input_targets_3d(&mut pw, cluster_pairs_targets, cluster_pairs)?;
    input_targets_3d_sign(&mut pw, vpqss_targets, vpqss)?;
    input_targets_3d_sign(&mut pw, vpqss_dis_targets, vpqss_dis)?;
    input_targets_2d_sign(
        &mut pw,
        ordered_vpqss_item_dis_targets,
        ordered_vpqss_item_dis,
    )?;
    input_targets_2d_sign(&mut pw, cluster_idx_dis_targets, cluster_idx_dis)?;
    input_targets_1d(&mut pw, f__targets, f_)?;
    input_targets_1d(&mut pw, t__targets, t_)?;
    println!("输入witness: {:?}", curr_time.elapsed());

    let (build_time, prove_time, verify_time, proof_size, memory_used, num_gates) =
        metrics_eval(builder, pw)?;
    Ok((
        build_time,
        prove_time,
        verify_time,
        proof_size,
        memory_used,
        num_gates,
    ))
}

/// Plaintext witness helper mirroring `auth_policy_visibility_gadget` (integer tags).
pub fn policy_visibility_witness(
    user_tenant_id: u64,
    user_project_ids: &[u64; MAX_PROJECTS],
    user_project_valids: &[u64; MAX_PROJECTS],
    user_clearance: u64,
    user_epoch: u64,
    checkpoint_epoch: u64,
    object_tenant_id: u64,
    object_project_id: u64,
    object_level: u64,
    object_state: u64,
    object_epoch: u64,
) -> u64 {
    if user_tenant_id != object_tenant_id {
        return 0;
    }
    let mut project_member = false;
    for i in 0..MAX_PROJECTS {
        if user_project_valids[i] == 1 && user_project_ids[i] == object_project_id {
            project_member = true;
        }
    }
    if !project_member {
        return 0;
    }
    if user_clearance < object_level {
        return 0;
    }
    if object_state != ACTIVE_STATE {
        return 0;
    }
    if user_epoch != checkpoint_epoch || object_epoch != checkpoint_epoch {
        return 0;
    }
    1
}

/// Form B masked distance witness: `g = valid * visibility`, `hat = g*d + (1-g)*d_max`.
pub fn auth_masked_distance_witness(valid: i64, visibility: u64, distance: i64, max_dis: i64) -> i64 {
    let g = if valid != 0 && visibility != 0 { 1 } else { 0 };
    if g == 1 {
        distance
    } else {
        max_dis
    }
}

/// AuthView policy-integrated set-based IVF-PQ proof.
pub fn set_based_auth_ivf_pq_proof_policy(
    query: Vec<i64>,
    ivf_center: Vec<Vec<i64>>,
    vpqss: Vec<Vec<Vec<i64>>>,
    valids: Vec<Vec<i64>>,
    itemss: Vec<Vec<i64>>,
    codebooks: Vec<Vec<Vec<i64>>>,
    ivf_roots: Vec<u64>,
    top_k: i64,
    cluster_idx_dis: Vec<Vec<i64>>,
    user_tenant_id: u64,
    user_project_ids: Vec<u64>,
    user_project_valids: Vec<u64>,
    user_clearance: u64,
    user_epoch: u64,
    checkpoint_epoch: u64,
    object_tenant_ids: Vec<Vec<u64>>,
    object_project_ids: Vec<Vec<u64>>,
    object_levels: Vec<Vec<u64>>,
    object_states: Vec<Vec<u64>>,
    object_epochs: Vec<Vec<u64>>,
    merkled: bool,
) -> Result<(f64, f64, f64, u64, u64, u64), Box<dyn std::error::Error>> {
    let d = codebooks[0][0].len();
    let D_ = query.len();
    let n_list = ivf_center.len();
    let n_probe = vpqss.len();
    let n = vpqss[0].len();
    let M = vpqss[0][0].len();
    let K = codebooks[0].len();

    assert_eq!(user_project_ids.len(), MAX_PROJECTS);
    assert_eq!(user_project_valids.len(), MAX_PROJECTS);
    assert_eq!(object_tenant_ids.len(), n_probe);
    assert_eq!(object_project_ids.len(), n_probe);
    assert_eq!(object_levels.len(), n_probe);
    assert_eq!(object_states.len(), n_probe);
    assert_eq!(object_epochs.len(), n_probe);

    let mut user_project_arr = [0u64; MAX_PROJECTS];
    let mut user_valid_arr = [0u64; MAX_PROJECTS];
    for i in 0..MAX_PROJECTS {
        user_project_arr[i] = user_project_ids[i];
        user_valid_arr[i] = user_project_valids[i];
    }

    let cluster_idxes: Vec<i64> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();

    let (depth, root, codebooks_root, cluster_center, cluster_pairs) = commitment_relevant_gen(
        ivf_center.clone(),
        cluster_idxes,
        vpqss.clone(),
        codebooks.clone(),
        ivf_roots.clone(),
    );

    let fs_hash = fs_oracle(
        query.clone().into_iter().map(|item| item as u64).collect(),
        7,
    );

    let centers: Vec<Vec<i64>> = (0..n_probe)
        .map(|i| ivf_center[cluster_idx_dis[i][0] as usize].clone())
        .collect();
    let luts = luts_gen_i64(&codebooks, &query, &centers);

    let mut vpqss_dis: Vec<Vec<Vec<i64>>> = Vec::with_capacity(n_probe);
    let mut vpqss_set: Vec<Vec<i64>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        let mut mat: Vec<Vec<i64>> = Vec::with_capacity(n);
        for j in 0..n {
            let mut row: Vec<i64> = Vec::with_capacity(M);
            for k in 0..M {
                let k_idx = vpqss[i][j][k];
                let curr_dis = luts[i][k][k_idx as usize];
                row.push(curr_dis);
                vpqss_set.push(vec![i as i64, k as i64, k_idx, curr_dis]);
            }
            mat.push(row);
        }
        vpqss_dis.push(mat);
    }

    let max_dis: i64 = (1_i64 << 62) - 1;
    let mut ordered_vpqss_item_dis: Vec<Vec<i64>> = Vec::with_capacity(n_probe * n);
    for i in 0..n_probe {
        for j in 0..n {
            let mut curr_dis: i64 = 0;
            for k in 0..M {
                curr_dis += vpqss_dis[i][j][k];
            }
            let visibility = policy_visibility_witness(
                user_tenant_id,
                &user_project_arr,
                &user_valid_arr,
                user_clearance,
                user_epoch,
                checkpoint_epoch,
                object_tenant_ids[i][j],
                object_project_ids[i][j],
                object_levels[i][j],
                object_states[i][j],
                object_epochs[i][j],
            );
            let hat_d = auth_masked_distance_witness(
                valids[i][j],
                visibility,
                curr_dis,
                max_dis,
            );
            ordered_vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
        }
    }
    ordered_vpqss_item_dis.sort_by_key(|row| row[1]);

    let mut lut_set: Vec<Vec<i64>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![i as i64, j as i64, k as i64, luts[i][j][k]]);
            }
        }
    }
    let (f_, t_) = convert_ft_set_i64(vpqss_set, lut_set, fs_hash[4]);
    let f_t_sz = f_.len();

    let mut builder = make_builder();
    let fs_hash_targets = builder.add_virtual_targets(7);
    let query_targets = builder.add_virtual_targets(D_);
    let root_targets = builder.add_virtual_target();
    let codebooks_root_targets = builder.add_virtual_target();
    let codebooks_targets = add_targets_3d(&mut builder, vec![M, K, d]);
    let ivf_center_targets = add_targets_2d(&mut builder, vec![n_list, D_]);
    let ivf_roots_targets = builder.add_virtual_targets(n_list);
    let cluster_center_targets = add_targets_2d(&mut builder, vec![n_probe, D_]);
    let valids_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let itemss_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let cluster_pairs_targets = add_targets_3d(&mut builder, vec![n_probe, depth, 2]);
    let vpqss_targets = add_targets_3d(&mut builder, vec![n_probe, n, M]);
    let vpqss_dis_targets = add_targets_3d(&mut builder, vec![n_probe, n, M]);
    let ordered_vpqss_item_dis_targets = add_targets_2d(&mut builder, vec![n_probe * n, 2]);
    let cluster_idx_dis_targets = add_targets_2d(&mut builder, vec![n_list, 2]);
    let f__targets = builder.add_virtual_targets(f_t_sz);
    let t__targets = builder.add_virtual_targets(f_t_sz);

    let user_tenant_target = builder.add_virtual_target();
    let user_project_targets: [Target; MAX_PROJECTS] =
        std::array::from_fn(|_| builder.add_virtual_target());
    let user_project_valid_targets: [Target; MAX_PROJECTS] =
        std::array::from_fn(|_| builder.add_virtual_target());
    let user_clearance_target = builder.add_virtual_target();
    let user_epoch_target = builder.add_virtual_target();
    let checkpoint_epoch_target = builder.add_virtual_target();

    let object_tenant_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_project_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_level_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_state_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_epoch_targets = add_targets_2d(&mut builder, vec![n_probe, n]);

    let user_targets = UserContextTargets {
        user_tenant_id: user_tenant_target,
        user_project_ids: user_project_targets,
        user_project_valids: user_project_valid_targets,
        user_clearance: user_clearance_target,
        user_epoch: user_epoch_target,
    };
    let slot_labels = SlotAuthLabelTargets {
        object_tenant_ids: object_tenant_targets.clone(),
        object_project_ids: object_project_targets.clone(),
        object_levels: object_level_targets.clone(),
        object_states: object_state_targets.clone(),
        object_epochs: object_epoch_targets.clone(),
    };

    set_based_auth_ivf_pq_gadget_policy(
        &mut builder,
        fs_hash_targets.clone(),
        query_targets.clone(),
        top_k as usize,
        root_targets.clone(),
        codebooks_root_targets.clone(),
        codebooks_targets.clone(),
        ivf_center_targets.clone(),
        ivf_roots_targets.clone(),
        cluster_center_targets.clone(),
        valids_targets.clone(),
        itemss_targets.clone(),
        cluster_pairs_targets.clone(),
        vpqss_targets.clone(),
        vpqss_dis_targets.clone(),
        ordered_vpqss_item_dis_targets.clone(),
        cluster_idx_dis_targets.clone(),
        &user_targets,
        checkpoint_epoch_target,
        &slot_labels,
        f__targets.clone(),
        t__targets.clone(),
        merkled,
    );

    public_targets_1d(&mut builder, query_targets.clone());

    let curr_time = Instant::now();
    let mut pw = PartialWitness::new();
    input_targets_1d(&mut pw, fs_hash_targets, fs_hash)?;
    input_targets_1d_sign(&mut pw, query_targets, query)?;
    input_targets_0d(&mut pw, root_targets, root)?;
    input_targets_0d(&mut pw, codebooks_root_targets, codebooks_root)?;
    input_targets_3d_sign(&mut pw, codebooks_targets, codebooks)?;
    input_targets_2d_sign(&mut pw, ivf_center_targets, ivf_center)?;
    input_targets_1d(&mut pw, ivf_roots_targets, ivf_roots)?;
    input_targets_2d_sign(&mut pw, cluster_center_targets, cluster_center)?;
    input_targets_2d_sign(&mut pw, valids_targets, valids)?;
    input_targets_2d_sign(&mut pw, itemss_targets, itemss)?;
    input_targets_3d(&mut pw, cluster_pairs_targets, cluster_pairs)?;
    input_targets_3d_sign(&mut pw, vpqss_targets, vpqss)?;
    input_targets_3d_sign(&mut pw, vpqss_dis_targets, vpqss_dis)?;
    input_targets_2d_sign(
        &mut pw,
        ordered_vpqss_item_dis_targets,
        ordered_vpqss_item_dis,
    )?;
    input_targets_2d_sign(&mut pw, cluster_idx_dis_targets, cluster_idx_dis)?;
    input_targets_1d(&mut pw, f__targets, f_)?;
    input_targets_1d(&mut pw, t__targets, t_)?;

    input_targets_0d(&mut pw, user_tenant_target, user_tenant_id)?;
    for i in 0..MAX_PROJECTS {
        input_targets_0d(&mut pw, user_project_targets[i], user_project_ids[i])?;
        input_targets_0d(&mut pw, user_project_valid_targets[i], user_project_valids[i])?;
    }
    input_targets_0d(&mut pw, user_clearance_target, user_clearance)?;
    input_targets_0d(&mut pw, user_epoch_target, user_epoch)?;
    input_targets_0d(&mut pw, checkpoint_epoch_target, checkpoint_epoch)?;

    let object_tenant_u64: Vec<Vec<u64>> = object_tenant_ids.clone();
    let object_project_u64: Vec<Vec<u64>> = object_project_ids.clone();
    let object_level_u64: Vec<Vec<u64>> = object_levels.clone();
    let object_state_u64: Vec<Vec<u64>> = object_states.clone();
    let object_epoch_u64: Vec<Vec<u64>> = object_epochs.clone();
    input_targets_2d(&mut pw, object_tenant_targets, object_tenant_u64)?;
    input_targets_2d(&mut pw, object_project_targets, object_project_u64)?;
    input_targets_2d(&mut pw, object_level_targets, object_level_u64)?;
    input_targets_2d(&mut pw, object_state_targets, object_state_u64)?;
    input_targets_2d(&mut pw, object_epoch_targets, object_epoch_u64)?;
    println!("输入witness: {:?}", curr_time.elapsed());

    let (build_time, prove_time, verify_time, proof_size, memory_used, num_gates) =
        metrics_eval(builder, pw)?;
    Ok((
        build_time,
        prove_time,
        verify_time,
        proof_size,
        memory_used,
        num_gates,
    ))
}

fn auth_tree_padded_size(n_slots: usize) -> usize {
    let mut p = 1;
    while p < n_slots {
        p *= 2;
    }
    p
}

/// AuthView committed-auth set-based IVF-PQ proof.
pub fn set_based_auth_ivf_pq_proof_committed(
    query: Vec<i64>,
    ivf_center: Vec<Vec<i64>>,
    vpqss: Vec<Vec<Vec<i64>>>,
    valids: Vec<Vec<i64>>,
    itemss: Vec<Vec<i64>>,
    codebooks: Vec<Vec<Vec<i64>>>,
    ivf_roots: Vec<u64>,
    top_k: i64,
    cluster_idx_dis: Vec<Vec<i64>>,
    root_auth: u64,
    user_tenant_id: u64,
    user_project_ids: Vec<u64>,
    user_project_valids: Vec<u64>,
    user_clearance: u64,
    user_epoch: u64,
    checkpoint_epoch: u64,
    object_tenant_ids: Vec<Vec<u64>>,
    object_project_ids: Vec<Vec<u64>>,
    object_levels: Vec<Vec<u64>>,
    object_states: Vec<Vec<u64>>,
    object_epochs: Vec<Vec<u64>>,
    auth_path_directions: Vec<Vec<Vec<u64>>>,
    auth_path_siblings: Vec<Vec<Vec<u64>>>,
    merkled: bool,
) -> Result<(f64, f64, f64, u64, u64, u64), Box<dyn std::error::Error>> {
    let d = codebooks[0][0].len();
    let D_ = query.len();
    let n_list = ivf_center.len();
    let n_probe = vpqss.len();
    let n = vpqss[0].len();
    let M = vpqss[0][0].len();
    let K = codebooks[0].len();

    assert_eq!(user_project_ids.len(), MAX_PROJECTS);
    assert_eq!(user_project_valids.len(), MAX_PROJECTS);
    assert_eq!(object_tenant_ids.len(), n_probe);
    assert_eq!(auth_path_directions.len(), n_probe);
    assert_eq!(auth_path_siblings.len(), n_probe);

    let auth_depth = tree_depth(auth_tree_padded_size(n_probe * n));
    assert_eq!(auth_path_directions[0][0].len(), auth_depth);
    assert_eq!(auth_path_siblings[0][0].len(), auth_depth);

    let mut user_project_arr = [0u64; MAX_PROJECTS];
    let mut user_valid_arr = [0u64; MAX_PROJECTS];
    for i in 0..MAX_PROJECTS {
        user_project_arr[i] = user_project_ids[i];
        user_valid_arr[i] = user_project_valids[i];
    }

    let cluster_idxes: Vec<i64> = (0..n_probe)
        .map(|i| cluster_idx_dis[i][0].clone())
        .collect();

    let (depth, root, codebooks_root, cluster_center, cluster_pairs) = commitment_relevant_gen(
        ivf_center.clone(),
        cluster_idxes,
        vpqss.clone(),
        codebooks.clone(),
        ivf_roots.clone(),
    );

    let fs_hash = fs_oracle(
        query.clone().into_iter().map(|item| item as u64).collect(),
        7,
    );

    let centers: Vec<Vec<i64>> = (0..n_probe)
        .map(|i| ivf_center[cluster_idx_dis[i][0] as usize].clone())
        .collect();
    let luts = luts_gen_i64(&codebooks, &query, &centers);

    let mut vpqss_dis: Vec<Vec<Vec<i64>>> = Vec::with_capacity(n_probe);
    let mut vpqss_set: Vec<Vec<i64>> = Vec::with_capacity(n_probe * n * M);
    for i in 0..n_probe {
        let mut mat: Vec<Vec<i64>> = Vec::with_capacity(n);
        for j in 0..n {
            let mut row: Vec<i64> = Vec::with_capacity(M);
            for k in 0..M {
                let k_idx = vpqss[i][j][k];
                let curr_dis = luts[i][k][k_idx as usize];
                row.push(curr_dis);
                vpqss_set.push(vec![i as i64, k as i64, k_idx, curr_dis]);
            }
            mat.push(row);
        }
        vpqss_dis.push(mat);
    }

    let max_dis: i64 = (1_i64 << 62) - 1;
    let mut ordered_vpqss_item_dis: Vec<Vec<i64>> = Vec::with_capacity(n_probe * n);
    for i in 0..n_probe {
        for j in 0..n {
            let mut curr_dis: i64 = 0;
            for k in 0..M {
                curr_dis += vpqss_dis[i][j][k];
            }
            let visibility = policy_visibility_witness(
                user_tenant_id,
                &user_project_arr,
                &user_valid_arr,
                user_clearance,
                user_epoch,
                checkpoint_epoch,
                object_tenant_ids[i][j],
                object_project_ids[i][j],
                object_levels[i][j],
                object_states[i][j],
                object_epochs[i][j],
            );
            let hat_d = auth_masked_distance_witness(
                valids[i][j],
                visibility,
                curr_dis,
                max_dis,
            );
            ordered_vpqss_item_dis.push(vec![itemss[i][j], hat_d]);
        }
    }
    ordered_vpqss_item_dis.sort_by_key(|row| row[1]);

    let mut lut_set: Vec<Vec<i64>> = Vec::with_capacity(n_probe * M * K);
    for i in 0..n_probe {
        for j in 0..M {
            for k in 0..K {
                lut_set.push(vec![i as i64, j as i64, k as i64, luts[i][j][k]]);
            }
        }
    }
    let (f_, t_) = convert_ft_set_i64(vpqss_set, lut_set, fs_hash[4]);
    let f_t_sz = f_.len();

    let mut builder = make_builder();
    let fs_hash_targets = builder.add_virtual_targets(7);
    let query_targets = builder.add_virtual_targets(D_);
    let root_targets = builder.add_virtual_target();
    let codebooks_root_targets = builder.add_virtual_target();
    let codebooks_targets = add_targets_3d(&mut builder, vec![M, K, d]);
    let ivf_center_targets = add_targets_2d(&mut builder, vec![n_list, D_]);
    let ivf_roots_targets = builder.add_virtual_targets(n_list);
    let cluster_center_targets = add_targets_2d(&mut builder, vec![n_probe, D_]);
    let valids_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let itemss_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let cluster_pairs_targets = add_targets_3d(&mut builder, vec![n_probe, depth, 2]);
    let vpqss_targets = add_targets_3d(&mut builder, vec![n_probe, n, M]);
    let vpqss_dis_targets = add_targets_3d(&mut builder, vec![n_probe, n, M]);
    let ordered_vpqss_item_dis_targets = add_targets_2d(&mut builder, vec![n_probe * n, 2]);
    let cluster_idx_dis_targets = add_targets_2d(&mut builder, vec![n_list, 2]);
    let f__targets = builder.add_virtual_targets(f_t_sz);
    let t__targets = builder.add_virtual_targets(f_t_sz);

    let root_auth_target = builder.add_virtual_target();
    let user_tenant_target = builder.add_virtual_target();
    let user_project_targets: [Target; MAX_PROJECTS] =
        std::array::from_fn(|_| builder.add_virtual_target());
    let user_project_valid_targets: [Target; MAX_PROJECTS] =
        std::array::from_fn(|_| builder.add_virtual_target());
    let user_clearance_target = builder.add_virtual_target();
    let user_epoch_target = builder.add_virtual_target();
    let checkpoint_epoch_target = builder.add_virtual_target();

    let object_tenant_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_project_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_level_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_state_targets = add_targets_2d(&mut builder, vec![n_probe, n]);
    let object_epoch_targets = add_targets_2d(&mut builder, vec![n_probe, n]);

    let auth_dir_targets = add_targets_3d(&mut builder, vec![n_probe, n, auth_depth]);
    let auth_sib_targets = add_targets_3d(&mut builder, vec![n_probe, n, auth_depth]);

    let user_targets = UserContextTargets {
        user_tenant_id: user_tenant_target,
        user_project_ids: user_project_targets,
        user_project_valids: user_project_valid_targets,
        user_clearance: user_clearance_target,
        user_epoch: user_epoch_target,
    };
    let slot_labels = SlotAuthLabelTargets {
        object_tenant_ids: object_tenant_targets.clone(),
        object_project_ids: object_project_targets.clone(),
        object_levels: object_level_targets.clone(),
        object_states: object_state_targets.clone(),
        object_epochs: object_epoch_targets.clone(),
    };
    let auth_paths = SlotAuthMerkleWitnessTargets {
        directions: auth_dir_targets.clone(),
        siblings: auth_sib_targets.clone(),
    };

    set_based_auth_ivf_pq_gadget_committed(
        &mut builder,
        fs_hash_targets.clone(),
        query_targets.clone(),
        top_k as usize,
        root_targets.clone(),
        codebooks_root_targets.clone(),
        codebooks_targets.clone(),
        ivf_center_targets.clone(),
        ivf_roots_targets.clone(),
        cluster_center_targets.clone(),
        valids_targets.clone(),
        itemss_targets.clone(),
        cluster_pairs_targets.clone(),
        vpqss_targets.clone(),
        vpqss_dis_targets.clone(),
        ordered_vpqss_item_dis_targets.clone(),
        cluster_idx_dis_targets.clone(),
        root_auth_target,
        &user_targets,
        checkpoint_epoch_target,
        &slot_labels,
        &auth_paths,
        auth_depth,
        f__targets.clone(),
        t__targets.clone(),
        merkled,
    );

    public_targets_1d(&mut builder, query_targets.clone());

    let curr_time = Instant::now();
    let mut pw = PartialWitness::new();
    input_targets_1d(&mut pw, fs_hash_targets, fs_hash)?;
    input_targets_1d_sign(&mut pw, query_targets, query)?;
    input_targets_0d(&mut pw, root_targets, root)?;
    input_targets_0d(&mut pw, codebooks_root_targets, codebooks_root)?;
    input_targets_3d_sign(&mut pw, codebooks_targets, codebooks)?;
    input_targets_2d_sign(&mut pw, ivf_center_targets, ivf_center)?;
    input_targets_1d(&mut pw, ivf_roots_targets, ivf_roots)?;
    input_targets_2d_sign(&mut pw, cluster_center_targets, cluster_center)?;
    input_targets_2d_sign(&mut pw, valids_targets, valids)?;
    input_targets_2d_sign(&mut pw, itemss_targets, itemss)?;
    input_targets_3d(&mut pw, cluster_pairs_targets, cluster_pairs)?;
    input_targets_3d_sign(&mut pw, vpqss_targets, vpqss)?;
    input_targets_3d_sign(&mut pw, vpqss_dis_targets, vpqss_dis)?;
    input_targets_2d_sign(
        &mut pw,
        ordered_vpqss_item_dis_targets,
        ordered_vpqss_item_dis,
    )?;
    input_targets_2d_sign(&mut pw, cluster_idx_dis_targets, cluster_idx_dis)?;
    input_targets_1d(&mut pw, f__targets, f_)?;
    input_targets_1d(&mut pw, t__targets, t_)?;

    input_targets_0d(&mut pw, root_auth_target, root_auth)?;
    input_targets_0d(&mut pw, user_tenant_target, user_tenant_id)?;
    for i in 0..MAX_PROJECTS {
        input_targets_0d(&mut pw, user_project_targets[i], user_project_ids[i])?;
        input_targets_0d(&mut pw, user_project_valid_targets[i], user_project_valids[i])?;
    }
    input_targets_0d(&mut pw, user_clearance_target, user_clearance)?;
    input_targets_0d(&mut pw, user_epoch_target, user_epoch)?;
    input_targets_0d(&mut pw, checkpoint_epoch_target, checkpoint_epoch)?;

    input_targets_2d(&mut pw, object_tenant_targets, object_tenant_ids)?;
    input_targets_2d(&mut pw, object_project_targets, object_project_ids)?;
    input_targets_2d(&mut pw, object_level_targets, object_levels)?;
    input_targets_2d(&mut pw, object_state_targets, object_states)?;
    input_targets_2d(&mut pw, object_epoch_targets, object_epochs)?;
    input_targets_3d(&mut pw, auth_dir_targets, auth_path_directions)?;
    input_targets_3d(&mut pw, auth_sib_targets, auth_path_siblings)?;
    println!("输入witness: {:?}", curr_time.elapsed());

    let (build_time, prove_time, verify_time, proof_size, memory_used, num_gates) =
        metrics_eval(builder, pw)?;
    Ok((
        build_time,
        prove_time,
        verify_time,
        proof_size,
        memory_used,
        num_gates,
    ))
}
