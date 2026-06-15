use crate::hash_gadgets::fs_oracle;
use crate::ivf_pq_verify::proof::{convert_ft_set_i64, luts_gen_i64};
use crate::merkle_ver::set_based_auth::set_based_auth_ivf_pq_gadget_all_visible;
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
