use crate::prelude::*;
use crate::utils::common_gadgets::static_lookup_gadget;

/// V3DB sentinel distance; matches `set_based.rs` (`2^62 - 1`).
pub const AUTH_MASK_D_MAX: u64 = 4611686018427387903;

/// Constrain `b` to `{0, 1}` using the project lookup gadget.
pub fn constrain_boolean_gadget(builder: &mut CircuitBuilder<F, D>, b: Target) {
    static_lookup_gadget(builder, b, vec![0, 1]);
}

/// Combined authorization gate: `g = valid * visibility` (both boolean).
pub fn auth_gate_gadget(
    builder: &mut CircuitBuilder<F, D>,
    valid: Target,
    visibility: Target,
) -> Target {
    builder.mul(valid, visibility)
}

/// Authorization-aware masked distance (Form B from Phase 2A design):
///
/// `g = valid * visibility`
/// `hat_d = g * distance + (1 - g) * d_max`
pub fn auth_mask_distance_gadget(
    builder: &mut CircuitBuilder<F, D>,
    valid: Target,
    visibility: Target,
    distance: Target,
    d_max: u64,
) -> Target {
    constrain_boolean_gadget(builder, valid);
    constrain_boolean_gadget(builder, visibility);

    let one = builder.one();
    let d_max_target = builder.constant(F::from_canonical_u64(d_max));

    let g = auth_gate_gadget(builder, valid, visibility);
    let sub_g = builder.sub(one, g);
    let gated_d = builder.mul(g, distance);
    let max_part = builder.mul(sub_g, d_max_target);
    builder.add(gated_d, max_part)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_auth_mask_case(valid: u64, visibility: u64, distance: u64, expected: u64) {
        let mut builder = make_builder();
        let valid_t = builder.add_virtual_target();
        let vis_t = builder.add_virtual_target();
        let dist_t = builder.add_virtual_target();

        let hat_d = auth_mask_distance_gadget(
            &mut builder,
            valid_t,
            vis_t,
            dist_t,
            AUTH_MASK_D_MAX,
        );
        let expected_t = builder.constant(F::from_canonical_u64(expected));
        builder.connect(hat_d, expected_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(valid_t, F::from_canonical_u64(valid))
            .expect("set valid");
        pw.set_target(vis_t, F::from_canonical_u64(visibility))
            .expect("set visibility");
        pw.set_target(dist_t, F::from_canonical_u64(distance))
            .expect("set distance");

        let proof = data.prove(pw).expect("prove");
        data.verify(proof).expect("verify");
    }

    #[test]
    fn auth_mask_valid1_vis1_passes_through_distance() {
        run_auth_mask_case(1, 1, 123, 123);
    }

    #[test]
    fn auth_mask_valid1_vis0_uses_d_max() {
        run_auth_mask_case(1, 0, 123, AUTH_MASK_D_MAX);
    }

    #[test]
    fn auth_mask_valid0_vis1_uses_d_max() {
        run_auth_mask_case(0, 1, 123, AUTH_MASK_D_MAX);
    }

    #[test]
    fn auth_mask_valid0_vis0_uses_d_max() {
        run_auth_mask_case(0, 0, 123, AUTH_MASK_D_MAX);
    }
}
