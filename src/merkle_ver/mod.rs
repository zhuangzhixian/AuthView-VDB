pub mod auth_commitment_gadget; // auth label Merkle commitment (Phase 2C-1)
pub mod auth_mask_gadget; // authorization visibility mask (Phase 2B-1)
pub mod auth_policy_gadget; // authorization policy predicate (Phase 2B-2)
pub mod slot_aligned_auth_commitment_gadget; // slot-aligned auth commitment (Phase 3B-2)
pub mod circuit_based; // circuit-only版本电路实现
pub mod circuit_based_proof; // circuit-only版本证明系统
pub mod ivf_pq_merkle; // 一些merkle库
pub mod set_based; // multi-set版本电路实现
pub mod set_based_auth; // AuthView set-based auth extension (Phase 2B-3a)
pub mod set_based_auth_proof; // AuthView set-based auth proof (Phase 2B-3a)
pub mod set_based_proof; // multi-set版本证明系统
pub mod standalone_commitment; // 单独的merkle承诺电路, 其他地方要引入
