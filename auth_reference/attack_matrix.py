"""Attack matrix registry for Phase 4C RQ1 evaluation (CSV + docs)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackMatrixRow:
    attack_id: str
    attack_name: str
    security_property: str
    layer: str
    proof_path: str
    tested_by: str
    expected_result: str
    observed_result: str
    status: str
    notes: str


# Static registry; observed_result/status updated by scripts/write_attack_matrix_summary.py
# after pytest, or maintained to match test_auth_attack_matrix.py coverage.
ATTACK_MATRIX: tuple[AttackMatrixRow, ...] = (
    AttackMatrixRow(
        "A1",
        "post_filter_insufficiency",
        "Retrieval Soundness under Authorization",
        "plaintext",
        "n/a",
        "tests/test_auth_attack_matrix.py::test_a1_post_filter_insufficiency",
        "authorized_topk != post_filter_topk on contrast fixture",
        "differs; post-filter returns empty while auth returns visible cids",
        "passed",
        "Semantic gap; V3DB baseline has no auth-view semantics",
    ),
    AttackMatrixRow(
        "A2",
        "unauthorized_label_forgery_tenant",
        "View Consistency; Commitment Binding",
        "zk_api",
        "auth_committed",
        "tests/test_auth_attack_matrix.py::test_a2_committed_forged_tenant_zk_fails",
        "proof generation/verify fails",
        "RuntimeError from py_set_based_auth_committed_with_merkle",
        "passed",
        "Witness tenant field tampered; Merkle leaf unchanged",
    ),
    AttackMatrixRow(
        "A3",
        "auth_merkle_path_substitution",
        "Commitment Binding",
        "zk_api",
        "auth_committed",
        "tests/test_auth_attack_matrix.py::test_a3_committed_wrong_auth_path_zk_fails",
        "proof fails",
        "RuntimeError on corrupted auth_path_siblings",
        "passed",
        "Global per-slot path sibling flip",
    ),
    AttackMatrixRow(
        "A4",
        "visibility_label_field_forgery",
        "View Consistency; Authorized Distance Soundness",
        "zk_api",
        "auth_committed",
        "tests/test_auth_attack_matrix.py::test_a4_committed_forged_level_zk_fails",
        "proof fails",
        "RuntimeError on object_level tamper vs Merkle leaf",
        "passed",
        "Policy uses same targets as commitment leaf",
    ),
    AttackMatrixRow(
        "A5",
        "wrong_root_auth_label_mixing",
        "Commitment Binding; Checkpoint Binding (pinned root)",
        "zk_api",
        "auth_committed",
        "tests/test_auth_attack_matrix.py::test_a5_committed_root_label_mixing_zk_fails",
        "proof fails",
        "RuntimeError when root_auth from alternate label set",
        "passed",
        "Paths/labels from tree A, root_auth from tree B",
    ),
    AttackMatrixRow(
        "A6",
        "cross_list_graft",
        "Layout Binding; list_id binding",
        "zk_api",
        "auth_slot_aligned",
        "tests/test_auth_attack_matrix.py::test_a6_slot_aligned_cross_list_graft_zk_fails",
        "proof fails",
        "RuntimeError on grafted top path/list root",
        "passed",
        "list_id binding constrains top path to probe list_id",
    ),
    AttackMatrixRow(
        "A7",
        "wrong_intra_list_path",
        "Commitment Binding",
        "zk_api",
        "auth_slot_aligned",
        "tests/test_auth_attack_matrix.py::test_a7_slot_aligned_wrong_intra_path_zk_fails",
        "proof fails",
        "RuntimeError on intra_path_siblings corruption",
        "passed",
        "Slot opening must match slot label under list root",
    ),
    AttackMatrixRow(
        "A8",
        "wrong_top_level_path",
        "Commitment Binding",
        "zk_api",
        "auth_slot_aligned",
        "tests/test_auth_attack_matrix.py::test_a8_slot_aligned_wrong_top_path_zk_fails",
        "proof fails",
        "RuntimeError on top_path_siblings corruption",
        "passed",
        "List root must open to pinned root_auth",
    ),
    AttackMatrixRow(
        "A9",
        "top_k_order_manipulation",
        "Top-k Soundness; Retrieval Soundness under Authorization",
        "circuit",
        "auth_committed",
        "set_equal_gadget + sortedness constraints (existing circuit)",
        "non-minimal or permuted witness fails",
        "ordered witness computed inside proof; not injectable via PyO3",
        "partially_covered",
        "No direct API to supply adversarial ordered list; circuit enforces multiset+sort",
    ),
    AttackMatrixRow(
        "A10",
        "candidate_omission",
        "Candidate Coverage",
        "circuit",
        "auth_committed",
        "standalone_commitment + fixed-shape buffers (existing circuit)",
        "omitted slot breaks content/auth witness",
        "full n_probe x n buffers required at API boundary",
        "partially_covered",
        "Omission attack tested at plaintext coverage check only",
    ),
    AttackMatrixRow(
        "A11",
        "stale_root_freshness",
        "Checkpoint Binding (global freshness)",
        "protocol",
        "all",
        "documented limitation",
        "not prevented by local proof alone",
        "verifier must pin root_auth; freshness via external registry",
        "out_of_scope",
        "Future: checkpoint registry / transparency log",
    ),
    AttackMatrixRow(
        "A12",
        "pinned_user_context_mismatch",
        "View Consistency",
        "zk_api",
        "auth_committed",
        "tests/test_auth_attack_matrix.py::test_a12_committed_user_clearance_mismatch_zk_fails",
        "proof fails when witness label fields disagree with Merkle under pinned user context",
        "RuntimeError on clearance tamper vs Merkle leaf",
        "passed",
        "Verifier-pinned gamma_U; prover cannot raise clearance in witness without Merkle",
    ),
    AttackMatrixRow(
        "A2b",
        "unauthorized_label_forgery_tenant_slot_aligned",
        "View Consistency; Commitment Binding",
        "zk_api",
        "auth_slot_aligned",
        "tests/test_auth_attack_matrix.py::test_a2b_slot_aligned_forged_tenant_zk_fails",
        "proof fails",
        "RuntimeError from py_set_based_auth_slot_aligned_with_merkle",
        "passed",
        "Same as A2 under two-level auth tree",
    ),
    AttackMatrixRow(
        "A10p",
        "candidate_omission_plaintext",
        "Candidate Coverage",
        "plaintext",
        "n/a",
        "tests/test_auth_reference.py::test_skipped_candidate_fails_coverage",
        "coverage check raises on subset",
        "ValueError on skipped candidate set",
        "plaintext_only",
        "Plaintext oracle only; ZK relies on full buffer shape",
    ),
    AttackMatrixRow(
        "A4p",
        "visibility_manipulation_plaintext",
        "Authorized Distance Soundness",
        "plaintext",
        "n/a",
        "tests/test_auth_reference.py::test_visibility_manipulation_detected",
        "oracle detects v_x tamper",
        "ValueError from verify_visibility_consistency",
        "plaintext_only",
        "Reference helper; committed ZK covered by A4",
    ),
)

CSV_FIELDS = (
    "attack_id",
    "attack_name",
    "security_property",
    "layer",
    "proof_path",
    "tested_by",
    "expected_result",
    "observed_result",
    "status",
    "notes",
)
