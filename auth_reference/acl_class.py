"""ACL-class compression plaintext reference (Phase 5A).

Multiple candidate slots share one ACL class. Policy visibility is evaluated once
per unique class; each slot inherits visibility via cid -> acl_class_id binding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from auth_reference.policy import ACTIVE_STATE, evaluate_policy
from auth_reference.records import (
    AuthLabel,
    CandidateRecord,
    Checkpoint,
    ScoredCandidate,
    UserContext,
)
from auth_reference.reference import (
    DEFAULT_D_MAX,
    authorized_topk,
    check_candidate_coverage,
    compute_masked_distance,
    run_authorized_reference,
    score_candidate,
)

# ZK-oriented id maps (aligned with v3db_adapter); plaintext policy uses strings.
TENANT_ID_TO_NAME: dict[int, str] = {1: "acme", 2: "other-tenant"}
PROJECT_ID_TO_NAME: dict[int, str] = {10: "proj-a", 11: "proj-b"}
TENANT_NAME_TO_ID: dict[str, int] = {v: k for k, v in TENANT_ID_TO_NAME.items()}
# Plaintext fixtures use "other"; ZK adapter uses "other-tenant".
TENANT_NAME_TO_ID.setdefault("other", TENANT_NAME_TO_ID["other-tenant"])
PROJECT_NAME_TO_ID: dict[str, int] = {v: k for k, v in PROJECT_ID_TO_NAME.items()}

# Plaintext cost-model unit weights (relative; for N_acl/N_sel comparison).
POLICY_EVAL_UNIT = 1
OBJECT_LABEL_OPEN_UNIT = 1
ACL_CLASS_OPEN_UNIT = 1
OBJECT_BINDING_OPEN_UNIT = 1


@dataclass(frozen=True)
class ACLClassLabel:
    """Dynamic ACL state at checkpoint sigma, keyed by acl_class_id."""

    acl_class_id: int
    tenant_id: int
    project_id: int
    required_clearance: int
    state: str = ACTIVE_STATE
    epoch: int = 0

    @property
    def tenant(self) -> str:
        return TENANT_ID_TO_NAME[self.tenant_id]

    @property
    def project(self) -> str:
        return PROJECT_ID_TO_NAME[self.project_id]

    def to_auth_label(self) -> AuthLabel:
        """Expand class label to object-level AuthLabel (identity fields omitted)."""
        return AuthLabel(
            tenant=self.tenant,
            project=self.project,
            level=self.required_clearance,
            state=self.state,
            epoch=self.epoch,
        )


@dataclass(frozen=True)
class ObjectClassBinding:
    """Static binding from content object cid to ACL class."""

    cid: int
    acl_class_id: int
    epoch: int = 0


@dataclass
class ACLClassView:
    """Compressed authorization view over selected candidates."""

    selected: list[CandidateRecord]
    bindings: dict[int, ObjectClassBinding]
    class_labels: dict[int, ACLClassLabel]
    class_visibility: dict[int, int]
    cid_visibility: dict[int, int]


@dataclass
class ACLCompressionCost:
    """Relative cost counters for object-level vs ACL-class paths."""

    n_sel: int
    n_acl: int
    n_vis: int
    acl_ratio: float
    visible_ratio: float
    object_level_policy_evals: int
    acl_class_policy_evals: int
    estimated_policy_eval_saved: int
    estimated_cost_object_level: int
    estimated_cost_acl_class: int


@dataclass
class ACLCompressedReferenceResult:
    """Output of authorized_topk_acl_compressed."""

    top_k_cids: list[int]
    scored: list[ScoredCandidate]
    view: ACLClassView
    cost: ACLCompressionCost
    checkpoint: Checkpoint
    user: UserContext


def evaluate_acl_class_visibility(
    user: UserContext,
    acl_class: ACLClassLabel,
    checkpoint: Checkpoint,
) -> int:
    """P(gamma_U, Lambda_c, sigma) evaluated once per ACL class."""
    return 1 if evaluate_policy(user, acl_class.to_auth_label(), checkpoint) else 0


def acl_class_label_from_auth_label(
    acl_class_id: int,
    label: AuthLabel,
) -> ACLClassLabel:
    """Derive ACL class from an object-level AuthLabel (for test fixtures)."""
    tenant_id = TENANT_NAME_TO_ID.get(label.tenant)
    project_id = PROJECT_NAME_TO_ID.get(label.project)
    if tenant_id is None or project_id is None:
        raise ValueError(
            f"unknown tenant/project for ACL encoding: {label.tenant}/{label.project}"
        )
    return ACLClassLabel(
        acl_class_id=acl_class_id,
        tenant_id=tenant_id,
        project_id=project_id,
        required_clearance=label.level,
        state=label.state,
        epoch=label.epoch,
    )


def object_binding_from_label(cid: int, acl_class_id: int, label: AuthLabel) -> ObjectClassBinding:
    return ObjectClassBinding(cid=cid, acl_class_id=acl_class_id, epoch=label.epoch)


def expand_auth_label_for_cid(
    binding: ObjectClassBinding,
    class_labels: dict[int, ACLClassLabel],
) -> AuthLabel:
    """Reconstruct object-level label from binding + class state."""
    acl_class = class_labels[binding.acl_class_id]
    return acl_class.to_auth_label()


def build_acl_class_view(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
) -> ACLClassView:
    """Build per-class and per-cid visibility maps over selected candidates."""
    selected = [c for c in candidates if c.valid]
    class_visibility: dict[int, int] = {}
    cid_visibility: dict[int, int] = {}

    used_class_ids: set[int] = set()
    for c in selected:
        binding = bindings.get(c.cid)
        if binding is None:
            raise ValueError(f"missing binding for cid={c.cid}")
        if binding.acl_class_id not in class_labels:
            raise ValueError(
                f"missing ACL class label for class_id={binding.acl_class_id}"
            )
        used_class_ids.add(binding.acl_class_id)

    for class_id in used_class_ids:
        class_visibility[class_id] = evaluate_acl_class_visibility(
            user, class_labels[class_id], checkpoint
        )

    for c in selected:
        binding = bindings[c.cid]
        cid_visibility[c.cid] = class_visibility[binding.acl_class_id]

    return ACLClassView(
        selected=selected,
        bindings=bindings,
        class_labels=class_labels,
        class_visibility=class_visibility,
        cid_visibility=cid_visibility,
    )


def score_candidate_acl_compressed(
    candidate: CandidateRecord,
    view: ACLClassView,
    user: UserContext,
    checkpoint: Checkpoint,
    d_max: int = DEFAULT_D_MAX,
) -> ScoredCandidate:
    """Score one slot using inherited class visibility."""
    visibility = view.cid_visibility[candidate.cid]
    hat, masked = compute_masked_distance(
        candidate.distance, candidate.valid, visibility, d_max
    )
    label = expand_auth_label_for_cid(view.bindings[candidate.cid], view.class_labels)
    return ScoredCandidate(
        cid=candidate.cid,
        list_id=candidate.list_id,
        slot_id=candidate.slot_id,
        valid=candidate.valid,
        distance=candidate.distance,
        label=label,
        visibility=visibility,
        hat_distance=hat,
        masked_distance=masked,
    )


def count_unique_acl_classes_in_candidates(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
) -> int:
    """N_acl over valid selected slots."""
    class_ids: set[int] = set()
    for c in candidates:
        if not c.valid:
            continue
        binding = bindings.get(c.cid)
        if binding is None:
            continue
        class_ids.add(binding.acl_class_id)
    return len(class_ids)


def estimate_acl_compression_cost(
    n_sel: int,
    n_acl: int,
    n_vis: int,
) -> ACLCompressionCost:
    """
    Relative cost model for plaintext comparison.

    Object-level path: N_sel policy evals + N_sel per-object label openings.
    ACL-class path: N_acl class policy evals + N_acl class openings
                    + N_sel object-to-class binding openings.
    """
    if n_sel <= 0:
        raise ValueError("n_sel must be positive")
    if n_acl <= 0 or n_acl > n_sel:
        raise ValueError("n_acl must satisfy 1 <= n_acl <= n_sel")

    object_policy = n_sel * POLICY_EVAL_UNIT
    acl_policy = n_acl * POLICY_EVAL_UNIT
    cost_object = object_policy + n_sel * OBJECT_LABEL_OPEN_UNIT
    cost_acl = (
        acl_policy
        + n_acl * ACL_CLASS_OPEN_UNIT
        + n_sel * OBJECT_BINDING_OPEN_UNIT
    )

    return ACLCompressionCost(
        n_sel=n_sel,
        n_acl=n_acl,
        n_vis=n_vis,
        acl_ratio=n_acl / n_sel,
        visible_ratio=n_vis / n_sel if n_sel else 0.0,
        object_level_policy_evals=object_policy,
        acl_class_policy_evals=acl_policy,
        estimated_policy_eval_saved=object_policy - acl_policy,
        estimated_cost_object_level=cost_object,
        estimated_cost_acl_class=cost_acl,
    )


def verify_object_class_bindings(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
    committed_bindings: dict[int, ObjectClassBinding],
) -> None:
    """Plaintext binding commitment check (forged cid -> class mapping)."""
    for c in candidates:
        if not c.valid:
            continue
        claimed = bindings.get(c.cid)
        committed = committed_bindings.get(c.cid)
        if committed is None:
            raise ValueError(f"missing committed binding for cid={c.cid}")
        if claimed is None or claimed != committed:
            raise ValueError(f"forged binding for cid={c.cid}")


def verify_class_visibility_consistency(
    view: ACLClassView,
    user: UserContext,
    checkpoint: Checkpoint,
) -> None:
    """Each class visibility bit must match P on class label."""
    for class_id, vis in view.class_visibility.items():
        expected = evaluate_acl_class_visibility(
            user, view.class_labels[class_id], checkpoint
        )
        if vis != expected:
            raise ValueError(
                f"class visibility manipulation on class_id={class_id}: "
                f"claimed {vis}, expected {expected}"
            )


def authorized_topk_acl_compressed(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
    *,
    d_max: int = DEFAULT_D_MAX,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
    committed_bindings: dict[int, ObjectClassBinding] | None = None,
    verify_visibility: bool = True,
) -> ACLCompressedReferenceResult:
    """
    Authorized top-k under ACL-class compression.

    Semantics match run_authorized_reference when object labels are expanded
    from (binding, class_labels) and each class policy is evaluated once.
    """
    check_candidate_coverage(
        candidates, n_probe=n_probe, slots_per_list=slots_per_list
    )
    if committed_bindings is not None:
        verify_object_class_bindings(candidates, bindings, committed_bindings)

    view = build_acl_class_view(candidates, bindings, class_labels, user, checkpoint)
    if verify_visibility:
        verify_class_visibility_consistency(view, user, checkpoint)

    scored = [
        score_candidate_acl_compressed(c, view, user, checkpoint, d_max)
        for c in candidates
    ]
    top_k_cids = authorized_topk(scored, top_k)

    n_sel = sum(1 for c in candidates if c.valid)
    n_acl = count_unique_acl_classes_in_candidates(candidates, bindings)
    n_vis = sum(
        1
        for c in candidates
        if c.valid and view.cid_visibility.get(c.cid, 0) == 1
    )
    cost = estimate_acl_compression_cost(n_sel, n_acl, n_vis)

    return ACLCompressedReferenceResult(
        top_k_cids=top_k_cids,
        scored=scored,
        view=view,
        cost=cost,
        checkpoint=checkpoint,
        user=user,
    )


def compare_object_level_vs_acl_class_reference(
    candidates: list[CandidateRecord],
    bindings: dict[int, ObjectClassBinding],
    class_labels: dict[int, ACLClassLabel],
    user: UserContext,
    checkpoint: Checkpoint,
    top_k: int,
    *,
    n_probe: int | None = None,
    slots_per_list: int | None = None,
) -> dict[str, object]:
    """
    Compare object-level and ACL-class reference outputs.

    Object-level candidates use labels expanded from ACL bindings.
    """
    expanded: list[CandidateRecord] = []
    committed_labels: dict[int, AuthLabel] = {}
    for c in candidates:
        binding = bindings[c.cid]
        label = expand_auth_label_for_cid(binding, class_labels)
        committed_labels[c.cid] = label
        expanded.append(
            CandidateRecord(
                cid=c.cid,
                list_id=c.list_id,
                slot_id=c.slot_id,
                valid=c.valid,
                distance=c.distance,
                label=label,
            )
        )

    object_result = run_authorized_reference(
        expanded,
        user,
        checkpoint,
        top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
        committed_labels=committed_labels,
    )
    acl_result = authorized_topk_acl_compressed(
        candidates,
        bindings,
        class_labels,
        user,
        checkpoint,
        top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
        committed_bindings=bindings,
    )

    topk_match = object_result.top_k_cids == acl_result.top_k_cids
    masked_match = all(
        o.masked_distance == a.masked_distance
        for o, a in zip(object_result.scored, acl_result.scored, strict=True)
    )
    vis_match = all(
        o.visibility == a.visibility
        for o, a in zip(object_result.scored, acl_result.scored, strict=True)
    )

    return {
        "equivalent": topk_match and masked_match and vis_match,
        "top_k_match": topk_match,
        "masked_distance_match": masked_match,
        "visibility_match": vis_match,
        "object_top_k": object_result.top_k_cids,
        "acl_top_k": acl_result.top_k_cids,
        "cost": acl_result.cost,
    }


def build_acl_fixtures_from_candidates(
    candidates: list[CandidateRecord],
    *,
    class_id_fn=None,
) -> tuple[dict[int, ObjectClassBinding], dict[int, ACLClassLabel]]:
    """
    Build bindings + class labels from object-level candidate labels.

    Default class_id_fn groups by (tenant, project, level, state, epoch).
    """
    if class_id_fn is None:
        class_id_fn = _default_class_id_from_label

    bindings: dict[int, ObjectClassBinding] = {}
    class_labels: dict[int, ACLClassLabel] = {}

    for c in candidates:
        class_id = class_id_fn(c.label)
        bindings[c.cid] = object_binding_from_label(c.cid, class_id, c.label)
        if class_id not in class_labels:
            class_labels[class_id] = acl_class_label_from_auth_label(class_id, c.label)

    return bindings, class_labels


def _default_class_id_from_label(label: AuthLabel) -> int:
    """Deterministic class id from label fields (plaintext fixture helper)."""
    tenant_id = TENANT_NAME_TO_ID.get(label.tenant, 0)
    project_id = PROJECT_NAME_TO_ID.get(label.project, 0)
    return (
        (tenant_id << 24)
        | (project_id << 16)
        | (label.level << 8)
        | (label.epoch & 0xFF)
    )


# Future ZK commitment leaf layouts (documented; not wired in Phase 5A).
ACL_CLASS_LEAF_FIELDS = (
    "acl_class_id",
    "tenant_id",
    "project_id",
    "required_clearance",
    "state",
    "epoch",
)
OBJECT_CLASS_BINDING_LEAF_FIELDS = ("cid", "acl_class_id", "epoch")
