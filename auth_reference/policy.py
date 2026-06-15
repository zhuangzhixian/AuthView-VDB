"""Authorization predicate P(gamma_U, lambda_x, sigma)."""

from __future__ import annotations

from auth_reference.records import AuthLabel, Checkpoint, UserContext

ACTIVE_STATE = "active"


def evaluate_policy(
    user: UserContext,
    label: AuthLabel,
    checkpoint: Checkpoint,
) -> bool:
    """
    P(gamma_U, lambda_x, sigma) in {0, 1}.

    First prototype rules:
    - tenant match
    - project membership
    - clearance >= object level
    - role membership when label specifies required roles
    - state == active
    - epoch matches checkpoint (when label epoch is set)
    """
    if label.tenant != user.tenant:
        return False
    if label.project not in user.projects:
        return False
    if label.level > user.clearance:
        return False
    if label.state != ACTIVE_STATE:
        return False
    if label.epoch != 0 and label.epoch != checkpoint.epoch:
        return False
    if label.roles and not label.roles.intersection(user.roles):
        return False
    return True


def compute_visibility(
    user: UserContext,
    label: AuthLabel,
    checkpoint: Checkpoint,
) -> int:
    """Return visibility bit v_x in {0, 1}."""
    return 1 if evaluate_policy(user, label, checkpoint) else 0
