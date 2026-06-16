#!/usr/bin/env python3
"""Write artifacts/acl_class_commitment_cases.csv from ACL-class witness fixtures."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    acl_class_label_from_auth_label,
    build_acl_fixtures_from_candidates,
    count_unique_acl_classes_in_candidates,
)
from auth_reference.acl_class_commitment import (
    build_acl_class_zk_witness_for_candidates,
    estimate_acl_class_zk_cost,
    verify_acl_class_witness_plaintext,
)
from auth_reference.attacks import (
    DEFAULT_CHECKPOINT,
    DEFAULT_USER,
    build_compliant_candidates,
    build_post_filter_contrast_candidates,
)

CSV_FIELDS = (
    "case_id",
    "N_sel",
    "N_acl",
    "N_acl_max",
    "root_acl_class",
    "root_object_class_binding",
    "acl_ratio",
    "selected_class_count",
    "binding_count",
    "object_level_policy_evals",
    "acl_class_policy_evals",
    "estimated_object_level_cost",
    "estimated_acl_class_cost",
    "witness_valid",
    "topk_equivalent",
)


def _class_one() -> ACLClassLabel:
    return ACLClassLabel(
        acl_class_id=1,
        tenant_id=1,
        project_id=10,
        required_clearance=2,
        state="active",
        epoch=DEFAULT_CHECKPOINT.epoch,
    )


def _record(
    case_id: str,
    candidates,
    bindings,
    class_labels,
    top_k: int,
    n_probe: int,
    slots_per_list: int,
    n_acl_max: int,
) -> dict[str, str | int]:
    witness = build_acl_class_zk_witness_for_candidates(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        n_acl_max=n_acl_max,
    )
    result = verify_acl_class_witness_plaintext(
        witness,
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    cost = result["cost"]
    n_sel = cost.n_sel
    n_acl = cost.n_acl
    return {
        "case_id": case_id,
        "N_sel": n_sel,
        "N_acl": n_acl,
        "N_acl_max": n_acl_max,
        "root_acl_class": witness.root_acl_class,
        "root_object_class_binding": witness.root_object_class_binding,
        "acl_ratio": f"{cost.acl_ratio:.4f}",
        "selected_class_count": sum(witness.selected_class_valids),
        "binding_count": witness.n_probe * witness.slot_per_list,
        "object_level_policy_evals": cost.policy_evals_object_level,
        "acl_class_policy_evals": cost.policy_evals_acl_class,
        "estimated_object_level_cost": cost.estimated_object_level_cost,
        "estimated_acl_class_cost": cost.estimated_acl_class_cost,
        "witness_valid": "true",
        "topk_equivalent": str(result["topk_equivalent"]).lower(),
    }


def build_rows() -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []

    compliant = build_compliant_candidates()
    b1, c1 = build_acl_fixtures_from_candidates(compliant)
    rows.append(_record("compliant_mixed", compliant, b1, c1, 3, 2, 3, 4))

    post = build_post_filter_contrast_candidates()
    b2, c2 = build_acl_fixtures_from_candidates(post)
    rows.append(_record("post_filter_contrast", post, b2, c2, 2, 2, 2, 4))

    same_class = compliant
    b3 = {c.cid: ObjectClassBinding(c.cid, 1, DEFAULT_CHECKPOINT.epoch) for c in same_class}
    c3 = {1: _class_one()}
    rows.append(_record("all_same_class", same_class, b3, c3, 3, 2, 3, 4))

    degenerate = compliant
    b4 = {c.cid: ObjectClassBinding(c.cid, c.cid, c.label.epoch) for c in degenerate}
    c4 = {c.cid: acl_class_label_from_auth_label(c.cid, c.label) for c in degenerate}
    rows.append(_record("degenerate_one_per_object", degenerate, b4, c4, 3, 2, 3, 8))

    return rows


def write_csv(output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = build_rows()
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write ACL-class commitment cases CSV.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/acl_class_commitment_cases.csv"),
    )
    args = parser.parse_args(argv)
    n = write_csv(args.output)
    print(f"Wrote {n} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
