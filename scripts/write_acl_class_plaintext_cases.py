#!/usr/bin/env python3
"""Write artifacts/acl_class_plaintext_cases.csv from plaintext ACL-class fixtures."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    build_acl_fixtures_from_candidates,
    compare_object_level_vs_acl_class_reference,
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
    "N_vis",
    "acl_ratio",
    "visible_ratio",
    "object_level_policy_evals",
    "acl_class_policy_evals",
    "estimated_cost_object_level",
    "estimated_cost_acl_class",
    "expected_equivalent",
    "observed_equivalent",
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
) -> dict[str, str | int]:
    cmp = compare_object_level_vs_acl_class_reference(
        candidates,
        bindings,
        class_labels,
        DEFAULT_USER,
        DEFAULT_CHECKPOINT,
        top_k,
        n_probe=n_probe,
        slots_per_list=slots_per_list,
    )
    cost = cmp["cost"]
    return {
        "case_id": case_id,
        "N_sel": cost.n_sel,
        "N_acl": cost.n_acl,
        "N_vis": cost.n_vis,
        "acl_ratio": f"{cost.acl_ratio:.4f}",
        "visible_ratio": f"{cost.visible_ratio:.4f}",
        "object_level_policy_evals": cost.object_level_policy_evals,
        "acl_class_policy_evals": cost.acl_class_policy_evals,
        "estimated_cost_object_level": cost.estimated_cost_object_level,
        "estimated_cost_acl_class": cost.estimated_cost_acl_class,
        "expected_equivalent": "true",
        "observed_equivalent": str(cmp["equivalent"]).lower(),
    }


def build_rows() -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []

    compliant = build_compliant_candidates()
    b1, c1 = build_acl_fixtures_from_candidates(compliant)
    rows.append(_record("compliant_mixed", compliant, b1, c1, 3, 2, 3))

    post = build_post_filter_contrast_candidates()
    b2, c2 = build_acl_fixtures_from_candidates(post)
    rows.append(_record("post_filter_contrast", post, b2, c2, 2, 2, 2))

    same_class = compliant
    b3 = {c.cid: ObjectClassBinding(c.cid, 1, DEFAULT_CHECKPOINT.epoch) for c in same_class}
    c3 = {1: _class_one()}
    rows.append(_record("all_same_class", same_class, b3, c3, 3, 2, 3))

    degenerate = compliant
    b4 = {
        c.cid: ObjectClassBinding(c.cid, c.cid, c.label.epoch) for c in degenerate
    }
    from auth_reference.acl_class import acl_class_label_from_auth_label

    c4 = {c.cid: acl_class_label_from_auth_label(c.cid, c.label) for c in degenerate}
    rows.append(_record("degenerate_one_class_per_object", degenerate, b4, c4, 3, 2, 3))

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
    parser = argparse.ArgumentParser(description="Write ACL-class plaintext cases CSV.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/acl_class_plaintext_cases.csv"),
    )
    args = parser.parse_args(argv)
    n = write_csv(args.output)
    print(f"Wrote {n} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
