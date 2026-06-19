#!/usr/bin/env python3
"""
Sanity audit for repaired access-signature layout cost model (Phase 6B-2.10).

Reads layout summary CSV and writes pass/fail sanity checks.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

SANITY_FIELDS = ["check_id", "description", "passed", "detail"]


def _load(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _f(row: dict, key: str) -> float:
    return float(row[key])


def _by_layout(rows: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for row in rows:
        layout = row["physical_layout"]
        if layout == "merged_k":
            continue
        out.setdefault(layout, []).append(row)
    return out


def _merged_k_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["physical_layout"] == "merged_k"]


def run_sanity_checks(rows: list[dict]) -> list[dict]:
    checks: list[dict] = []
    base = _by_layout(rows)
    merged = _merged_k_rows(rows)

    def add(check_id: str, description: str, passed: bool, detail: str) -> None:
        checks.append(
            {
                "check_id": check_id,
                "description": description,
                "passed": str(passed).lower(),
                "detail": detail,
            }
        )

    sa_oracle = _f(base["oracle_authorized_view"][0], "median_SA_commit")
    sa_global = _f(base["global"][0], "median_SA_commit")
    sa_acl = _f(base["acl_signature"][0], "median_SA_commit")
    pa_oracle = _f(base["oracle_authorized_view"][0], "median_PA_plan")
    pa_global = _f(base["global"][0], "median_PA_plan")
    pa_acl = _f(base["acl_signature"][0], "median_PA_plan")
    imp_global = _f(base["global"][0], "median_impure_valid_ratio")
    imp_acl = _f(base["acl_signature"][0], "median_impure_valid_ratio")

    add(
        "oracle_has_highest_SA",
        "Oracle SA_commit >= all other layouts",
        sa_oracle >= max(sa_global, sa_acl) - 1e-6,
        f"oracle={sa_oracle:.4f}, global={sa_global:.4f}, acl={sa_acl:.4f}",
    )
    add(
        "oracle_has_lowest_PA",
        "Oracle PA_plan <= all other base layouts",
        pa_oracle <= min(pa_global, pa_acl) + 0.05,
        f"oracle={pa_oracle:.4f}, global={pa_global:.4f}, acl={pa_acl:.4f}",
    )
    add(
        "global_has_low_SA_high_PA",
        "Global SA low and PA high vs oracle",
        sa_global < sa_oracle and pa_global > pa_oracle,
        f"SA global={sa_global:.4f} oracle={sa_oracle:.4f}; PA global={pa_global:.4f} oracle={pa_oracle:.4f}",
    )
    add(
        "acl_signature_between_global_and_oracle",
        "ACL-signature PA between global and oracle; SA between global and oracle",
        pa_oracle < pa_acl < pa_global and sa_global < sa_acl < sa_oracle,
        f"PA oracle={pa_oracle:.4f} acl={pa_acl:.4f} global={pa_global:.4f}; "
        f"SA global={sa_global:.4f} acl={sa_acl:.4f} oracle={sa_oracle:.4f}",
    )

    merged_sorted = sorted(merged, key=lambda r: int(r["merged_k"]))
    pa_by_k = [_f(r, "median_PA_plan") for r in merged_sorted]
    sa_by_k = [_f(r, "median_SA_commit") for r in merged_sorted]
    ks = [int(r["merged_k"]) for r in merged_sorted]

    pa_mono = all(pa_by_k[i] <= pa_by_k[i + 1] + 0.02 for i in range(len(pa_by_k) - 1))
    sa_mono = all(sa_by_k[i] >= sa_by_k[i + 1] - 0.02 for i in range(len(sa_by_k) - 1))
    add(
        "merged_k_monotonic_PA_with_k",
        "Merged-k PA non-decreasing as k increases",
        pa_mono,
        ", ".join(f"k={k}:PA={p:.3f}" for k, p in zip(ks, pa_by_k)),
    )
    add(
        "merged_k_monotonic_SA_with_k",
        "Merged-k SA non-increasing as k increases",
        sa_mono,
        ", ".join(f"k={k}:SA={s:.3f}" for k, s in zip(ks, sa_by_k)),
    )

    dominated = all(
        not (sa_by_k[i] >= sa_oracle - 0.01 and pa_by_k[i] <= pa_oracle + 0.05)
        for i in range(len(pa_by_k))
    )
    add(
        "merged_k_not_dominated_for_all_k",
        "No merged-k point dominates oracle on both SA and PA",
        dominated,
        "checked all merged-k rows",
    )
    add(
        "acl_signature_not_identical_to_oracle",
        "ACL-signature SA differs from oracle (replication vs signature table)",
        abs(sa_acl - sa_oracle) > 0.05,
        f"ΔSA={abs(sa_acl - sa_oracle):.4f}, ΔPA={abs(pa_acl - pa_oracle):.4f}",
    )

    all_masked = all(r["all_planned_equals_masked"] == "true" for r in rows)
    all_valid = all(r["all_validation_passed"] == "true" for r in rows)
    add(
        "all_planned_equals_masked",
        "All summary groups planned_equals_masked",
        all_masked,
        f"{sum(1 for r in rows if r['all_planned_equals_masked']=='true')}/{len(rows)} groups",
    )
    add(
        "all_validation_passed",
        "All summary groups validation_passed",
        all_valid,
        f"{sum(1 for r in rows if r['all_validation_passed']=='true')}/{len(rows)} groups",
    )

    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Layout model sanity audit.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("artifacts/proof_planning_layout_summary_repaired.csv"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/proof_planning_layout_sanity.csv"),
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    rows = _load(args.input)
    checks = run_sanity_checks(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SANITY_FIELDS)
        writer.writeheader()
        writer.writerows(checks)

    passed = sum(1 for c in checks if c["passed"] == "true")
    print(f"Wrote {len(checks)} sanity checks to {args.output} ({passed}/{len(checks)} passed)")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
