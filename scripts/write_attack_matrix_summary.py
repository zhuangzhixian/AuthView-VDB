#!/usr/bin/env python3
"""Write artifacts/auth_attack_matrix.csv from attack matrix registry."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from auth_reference.attack_matrix import ATTACK_MATRIX, CSV_FIELDS


def write_csv(output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in ATTACK_MATRIX:
            writer.writerow(
                {
                    "attack_id": row.attack_id,
                    "attack_name": row.attack_name,
                    "security_property": row.security_property,
                    "layer": row.layer,
                    "proof_path": row.proof_path,
                    "tested_by": row.tested_by,
                    "expected_result": row.expected_result,
                    "observed_result": row.observed_result,
                    "status": row.status,
                    "notes": row.notes,
                }
            )
    return len(ATTACK_MATRIX)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write auth attack matrix CSV.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/auth_attack_matrix.csv"),
        help="Output CSV path.",
    )
    args = parser.parse_args(argv)
    n = write_csv(args.output)
    print(f"Wrote {n} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
