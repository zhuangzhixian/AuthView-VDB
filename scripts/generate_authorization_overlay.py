#!/usr/bin/env python3
"""Phase 9A: Generate authorization overlays for public benchmark datasets."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from scripts.auth_overlay_lib import (
    DEFAULT_POLICY_MODES,
    DEFAULT_SELECTIVITIES,
    EXPECTED_NUM_BASE,
    SUMMARY_OVERLAY_FIELDS,
    generate_overlay,
    save_visibility_npz,
    seed_for,
    write_sample_object_visibility_csv,
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_num_base_from_summary(path: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            dataset = row["dataset"]
            if dataset in out:
                continue
            out[dataset] = int(float(row["num_base"]))
    return out


def write_csv(path: Path, rows: list[dict], fieldnames: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate authorization overlay masks.")
    parser.add_argument("--datasets", default="sift1m,gist1m")
    parser.add_argument(
        "--num-base-from-summary",
        type=Path,
        default=Path("artifacts/public_utility/sift_gist_utility_summary.csv"),
    )
    parser.add_argument("--policy-modes", default=",".join(DEFAULT_POLICY_MODES))
    parser.add_argument("--selectivities", default=",".join(str(s) for s in DEFAULT_SELECTIVITIES))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/auth_overlay"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sample-size", type=int, default=10_000)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    summary_path = (
        args.num_base_from_summary
        if args.num_base_from_summary.is_absolute()
        else root / args.num_base_from_summary
    )
    num_base_map = load_num_base_from_summary(summary_path)

    datasets = [d.strip() for d in args.datasets.split(",") if d.strip()]
    policy_modes = [p.strip() for p in args.policy_modes.split(",") if p.strip()]
    selectivities = [float(s.strip()) for s in args.selectivities.split(",") if s.strip()]

    for dataset in datasets:
        num_base = num_base_map.get(dataset) or EXPECTED_NUM_BASE.get(dataset)
        if num_base is None:
            raise SystemExit(f"unknown num_base for dataset {dataset}")

        for policy_mode in policy_modes:
            overlay_rows: list[dict] = []
            for selectivity in selectivities:
                seed = seed_for(dataset, policy_mode, selectivity, args.seed)
                visible, acl_class, observed = generate_overlay(
                    dataset=dataset,
                    policy_mode=policy_mode,
                    selectivity=selectivity,
                    num_base=num_base,
                    seed=seed,
                )
                sel_tag = str(selectivity).replace(".", "p")
                mask_path = output_dir / f"{dataset}_{policy_mode}_sel{sel_tag}_visibility.npz"
                sample_csv = output_dir / f"{dataset}_{policy_mode}_sel{sel_tag}_object_visibility_sample.csv"
                save_visibility_npz(
                    mask_path,
                    visible=visible,
                    acl_class=acl_class,
                    dataset=dataset,
                    policy_mode=policy_mode,
                    selectivity_target=selectivity,
                    selectivity_observed=observed,
                    seed=seed,
                )
                write_sample_object_visibility_csv(
                    sample_csv,
                    visible,
                    acl_class,
                    sample_size=args.sample_size,
                    seed=seed,
                )
                overlay_rows.append(
                    {
                        "dataset": dataset,
                        "policy_mode": policy_mode,
                        "selectivity_target": selectivity,
                        "selectivity_observed": observed,
                        "seed": seed,
                        "num_base": num_base,
                        "num_acl_classes": int(len(set(acl_class.tolist()))),
                        "visible_count": int(visible.sum()),
                        "mask_path": str(mask_path),
                        "sample_csv_path": str(sample_csv),
                    }
                )
                print(
                    f"{dataset}/{policy_mode} sel={selectivity}: "
                    f"observed={observed:.4f} mask={mask_path.name}"
                )

            summary_csv = output_dir / f"{dataset}_{policy_mode}_overlay_summary.csv"
            write_csv(summary_csv, overlay_rows, SUMMARY_OVERLAY_FIELDS)

            vis_rows: list[dict] = []
            for row in overlay_rows:
                sample_path = Path(row["sample_csv_path"])
                if not sample_path.is_file():
                    continue
                with sample_path.open(newline="", encoding="utf-8") as f:
                    for srow in csv.DictReader(f):
                        vis_rows.append(
                            {
                                "selectivity": row["selectivity_target"],
                                "object_id": srow["object_id"],
                                "acl_class": srow["acl_class"],
                                "visible": srow["visible"],
                            }
                        )
            if vis_rows:
                vis_csv = output_dir / f"{dataset}_{policy_mode}_object_visibility.csv"
                write_csv(
                    vis_csv,
                    vis_rows,
                    ("selectivity", "object_id", "acl_class", "visible"),
                )

            print(f"Wrote {summary_csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
