#!/usr/bin/env python3
"""
Phase 8A: Read-only scan for public benchmark dataset files (SIFT1M, GIST1M, MS MARCO).

Does not download, modify, or index data. Outputs markdown only (no JSON).
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ROOTS = (
    "/home/zhixian/AuthView-VDB/data",
    "/home/zhixian/data",
    "/home/zhixian/datasets",
    "/data",
    "/data1",
    "/data2",
    "/mnt/data",
)

# basename (lower) -> (dataset, role)
FILENAME_RULES: dict[str, tuple[str, str]] = {
    "sift_base.fvecs": ("sift1m", "base"),
    "sift_query.fvecs": ("sift1m", "query"),
    "sift_groundtruth.ivecs": ("sift1m", "groundtruth"),
    "sift_learn.fvecs": ("sift1m", "learn"),
    "sift.tar.gz": ("sift1m", "tarball"),
    "gist_base.fvecs": ("gist1m", "base"),
    "gist_query.fvecs": ("gist1m", "query"),
    "gist_groundtruth.ivecs": ("gist1m", "groundtruth"),
    "gist_learn.fvecs": ("gist1m", "learn"),
    "gist.tar.gz": ("gist1m", "tarball"),
    "collection.duckdb": ("msmarco", "collection"),
    "queries.dev.duckdb": ("msmarco", "queries_dev"),
    "qrels.dev.tsv": ("msmarco", "qrels"),
}

REQUIRED_ROLES: dict[str, frozenset[str]] = {
    "sift1m": frozenset({"base", "query", "groundtruth"}),
    "gist1m": frozenset({"base", "query", "groundtruth"}),
    "msmarco": frozenset({"collection", "queries_dev", "qrels"}),
}

DATASET_LABELS = {
    "sift1m": "SIFT1M",
    "gist1m": "GIST1M",
    "msmarco": "MS MARCO (passage/dev)",
}


@dataclass
class FoundFile:
    path: Path
    size_bytes: int
    mtime: float
    dataset: str
    role: str
    matched_by: str


@dataclass
class ScanResult:
    roots_scanned: list[str] = field(default_factory=list)
    roots_skipped: list[tuple[str, str]] = field(default_factory=list)
    files: list[FoundFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KB"
    if n < 1024**3:
        return f"{n / 1024**2:.1f} MB"
    return f"{n / 1024**3:.2f} GB"


def _format_mtime(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _match_file(path: Path) -> FoundFile | None:
    name = path.name.lower()
    if name in FILENAME_RULES:
        dataset, role = FILENAME_RULES[name]
        stat = path.stat()
        return FoundFile(
            path=path.resolve(),
            size_bytes=stat.st_size,
            mtime=stat.st_mtime,
            dataset=dataset,
            role=role,
            matched_by=name,
        )

    path_lower = str(path).lower()
    if "msmarco" in path_lower or "ms_marco" in path_lower or "ms-macro" in path_lower:
        if path.is_file() and path.suffix.lower() in (".duckdb", ".tsv", ".db"):
            stat = path.stat()
            return FoundFile(
                path=path.resolve(),
                size_bytes=stat.st_size,
                mtime=stat.st_mtime,
                dataset="msmarco",
                role="other",
                matched_by="path keyword",
            )
    return None


def scan_roots(roots: list[Path], *, max_depth: int) -> ScanResult:
    result = ScanResult()
    seen_paths: set[Path] = set()

    for root in roots:
        root = root.resolve()
        if not root.exists():
            result.roots_skipped.append((str(root), "does not exist"))
            continue
        if not os.access(root, os.R_OK):
            result.roots_skipped.append((str(root), "not readable"))
            continue

        result.roots_scanned.append(str(root))
        root_depth = len(root.parts)

        try:
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                current = Path(dirpath)
                depth = len(current.parts) - root_depth
                if depth >= max_depth:
                    dirnames.clear()
                    continue

                for fname in filenames:
                    full = current / fname
                    if full in seen_paths:
                        continue
                    try:
                        found = _match_file(full)
                    except OSError as exc:
                        result.warnings.append(f"stat failed: {full} ({exc})")
                        continue
                    if found is None:
                        continue
                    seen_paths.add(full)
                    result.files.append(found)
        except PermissionError as exc:
            result.roots_skipped.append((str(root), f"permission denied: {exc}"))
        except OSError as exc:
            result.warnings.append(f"walk failed under {root}: {exc}")

    return result


def roles_by_dataset(files: list[FoundFile]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {k: set() for k in REQUIRED_ROLES}
    for f in files:
        if f.role != "other":
            out.setdefault(f.dataset, set()).add(f.role)
    return out


def directory_completeness(files: list[FoundFile]) -> dict[str, list[tuple[str, str]]]:
    """Return dataset -> list of (directory, status) for dirs with any benchmark file."""
    by_dir: dict[Path, list[FoundFile]] = {}
    for f in files:
        by_dir.setdefault(f.path.parent, []).append(f)

    report: dict[str, list[tuple[str, str]]] = {k: [] for k in REQUIRED_ROLES}
    for directory, dir_files in sorted(by_dir.items(), key=lambda x: str(x[0])):
        roles_in_dir: dict[str, set[str]] = {}
        for f in dir_files:
            if f.role == "other":
                continue
            roles_in_dir.setdefault(f.dataset, set()).add(f.role)

        for dataset, roles in roles_in_dir.items():
            required = REQUIRED_ROLES[dataset]
            if required.issubset(roles):
                status = "ready"
            elif roles:
                status = "partial"
            else:
                continue
            report[dataset].append((str(directory), status))
    return report


def dataset_status(files: list[FoundFile]) -> dict[str, str]:
    roles = roles_by_dataset(files)
    status: dict[str, str] = {}
    for dataset, required in REQUIRED_ROLES.items():
        found = roles.get(dataset, set())
        if not found:
            status[dataset] = "missing"
        elif required.issubset(found):
            status[dataset] = "ready"
        else:
            status[dataset] = "partial"
    return status


def render_markdown(result: ScanResult) -> str:
    status = dataset_status(result.files)
    dir_report = directory_completeness(result.files)
    roles = roles_by_dataset(result.files)
    lines = [
        "# Public Benchmark Dataset Inventory",
        "",
        "Auto-generated by `scripts/inspect_public_benchmark_data.py` (Phase 8A).",
        "Read-only scan — no downloads, no modifications.",
        "",
        f"Generated: {dt.datetime.now(tz=dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Summary",
        "",
        "| Dataset | Status | Required roles found | Missing roles |",
        "|---------|--------|----------------------|---------------|",
    ]

    for dataset in ("sift1m", "gist1m", "msmarco"):
        required = REQUIRED_ROLES[dataset]
        found = roles.get(dataset, set())
        missing = sorted(required - found)
        found_str = ", ".join(sorted(found)) if found else "—"
        missing_str = ", ".join(missing) if missing else "—"
        lines.append(
            f"| {DATASET_LABELS[dataset]} | **{status[dataset]}** | {found_str} | {missing_str} |"
        )

    lines.extend(["", "## Roots scanned", ""])
    if result.roots_scanned:
        for r in result.roots_scanned:
            lines.append(f"- `{r}`")
    else:
        lines.append("- (none)")

    if result.roots_skipped:
        lines.extend(["", "## Roots skipped", ""])
        for path, reason in result.roots_skipped:
            lines.append(f"- `{path}` — {reason}")

    if result.warnings:
        lines.extend(["", "## Warnings", ""])
        for w in result.warnings:
            lines.append(f"- {w}")

    lines.extend(["", "## Directory-level completeness", ""])
    for dataset in ("sift1m", "gist1m", "msmarco"):
        lines.append(f"### {DATASET_LABELS[dataset]}")
        entries = dir_report.get(dataset, [])
        if not entries:
            lines.append("- No matching files found under scanned roots.")
        else:
            for directory, st in entries:
                lines.append(f"- `{directory}` — **{st}**")
        lines.append("")

    lines.extend(["## Discovered files", ""])
    if not result.files:
        lines.append("No benchmark files matched.")
    else:
        lines.extend(
            [
                "| Dataset | Role | Size | Modified | Path |",
                "|---------|------|------|----------|------|",
            ]
        )
        for f in sorted(result.files, key=lambda x: (x.dataset, x.role, str(x.path))):
            lines.append(
                f"| {DATASET_LABELS.get(f.dataset, f.dataset)} | {f.role} | "
                f"{_human_size(f.size_bytes)} | {_format_mtime(f.mtime)} | `{f.path}` |"
            )

    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan local filesystem for public benchmark dataset files."
    )
    parser.add_argument(
        "--roots",
        nargs="+",
        default=list(DEFAULT_ROOTS),
        help="Root directories to scan.",
    )
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/public_benchmark_inventory.md"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    roots = [Path(r) for r in args.roots]
    result = scan_roots(roots, max_depth=args.max_depth)
    md = render_markdown(result)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(md, encoding="utf-8")
    print(f"Wrote {args.output}")
    print(f"Discovered {len(result.files)} file(s)")
    for dataset, st in dataset_status(result.files).items():
        print(f"  {DATASET_LABELS[dataset]}: {st}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
