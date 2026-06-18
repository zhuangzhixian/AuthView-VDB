#!/usr/bin/env python3
"""
Phase 8B: Prepare TEXMEX SIFT1M / GIST1M datasets for V3DB-compatible loaders.

Default mode prints steps only. Pass --download to fetch archives/files.
Outputs markdown report only (no JSON).
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

TEXMEX_BASE = "http://corpus-texmex.irisa.fr"
TEXMEX_ATTRIBUTION = "TEXMEX / IRISA ANN benchmarks (http://corpus-texmex.irisa.fr/)"

DATASET_SPECS: dict[str, dict] = {
    "sift1m": {
        "label": "SIFT1M",
        "prefix": "sift",
        "subdir": "sift1m",
        "v3db_link_name": "sift",
        "expected_dim": 128,
        "required_roles": ("base", "query", "groundtruth"),
        "optional_roles": ("learn",),
        "files": {
            "base": "sift_base.fvecs",
            "query": "sift_query.fvecs",
            "groundtruth": "sift_groundtruth.ivecs",
            "learn": "sift_learn.fvecs",
        },
        "tarball": "sift.tar.gz",
        "tarball_url": f"{TEXMEX_BASE}/sift/sift.tar.gz",
        "file_urls": {
            "base": f"{TEXMEX_BASE}/sift/sift_base.fvecs",
            "query": f"{TEXMEX_BASE}/sift/sift_query.fvecs",
            "groundtruth": f"{TEXMEX_BASE}/sift/sift_groundtruth.ivecs",
            "learn": f"{TEXMEX_BASE}/sift/sift_learn.fvecs",
        },
    },
    "gist1m": {
        "label": "GIST1M",
        "prefix": "gist",
        "subdir": "gist1m",
        "v3db_link_name": "gist",
        "expected_dim": 960,
        "required_roles": ("base", "query", "groundtruth"),
        "optional_roles": ("learn",),
        "files": {
            "base": "gist_base.fvecs",
            "query": "gist_query.fvecs",
            "groundtruth": "gist_groundtruth.ivecs",
            "learn": "gist_learn.fvecs",
        },
        "tarball": "gist.tar.gz",
        "tarball_url": f"{TEXMEX_BASE}/gist/gist.tar.gz",
        "file_urls": {
            "base": f"{TEXMEX_BASE}/gist/gist_base.fvecs",
            "query": f"{TEXMEX_BASE}/gist/gist_query.fvecs",
            "groundtruth": f"{TEXMEX_BASE}/gist/gist_groundtruth.ivecs",
            "learn": f"{TEXMEX_BASE}/gist/gist_learn.fvecs",
        },
    },
}


@dataclass
class FileCheck:
    role: str
    canonical_name: str
    path: Path
    exists: bool
    size_bytes: int = 0
    normalized_from: str | None = None


@dataclass
class DatasetPrepareResult:
    dataset: str
    label: str
    dataset_dir: Path
    checks: list[FileCheck] = field(default_factory=list)
    status: str = "missing"
    messages: list[str] = field(default_factory=list)
    download_attempted: bool = False
    v3db_link: Path | None = None
    v3db_link_ok: bool = False


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def dataset_dir(data_root: Path, spec: dict) -> Path:
    return data_root / spec["subdir"]


def ensure_dataset_dirs(data_root: Path, datasets: Iterable[str]) -> list[Path]:
    created: list[Path] = []
    data_root.mkdir(parents=True, exist_ok=True)
    for name in datasets:
        d = dataset_dir(data_root, DATASET_SPECS[name])
        d.mkdir(parents=True, exist_ok=True)
        created.append(d)
    return created


def _find_candidate_files(directory: Path, role: str, prefix: str) -> list[Path]:
    patterns = {
        "base": [f"{prefix}_base.fvecs", "*_base.fvecs"],
        "query": [f"{prefix}_query.fvecs", "*_query.fvecs"],
        "groundtruth": [f"{prefix}_groundtruth.ivecs", "*_groundtruth.ivecs"],
        "learn": [f"{prefix}_learn.fvecs", "*_learn.fvecs"],
    }
    found: list[Path] = []
    for pattern in patterns.get(role, []):
        found.extend(directory.glob(pattern))
    return sorted({p.resolve() for p in found if p.is_file()})


def normalize_dataset_files(directory: Path, spec: dict) -> list[str]:
    """Create symlinks for non-canonical filenames. Returns normalization notes."""
    notes: list[str] = []
    prefix = spec["prefix"]
    for role, canonical in spec["files"].items():
        target = directory / canonical
        if target.exists() or target.is_symlink():
            continue
        candidates = _find_candidate_files(directory, role, prefix)
        candidates = [c for c in candidates if c.name != canonical]
        if not candidates:
            continue
        source = candidates[0]
        try:
            target.symlink_to(source.name)
            notes.append(f"symlink {canonical} -> {source.name}")
        except OSError as exc:
            notes.append(f"could not symlink {canonical} from {source.name}: {exc}")
    return notes


def check_dataset_files(directory: Path, spec: dict) -> list[FileCheck]:
    checks: list[FileCheck] = []
    for role, canonical in spec["files"].items():
        path = directory / canonical
        exists = path.is_file() or (path.is_symlink() and path.exists())
        size = path.stat().st_size if exists else 0
        normalized_from = None
        if exists and path.is_symlink():
            normalized_from = path.readlink()
        checks.append(
            FileCheck(
                role=role,
                canonical_name=canonical,
                path=path,
                exists=exists,
                size_bytes=size,
                normalized_from=str(normalized_from) if normalized_from else None,
            )
        )
    return checks


def dataset_status_from_checks(spec: dict, checks: list[FileCheck]) -> str:
    required = {spec["files"][r] for r in spec["required_roles"]}
    present = {c.canonical_name for c in checks if c.exists}
    if required.issubset(present):
        return "ready"
    if present:
        return "partial"
    return "missing"


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KB"
    if n < 1024**3:
        return f"{n / 1024**2:.1f} MB"
    return f"{n / 1024**3:.2f} GB"


def download_streaming(url: str, dest: Path, *, chunk_size: int = 1 << 20) -> None:
    """Resume-friendly streaming download using HTTP Range when partial file exists."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    existing = dest.stat().st_size if dest.exists() else 0
    headers = {}
    mode = "wb"
    if existing > 0:
        headers["Range"] = f"bytes={existing}-"
        mode = "ab"

    req = urllib.request.Request(url, headers=headers)
    print(f"GET {url}")
    if existing:
        print(f"  resume from {_human_size(existing)}")

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            code = getattr(resp, "status", resp.getcode())
            if existing and code not in (206, 200):
                print(f"  warning: unexpected status {code}; restarting download")
                dest.unlink(missing_ok=True)
                existing = 0
                mode = "wb"
                req = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=120)

            with open(dest, mode) as out:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"download failed for {url}: {exc}") from exc


def extract_tarball(tar_path: Path, dest_dir: Path) -> list[str]:
    notes: list[str] = []
    with tarfile.open(tar_path, "r:*") as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        tf.extractall(path=dest_dir, filter="data")
        notes.append(f"extracted {len(members)} file(s) from {tar_path.name}")
    return notes


def download_dataset(spec: dict, directory: Path) -> list[str]:
    messages: list[str] = []
    tar_path = directory / spec["tarball"]
    try:
        if not tar_path.exists() or tar_path.stat().st_size == 0:
            download_streaming(spec["tarball_url"], tar_path)
            messages.append(f"downloaded {spec['tarball']}")
        else:
            messages.append(f"using existing archive {spec['tarball']}")

        messages.extend(extract_tarball(tar_path, directory))
        messages.extend(normalize_dataset_files(directory, spec))
    except RuntimeError as exc:
        messages.append(str(exc))
        messages.append("Manual download:")
        messages.append(f"  wget -c {spec['tarball_url']} -O {tar_path}")
        messages.append(f"  tar -xzf {tar_path} -C {directory}")
        for role in spec["required_roles"]:
            url = spec["file_urls"][role]
            fname = spec["files"][role]
            messages.append(f"  wget -c {url} -O {directory / fname}")
    return messages


def link_v3db_compat(data_root: Path, spec: dict) -> tuple[Path, bool, str]:
    """Create data/{sift|gist} -> public/{sift1m|gist1m} relative symlink."""
    root = repo_root()
    data_parent = root / "data"
    data_parent.mkdir(parents=True, exist_ok=True)
    link_path = data_parent / spec["v3db_link_name"]
    rel_target = Path("public") / spec["subdir"]

    if link_path.exists() or link_path.is_symlink():
        if link_path.is_symlink():
            try:
                resolved = (link_path.parent / link_path.readlink()).resolve()
                expected = (data_parent / rel_target).resolve()
                if resolved == expected:
                    return link_path, True, "existing symlink OK"
            except OSError:
                pass
            return link_path, False, f"symlink already exists at {link_path}; not overwriting"
        return link_path, False, f"path {link_path} exists and is not a symlink; skipped"

    try:
        link_path.symlink_to(rel_target, target_is_directory=True)
        return link_path, True, f"created {link_path} -> {rel_target}"
    except OSError as exc:
        return link_path, False, f"symlink failed ({exc}); use: ln -s {rel_target} {link_path}"


def prepare_one(
    name: str,
    *,
    data_root: Path,
    download: bool,
    link_v3db: bool,
    check_only: bool,
) -> DatasetPrepareResult:
    spec = DATASET_SPECS[name]
    directory = dataset_dir(data_root, spec)
    directory.mkdir(parents=True, exist_ok=True)
    result = DatasetPrepareResult(dataset=name, label=spec["label"], dataset_dir=directory)

    norm_notes = normalize_dataset_files(directory, spec)
    result.messages.extend(norm_notes)
    result.checks = check_dataset_files(directory, spec)
    result.status = dataset_status_from_checks(spec, result.checks)

    if check_only and not download:
        result.messages.append("check-only: no download attempted")
        if link_v3db and result.status == "ready":
            link_path, ok, msg = link_v3db_compat(data_root, spec)
            result.v3db_link = link_path
            result.v3db_link_ok = ok
            result.messages.append(msg)
        return result

    if download and result.status != "ready":
        result.download_attempted = True
        result.messages.extend(download_dataset(spec, directory))
        result.messages.extend(normalize_dataset_files(directory, spec))
        result.checks = check_dataset_files(directory, spec)
        result.status = dataset_status_from_checks(spec, result.checks)

    if link_v3db and result.status == "ready":
        link_path, ok, msg = link_v3db_compat(data_root, spec)
        result.v3db_link = link_path
        result.v3db_link_ok = ok
        result.messages.append(msg)

    return result


def print_prepare_steps(datasets: list[str], data_root: Path) -> None:
    print(f"Data root: {data_root.resolve()}")
    print(f"Source: {TEXMEX_ATTRIBUTION}")
    print()
    for name in datasets:
        spec = DATASET_SPECS[name]
        directory = dataset_dir(data_root, spec)
        print(f"=== {spec['label']} ({name}) ===")
        print(f"  Directory: {directory}")
        print(f"  V3DB symlink: data/{spec['v3db_link_name']} -> public/{spec['subdir']}")
        print("  Required files:")
        for role in spec["required_roles"]:
            print(f"    - {spec['files'][role]}")
        print("  Optional:")
        for role in spec["optional_roles"]:
            print(f"    - {spec['files'][role]}")
        print(f"  Tarball: {spec['tarball_url']}")
        print("  Per-file URLs:")
        for role in spec["required_roles"]:
            print(f"    - {spec['file_urls'][role]}")
        print()


def render_report(results: list[DatasetPrepareResult], *, data_root: Path) -> str:
    now = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# TEXMEX Dataset Preparation Report",
        "",
        f"Generated: {now}",
        f"Data root: `{data_root.resolve()}`",
        f"Source: {TEXMEX_ATTRIBUTION}",
        "",
        "## Summary",
        "",
        "| Dataset | Status | Directory | V3DB link |",
        "|---------|--------|-----------|-----------|",
    ]
    for r in results:
        link_str = "OK" if r.v3db_link_ok else ("—" if r.v3db_link is None else "skipped/failed")
        lines.append(
            f"| {r.label} | **{r.status}** | `{r.dataset_dir}` | {link_str} |"
        )

    for r in results:
        lines.extend(["", f"## {r.label}", ""])
        lines.append(f"**Status:** {r.status}")
        lines.append("")
        lines.append("| Role | File | Present | Size |")
        lines.append("|------|------|---------|------|")
        for c in r.checks:
            present = "yes" if c.exists else "no"
            size = _human_size(c.size_bytes) if c.exists else "—"
            extra = f" (symlink -> {c.normalized_from})" if c.normalized_from else ""
            lines.append(f"| {c.role} | `{c.canonical_name}`{extra} | {present} | {size} |")

        if r.messages:
            lines.extend(["", "### Messages", ""])
            for msg in r.messages:
                lines.append(f"- {msg}")

    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare TEXMEX SIFT1M/GIST1M datasets.")
    parser.add_argument(
        "--dataset",
        choices=["sift1m", "gist1m", "all"],
        default="all",
    )
    parser.add_argument("--data-root", type=Path, default=Path("data/public"))
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download archives/files (default: print steps only).",
    )
    parser.add_argument(
        "--link-v3db",
        action="store_true",
        help="Create data/sift or data/gist symlinks when dataset is ready.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Check existing files; do not download unless --download is also set.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/texmex_prepare_report.md"),
    )
    return parser.parse_args(argv)


def resolve_datasets(choice: str) -> list[str]:
    if choice == "all":
        return ["sift1m", "gist1m"]
    return [choice]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    datasets = resolve_datasets(args.dataset)
    data_root = args.data_root
    if not data_root.is_absolute():
        data_root = repo_root() / data_root

    ensure_dataset_dirs(data_root, datasets)
    print_prepare_steps(datasets, data_root)

    if not args.download and not args.check_only and not args.link_v3db:
        print("Dry run (default). Re-run with --check-only, --download, and/or --link-v3db.")
        results = [
            prepare_one(
                name,
                data_root=data_root,
                download=False,
                link_v3db=False,
                check_only=True,
            )
            for name in datasets
        ]
    else:
        results = [
            prepare_one(
                name,
                data_root=data_root,
                download=args.download,
                link_v3db=args.link_v3db,
                check_only=args.check_only,
            )
            for name in datasets
        ]

    report = render_report(results, data_root=data_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"Wrote {args.output}")
    for r in results:
        print(f"  {r.label}: {r.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
