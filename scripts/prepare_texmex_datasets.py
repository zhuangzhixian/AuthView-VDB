#!/usr/bin/env python3
"""
Phase 8B: Prepare TEXMEX SIFT1M / GIST1M datasets for V3DB-compatible loaders.

Default mode prints steps only. Pass --download to fetch archives/files.
Outputs markdown report only (no JSON).
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

TEXMEX_BASE = "http://corpus-texmex.irisa.fr"
TEXMEX_FTP_BASE = "ftp://ftp.irisa.fr/local/texmex/corpus"
TEXMEX_ATTRIBUTION = "TEXMEX / IRISA ANN benchmarks (http://corpus-texmex.irisa.fr/)"
NORMALIZE_MAX_DEPTH = 4

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
        "tarball_url_primary": f"{TEXMEX_FTP_BASE}/sift.tar.gz",
        "tarball_url_fallback": f"{TEXMEX_BASE}/sift/sift.tar.gz",
        "file_urls_fallback": {
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
        "tarball_url_primary": f"{TEXMEX_FTP_BASE}/gist.tar.gz",
        "tarball_url_fallback": f"{TEXMEX_BASE}/gist/gist.tar.gz",
        "file_urls_fallback": {
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
    download_errors: list[str] = field(default_factory=list)
    v3db_link: Path | None = None
    v3db_link_ok: bool = False
    v3db_link_warning: bool = False


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


def find_canonical_in_tree(
    directory: Path,
    canonical_name: str,
    *,
    max_depth: int = NORMALIZE_MAX_DEPTH,
) -> Path | None:
    """Find shallowest real file named canonical_name under directory (max depth)."""
    directory = directory.resolve()
    if not directory.is_dir():
        return None

    base_depth = len(directory.parts)
    matches: list[tuple[int, str, Path]] = []

    for root, dirnames, filenames in os.walk(directory):
        root_path = Path(root)
        depth = len(root_path.parts) - base_depth
        if depth >= max_depth:
            dirnames.clear()
        if canonical_name not in filenames:
            continue
        candidate = root_path / canonical_name
        if candidate.is_symlink():
            if candidate.exists():
                matches.append((depth, str(candidate), candidate.resolve()))
            continue
        if candidate.is_file():
            matches.append((depth, str(candidate), candidate.resolve()))

    if not matches:
        return None
    matches.sort(key=lambda item: (item[0], item[1]))
    return matches[0][2]


def _relative_link_target(source: Path, directory: Path) -> str:
    rel = os.path.relpath(source, directory)
    if not rel.startswith("."):
        rel = f"./{rel}"
    return rel


def _ensure_root_symlink(directory: Path, canonical: str, source: Path) -> str:
    """Create or update root-level symlink; never overwrite a regular file."""
    target = directory / canonical
    rel_source = _relative_link_target(source, directory)

    if target.exists() and not target.is_symlink():
        return f"warning: {canonical} exists as regular file at dataset root; not overwriting"

    if target.is_symlink():
        try:
            if target.resolve() == source.resolve():
                return f"symlink {canonical} already OK -> {target.readlink()}"
        except OSError:
            pass
        target.unlink()
        target.symlink_to(rel_source)
        return f"updated symlink {canonical} -> {rel_source}"

    target.symlink_to(rel_source)
    return f"created symlink {canonical} -> {rel_source}"


def normalize_dataset_files(
    directory: Path,
    spec: dict,
    *,
    max_depth: int = NORMALIZE_MAX_DEPTH,
) -> list[str]:
    """Ensure canonical files exist at dataset root via relative symlinks."""
    notes: list[str] = []
    directory = directory.resolve()

    for role, canonical in spec["files"].items():
        root_path = directory / canonical
        if root_path.is_file() and not root_path.is_symlink():
            notes.append(f"kept existing regular file {canonical} at dataset root")
            continue

        source = find_canonical_in_tree(directory, canonical, max_depth=max_depth)
        if source is None:
            if role in spec["required_roles"]:
                notes.append(f"required file not found in tree: {canonical}")
            continue

        if source == root_path.resolve():
            continue

        notes.append(_ensure_root_symlink(directory, canonical, source))

    return notes


def check_dataset_files(directory: Path, spec: dict) -> list[FileCheck]:
    checks: list[FileCheck] = []
    for role, canonical in spec["files"].items():
        path = directory / canonical
        exists = path.is_file() or (path.is_symlink() and path.exists())
        size = path.stat().st_size if exists else 0
        normalized_from = None
        if exists and path.is_symlink():
            normalized_from = str(path.readlink())
        checks.append(
            FileCheck(
                role=role,
                canonical_name=canonical,
                path=path,
                exists=exists,
                size_bytes=size,
                normalized_from=normalized_from,
            )
        )
    return checks


def dataset_status_from_checks(spec: dict, checks: list[FileCheck]) -> str:
    required = {spec["files"][r] for r in spec["required_roles"]}
    present = {c.canonical_name for c in checks if c.exists}
    if required.issubset(present):
        return "ready"
    if present & required:
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
    """Resume-friendly download for HTTP; full fetch for FTP."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    is_ftp = url.lower().startswith("ftp://")
    existing = dest.stat().st_size if dest.exists() and not is_ftp else 0
    headers: dict[str, str] = {}
    mode = "wb"
    if existing > 0:
        headers["Range"] = f"bytes={existing}-"
        mode = "ab"

    req = urllib.request.Request(url, headers=headers)
    print(f"GET {url}")
    if existing:
        print(f"  resume from {_human_size(existing)}")

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            code = getattr(resp, "status", resp.getcode())
            if existing and code not in (206, 200):
                print(f"  warning: unexpected status {code}; restarting download")
                dest.unlink(missing_ok=True)
                existing = 0
                mode = "wb"
                req = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=300)

            with open(dest, mode) as out:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{exc}") from exc
    except TimeoutError as exc:
        raise RuntimeError(f"timeout: {exc}") from exc


def extract_tarball(tar_path: Path, dest_dir: Path) -> list[str]:
    notes: list[str] = []
    with tarfile.open(tar_path, "r:*") as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        tf.extractall(path=dest_dir, filter="data")
        notes.append(f"extracted {len(members)} file(s) from {tar_path.name}")
    return notes


def download_dataset(spec: dict, directory: Path) -> tuple[list[str], list[str]]:
    messages: list[str] = []
    errors: list[str] = []
    tar_path = directory / spec["tarball"]
    primary = spec["tarball_url_primary"]
    fallback = spec["tarball_url_fallback"]

    if tar_path.exists() and tar_path.stat().st_size > 0:
        messages.append(f"using existing archive {spec['tarball']} ({_human_size(tar_path.stat().st_size)})")
    else:
        downloaded = False
        for label, url in (("primary FTP", primary), ("fallback HTTP", fallback)):
            try:
                download_streaming(url, tar_path)
                messages.append(f"downloaded {spec['tarball']} via {label}: {url}")
                downloaded = True
                break
            except RuntimeError as exc:
                err = f"{label} download failed ({url}): {exc}"
                errors.append(err)
                print(f"ERROR: {err}", file=sys.stderr)
        if not downloaded:
            messages.append("DOWNLOAD FAILED — all sources exhausted")
            for err in errors:
                messages.append(err)
            messages.append("Manual download (recommended primary FTP):")
            messages.append(f"  wget -c {primary} -O {tar_path}")
            messages.append(f"  # fallback if FTP unavailable:")
            messages.append(f"  wget -c {fallback} -O {tar_path}")
            messages.append(f"  tar -xzf {tar_path} -C {directory}")
            for role in spec["required_roles"]:
                url = spec["file_urls_fallback"][role]
                fname = spec["files"][role]
                messages.append(f"  wget -c {url} -O {directory / fname}")
            return messages, errors

    try:
        messages.extend(extract_tarball(tar_path, directory))
    except (tarfile.TarError, OSError) as exc:
        err = f"extract failed for {tar_path}: {exc}"
        errors.append(err)
        messages.append(err)
        return messages, errors

    messages.extend(normalize_dataset_files(directory, spec))
    return messages, errors


def link_v3db_compat(data_root: Path, spec: dict) -> tuple[Path, bool, str, bool]:
    """Create data/{sift|gist} -> public/{sift1m|gist1m} relative symlink."""
    root = repo_root()
    data_parent = root / "data"
    data_parent.mkdir(parents=True, exist_ok=True)
    link_path = data_parent / spec["v3db_link_name"]
    rel_target = Path("public") / spec["subdir"]
    expected_resolved = (data_parent / rel_target).resolve()
    warning = False

    if link_path.is_symlink():
        try:
            resolved = (link_path.parent / link_path.readlink()).resolve()
            if resolved == expected_resolved:
                msg = f"V3DB symlink OK: {link_path} -> {link_path.readlink()}"
                print(msg)
                return link_path, True, msg, False
        except OSError:
            pass
        link_path.unlink()
        link_path.symlink_to(rel_target, target_is_directory=True)
        msg = f"updated V3DB symlink: {link_path} -> {rel_target}"
        print(msg)
        return link_path, True, msg, False

    if link_path.exists():
        if link_path.is_dir():
            msg = (
                f"warning: {link_path} is an existing directory; "
                f"not replacing (expected symlink -> {rel_target})"
            )
            print(msg, file=sys.stderr)
            return link_path, False, msg, True
        msg = f"warning: {link_path} exists and is not a symlink; skipped"
        print(msg, file=sys.stderr)
        return link_path, False, msg, True

    link_path.symlink_to(rel_target, target_is_directory=True)
    msg = f"created V3DB symlink: {link_path} -> {rel_target}"
    print(msg)
    return link_path, True, msg, False


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
            link_path, ok, msg, warning = link_v3db_compat(data_root, spec)
            result.v3db_link = link_path
            result.v3db_link_ok = ok
            result.v3db_link_warning = warning
            result.messages.append(msg)
        return result

    if download and result.status != "ready":
        result.download_attempted = True
        dl_messages, dl_errors = download_dataset(spec, directory)
        result.messages.extend(dl_messages)
        result.download_errors.extend(dl_errors)
        if not dl_errors:
            result.messages.extend(normalize_dataset_files(directory, spec))
        result.checks = check_dataset_files(directory, spec)
        result.status = dataset_status_from_checks(spec, result.checks)
        if dl_errors and result.status != "ready":
            result.messages.append(
                f"dataset remains {result.status} after download failure; see errors above"
            )

    if link_v3db and result.status == "ready":
        link_path, ok, msg, warning = link_v3db_compat(data_root, spec)
        result.v3db_link = link_path
        result.v3db_link_ok = ok
        result.v3db_link_warning = warning
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
        print("  Required files (dataset root):")
        for role in spec["required_roles"]:
            print(f"    - {spec['files'][role]}")
        print("  Optional:")
        for role in spec["optional_roles"]:
            print(f"    - {spec['files'][role]}")
        print(f"  Tarball primary (FTP): {spec['tarball_url_primary']}")
        print(f"  Tarball fallback (HTTP): {spec['tarball_url_fallback']}")
        print("  Per-file fallback URLs (manual HTTP):")
        for role in spec["required_roles"]:
            print(f"    - {spec['file_urls_fallback'][role]}")
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
        "## Download URLs",
        "",
        "| Dataset | Primary (FTP) | Fallback (HTTP) |",
        "|---------|---------------|-----------------|",
    ]
    for name in ("sift1m", "gist1m"):
        spec = DATASET_SPECS[name]
        lines.append(
            f"| {spec['label']} | `{spec['tarball_url_primary']}` | `{spec['tarball_url_fallback']}` |"
        )

    lines.extend(
        [
            "",
            "## Summary",
            "",
            "| Dataset | Status | Directory | V3DB link |",
            "|---------|--------|-----------|-----------|",
        ]
    )
    for r in results:
        if r.v3db_link_warning:
            link_str = "warning"
        elif r.v3db_link_ok:
            link_str = "OK"
        elif r.v3db_link is None:
            link_str = "—"
        else:
            link_str = "skipped/failed"
        lines.append(
            f"| {r.label} | **{r.status}** | `{r.dataset_dir}` | {link_str} |"
        )

    for r in results:
        spec = DATASET_SPECS[r.dataset]
        lines.extend(["", f"## {r.label}", ""])
        lines.append(f"**Status:** {r.status}")
        lines.extend(
            [
                "",
                f"- Primary tarball: `{spec['tarball_url_primary']}`",
                f"- Fallback tarball: `{spec['tarball_url_fallback']}`",
                "",
                "| Role | File | Present | Size |",
                "|------|------|---------|------|",
            ]
        )
        for c in r.checks:
            present = "yes" if c.exists else "no"
            size = _human_size(c.size_bytes) if c.exists else "—"
            extra = f" (symlink -> `{c.normalized_from}`)" if c.normalized_from else ""
            lines.append(f"| {c.role} | `{c.canonical_name}`{extra} | {present} | {size} |")

        if r.download_errors:
            lines.extend(["", "### Download errors", ""])
            for err in r.download_errors:
                lines.append(f"- **ERROR:** {err}")

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
        line = f"  {r.label}: {r.status}"
        if r.download_errors:
            line += f" (download errors: {len(r.download_errors)})"
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
