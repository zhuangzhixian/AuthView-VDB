#!/usr/bin/env python3
"""
Phase 5C: ACL-class compression benchmark (auth_committed vs auth_acl_class).

Scans N_acl at fixed N_sel workloads; object-level labels are expanded from ACL
class structure so both paths share candidates, distances, and visibility semantics.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
from pathlib import Path

import numpy as np

from auth_reference.records import AuthLabel
from auth_reference.acl_class import (
    ACLClassLabel,
    ObjectClassBinding,
    expand_auth_label_for_cid,
)
from auth_reference.acl_class_commitment import (
    build_acl_class_zk_witness_for_buffers,
    split_acl_class_zk_witness_for_zk,
)
from auth_reference.attacks import DEFAULT_CHECKPOINT
from auth_reference.policy import compute_visibility
from auth_reference.v3db_adapter import (
    build_committed_auth_witness,
    build_synthetic_user_context,
    candidate_records_from_slot_buffers,
    compute_v3db_slot_distances,
    encode_user_context_for_zk,
)
from scripts.bench_auth_paths import (
    _learn_base_index,
    _resize_proof_inputs,
)
from tests.test_auth_zk_all_visible import _build_merkle_proof_inputs
from zk_IVF_PQ.zk_IVF_PQ import (
    py_set_based_auth_acl_class_with_merkle,
    py_set_based_auth_committed_with_merkle,
)

CSV_FIELDS = [
    "path",
    "repeat_id",
    "num_vectors",
    "dim",
    "n_list",
    "n_probe",
    "slot_per_list",
    "top_k",
    "N_sel",
    "N_acl",
    "N_acl_max",
    "acl_ratio",
    "visible_ratio",
    "build_time",
    "prove_time",
    "verify_time",
    "proof_size",
    "memory",
    "gates",
]

PATH_NAMES = ("auth_committed", "auth_acl_class")


def _parse_int_list(value: str) -> list[int]:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected at least one integer")
    return [int(p) for p in parts]


def build_acl_lattice_for_n_acl(
    valid_cids: list[int],
    n_acl: int,
    user,
    checkpoint,
) -> tuple[
    dict[int, ObjectClassBinding],
    dict[int, ACLClassLabel],
    dict[int, AuthLabel],
]:
    """Partition valid cids into exactly ``n_acl`` classes (stable sorted order)."""
    if n_acl < 1:
        raise ValueError("n_acl must be >= 1")
    if n_acl > len(valid_cids):
        raise ValueError(f"n_acl={n_acl} exceeds valid cid count {len(valid_cids)}")

    sorted_cids = sorted(valid_cids)
    class_labels: dict[int, ACLClassLabel] = {}
    for class_idx in range(n_acl):
        class_id = 1000 + class_idx
        if n_acl >= 2 and class_idx == 0:
            class_labels[class_id] = ACLClassLabel(
                acl_class_id=class_id,
                tenant_id=2,
                project_id=10,
                required_clearance=1,
                state="active",
                epoch=checkpoint.epoch,
            )
        else:
            class_labels[class_id] = ACLClassLabel(
                acl_class_id=class_id,
                tenant_id=1,
                project_id=10,
                required_clearance=int(user.clearance),
                state="active",
                epoch=checkpoint.epoch,
            )

    bindings: dict[int, ObjectClassBinding] = {}
    object_labels: dict[int, AuthLabel] = {}
    for i, cid in enumerate(sorted_cids):
        class_idx = i % n_acl
        class_id = 1000 + class_idx
        acl_class = class_labels[class_id]
        binding = ObjectClassBinding(
            cid=int(cid),
            acl_class_id=class_id,
            epoch=acl_class.epoch,
        )
        bindings[int(cid)] = binding
        object_labels[int(cid)] = expand_auth_label_for_cid(binding, class_labels)

    return bindings, class_labels, object_labels


def _visible_ratio(candidates, user, checkpoint) -> float:
    valid = [c for c in candidates if c.valid]
    if not valid:
        return 0.0
    visible = sum(
        1 for c in valid if compute_visibility(user, c.label, checkpoint)
    )
    return visible / len(valid)


def build_base_inputs(
    *,
    query: np.ndarray,
    center: np.ndarray,
    code_books: np.ndarray,
    quant_vecs: np.ndarray,
    id_groups: dict,
    num_vectors: int,
    dim: int,
    n_list: int,
    n_probe: int,
    top_k: int,
    slot_per_list: int,
):
    """V3DB proof inputs + slot rows (no auth labels yet)."""
    inputs = _build_merkle_proof_inputs(
        query, center, code_books, quant_vecs, id_groups, n_probe
    )
    _resize_proof_inputs(
        inputs,
        id_groups=id_groups,
        quant_vecs=quant_vecs,
        n_list=n_list,
        slot_per_list=slot_per_list,
    )
    buffers = inputs["buffers"]
    user = build_synthetic_user_context(clearance=10, epoch=DEFAULT_CHECKPOINT.epoch)
    checkpoint = DEFAULT_CHECKPOINT
    slot_rows = compute_v3db_slot_distances(query, center, code_books, buffers)
    valid_cids = sorted({int(r[3]) for r in slot_rows if r[4]})
    return {
        "inputs": inputs,
        "buffers": buffers,
        "slot_rows": slot_rows,
        "valid_cids": valid_cids,
        "user": user,
        "checkpoint": checkpoint,
        "top_k": top_k,
        "meta": {
            "num_vectors": num_vectors,
            "dim": dim,
            "n_list": n_list,
            "n_probe": n_probe,
            "slot_per_list": int(buffers.capacity),
            "top_k": top_k,
            "N_sel": n_probe * int(buffers.capacity),
        },
    }


def build_acl_workload(base: dict, n_acl: int) -> dict:
    """Attach ACL lattice, expanded object labels, and ZK witnesses for one N_acl."""
    bindings, class_labels, object_labels = build_acl_lattice_for_n_acl(
        base["valid_cids"],
        n_acl,
        base["user"],
        base["checkpoint"],
    )
    candidates = candidate_records_from_slot_buffers(base["slot_rows"], object_labels)
    user_w = encode_user_context_for_zk(base["user"], base["checkpoint"])
    committed_w = build_committed_auth_witness(base["buffers"], object_labels)
    acl_witness = build_acl_class_zk_witness_for_buffers(
        base["buffers"],
        bindings,
        class_labels,
        base["user"],
        base["checkpoint"],
        n_acl_max=n_acl,
    )
    acl_split = split_acl_class_zk_witness_for_zk(acl_witness)
    n_sel = base["meta"]["N_sel"]
    return {
        **base,
        "n_acl": n_acl,
        "n_acl_max": n_acl,
        "acl_ratio": n_acl / n_sel if n_sel else 0.0,
        "visible_ratio": _visible_ratio(candidates, base["user"], base["checkpoint"]),
        "candidates": candidates,
        "object_labels": object_labels,
        "user_w": user_w,
        "committed_w": committed_w,
        "acl_split": acl_split,
    }


def _common_v3db_args(workload) -> tuple:
    inputs = workload["inputs"]
    return (
        inputs["query"].tolist(),
        inputs["center"].tolist(),
        inputs["vpqss"].tolist(),
        inputs["valids"].tolist(),
        inputs["itemss"].tolist(),
        inputs["code_books"].tolist(),
        inputs["ivf_roots"].tolist(),
        int(workload["top_k"]),
        inputs["cluster_idx_dis"].tolist(),
    )


def run_path(path: str, workload) -> tuple[float, float, float, int, int, int]:
    base = _common_v3db_args(workload)
    user_w = workload["user_w"]
    committed_w = workload["committed_w"]
    split = workload["acl_split"]

    if path == "auth_committed":
        return py_set_based_auth_committed_with_merkle(
            *base,
            int(committed_w["root_auth"]),
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            committed_w["object_tenant_ids"],
            committed_w["object_project_ids"],
            committed_w["object_levels"],
            committed_w["object_states"],
            committed_w["object_epochs"],
            committed_w["auth_path_directions"],
            committed_w["auth_path_siblings"],
        )
    if path == "auth_acl_class":
        return py_set_based_auth_acl_class_with_merkle(
            *base,
            int(split["root_acl_class"]),
            int(split["root_object_class_binding"]),
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            list(split["selected_class_valids"]),
            list(split["selected_acl_class_ids"]),
            list(split["selected_class_tenant_ids"]),
            list(split["selected_class_project_ids"]),
            list(split["selected_class_required_clearances"]),
            list(split["selected_class_states"]),
            list(split["selected_class_epochs"]),
            split["selected_class_path_directions"],
            split["selected_class_path_siblings"],
            split["binding_acl_class_ids"],
            split["binding_epochs"],
            split["binding_path_directions"],
            split["binding_path_siblings"],
            split["per_slot_class_selector"],
        )
    raise ValueError(f"unknown path: {path}")


def _row(path: str, repeat_id: int, workload: dict, metrics: tuple) -> dict:
    build_time, prove_time, verify_time, proof_size, memory, gates = metrics
    meta = workload["meta"]
    return {
        "path": path,
        "repeat_id": repeat_id,
        "num_vectors": meta["num_vectors"],
        "dim": meta["dim"],
        "n_list": meta["n_list"],
        "n_probe": meta["n_probe"],
        "slot_per_list": meta["slot_per_list"],
        "top_k": meta["top_k"],
        "N_sel": meta["N_sel"],
        "N_acl": workload["n_acl"],
        "N_acl_max": workload["n_acl_max"],
        "acl_ratio": f"{workload['acl_ratio']:.6f}",
        "visible_ratio": f"{workload['visible_ratio']:.6f}",
        "build_time": build_time,
        "prove_time": prove_time,
        "verify_time": verify_time,
        "proof_size": proof_size,
        "memory": memory,
        "gates": gates,
    }


def print_summary(rows: list[dict]) -> None:
    """Print N_acl vs gates for repeat_id=0."""
    repeat0 = [r for r in rows if int(r["repeat_id"]) == 0]
    if not repeat0:
        repeat0 = rows

    workloads: dict[tuple[int, int, int], list[dict]] = {}
    for row in repeat0:
        key = (int(row["n_probe"]), int(row["slot_per_list"]), int(row["top_k"]))
        workloads.setdefault(key, []).append(row)

    print("\n--- ACL-class compression summary (repeat_id=0) ---")
    print(
        f"{'n_probe':>7} {'slot':>5} {'N_sel':>6} {'N_acl':>6} "
        f"{'committed':>10} {'acl_class':>10} {'acl/c':>8} {'prove_r':>8}"
    )
    for key in sorted(workloads):
        group = workloads[key]
        n_probe, slot, top_k = key
        n_sel = int(group[0]["N_sel"])
        by_n_acl: dict[int, dict[str, dict]] = {}
        for row in group:
            n_acl = int(row["N_acl"])
            by_n_acl.setdefault(n_acl, {})[row["path"]] = row

        for n_acl in sorted(by_n_acl):
            paths = by_n_acl[n_acl]
            committed = paths.get("auth_committed")
            acl = paths.get("auth_acl_class")
            if not committed or not acl:
                continue
            c_gates = int(committed["gates"])
            a_gates = int(acl["gates"])
            ratio = a_gates / c_gates if c_gates else 0.0
            prove_r = (
                float(acl["prove_time"]) / float(committed["prove_time"])
                if float(committed["prove_time"])
                else 0.0
            )
            print(
                f"{n_probe:7d} {slot:5d} {n_sel:6d} {n_acl:6d} "
                f"{c_gates:10d} {a_gates:10d} {ratio:8.3f} {prove_r:8.3f}"
            )
    print("  acl/c = auth_acl_class / auth_committed gates; prove_r = prove_time ratio")
    print("---------------------------------------------------\n")


def filter_n_acl_list(n_acl_list: list[int], n_sel: int, n_valid: int) -> list[int]:
    """Keep N_acl values that are <= N_sel and <= number of valid cids."""
    cap = min(n_sel, n_valid)
    return sorted({n for n in n_acl_list if 1 <= n <= cap})


def run_benchmark(
    *,
    repeat: int,
    output: Path,
    num_vectors: int,
    dim: int,
    n_list: int,
    n_probe_list: list[int],
    slot_per_list_list: list[int],
    top_k_list: list[int],
    n_acl_list: list[int],
    n_iter: int,
    seed: int,
) -> list[dict]:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    grid = list(itertools.product(n_probe_list, slot_per_list_list, top_k_list))

    for repeat_id in range(repeat):
        query, learned = _learn_base_index(
            num_vectors=num_vectors,
            dim=dim,
            n_list=n_list,
            n_iter=n_iter,
            seed=seed + repeat_id,
        )
        _labels, center, code_books, quant_vecs, id_groups = learned

        for n_probe, slot_per_list, top_k in grid:
            base = build_base_inputs(
                query=query,
                center=center,
                code_books=code_books,
                quant_vecs=quant_vecs,
                id_groups=id_groups,
                num_vectors=num_vectors,
                dim=dim,
                n_list=n_list,
                n_probe=n_probe,
                top_k=top_k,
                slot_per_list=slot_per_list,
            )
            filtered_n_acl = filter_n_acl_list(
                n_acl_list,
                base["meta"]["N_sel"],
                len(base["valid_cids"]),
            )
            if not filtered_n_acl:
                print(
                    f"skip workload n_probe={n_probe} slot={slot_per_list}: "
                    f"no valid N_acl in {n_acl_list}",
                    file=sys.stderr,
                )
                continue

            for n_acl in filtered_n_acl:
                workload = build_acl_workload(base, n_acl)
                for path in PATH_NAMES:
                    metrics = run_path(path, workload)
                    rows.append(_row(path, repeat_id, workload, metrics))

    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print_summary(rows)
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark ACL-class vs object-level committed AuthView ZK paths."
    )
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/auth_zk_acl_class_metrics.csv"),
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--num-vectors", type=int, default=400)
    parser.add_argument("--dim", type=int, default=64)
    parser.add_argument("--n-list", type=int, default=8)
    parser.add_argument("--n-iter", type=int, default=8)
    parser.add_argument(
        "--n-probe-list",
        type=_parse_int_list,
        default=_parse_int_list("4"),
    )
    parser.add_argument(
        "--slot-per-list-list",
        type=_parse_int_list,
        default=_parse_int_list("64"),
    )
    parser.add_argument(
        "--top-k-list",
        type=_parse_int_list,
        default=_parse_int_list("5"),
    )
    parser.add_argument(
        "--n-acl-list",
        type=_parse_int_list,
        default=_parse_int_list("1,2,4,8,16,32,64"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.repeat < 1:
        print("error: --repeat must be >= 1", file=sys.stderr)
        return 1

    rows = run_benchmark(
        repeat=args.repeat,
        output=args.output,
        num_vectors=args.num_vectors,
        dim=args.dim,
        n_list=args.n_list,
        n_probe_list=args.n_probe_list,
        slot_per_list_list=args.slot_per_list_list,
        top_k_list=args.top_k_list,
        n_acl_list=args.n_acl_list,
        n_iter=args.n_iter,
        seed=args.seed,
    )
    n_workloads = len(args.n_probe_list) * len(args.slot_per_list_list) * len(args.top_k_list)
    print(
        f"Wrote {len(rows)} rows (~{n_workloads} workloads × "
        f"len(N_acl) × {len(PATH_NAMES)} paths × {args.repeat} repeats) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
