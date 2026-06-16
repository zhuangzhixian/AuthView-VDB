#!/usr/bin/env python3
"""
Phase 2D/2E/3C: AuthView ZK proof path overhead + scaling benchmark.

Compares five paths on synthetic IVF-PQ workloads:
  baseline, auth_all_visible, auth_policy, auth_committed, auth_slot_aligned
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
from pathlib import Path

import numpy as np

from auth_reference.attacks import DEFAULT_CHECKPOINT
from auth_reference.auth_commitment import next_pow2
from auth_reference.slot_aligned_auth_commitment import tree_depth_padded
from auth_reference.v3db_adapter import (
    V3DBSlotBuffers,
    build_committed_auth_witness,
    build_partial_visible_labels,
    build_slot_aligned_zk_witness_for_buffers,
    build_synthetic_user_context,
    candidate_records_from_slot_buffers,
    compute_v3db_slot_distances,
    encode_slot_auth_labels_for_zk,
    encode_user_context_for_zk,
)
from ivf_pq.zk import ivf_pq_learn
from tests.test_auth_zk_all_visible import (
    _build_merkle_proof_inputs,
    _compute_cluster_root,
)
from zk_IVF_PQ.zk_IVF_PQ import (
    py_set_based_auth_all_visible_with_merkle,
    py_set_based_auth_committed_with_merkle,
    py_set_based_auth_slot_aligned_with_merkle,
    py_set_based_auth_with_merkle,
    py_set_based_with_merkle,
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
    "visible_ratio",
    "auth_tree_depth",
    "build_time",
    "prove_time",
    "verify_time",
    "proof_size",
    "memory",
    "gates",
]

PATH_NAMES = (
    "baseline",
    "auth_all_visible",
    "auth_policy",
    "auth_committed",
    "auth_slot_aligned",
)


def _parse_int_list(value: str) -> list[int]:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected at least one integer")
    return [int(p) for p in parts]


def auth_tree_depth(n_probe: int, slot_per_list: int) -> int:
    """Global committed tree depth: tree_depth(next_pow2(N_sel))."""
    padded = next_pow2(n_probe * slot_per_list)
    depth = 0
    n = padded
    while n > 1:
        n //= 2
        depth += 1
    return depth


def slot_aligned_auth_tree_depth(n_list: int, slot_per_list: int) -> int:
    """Slot-aligned auth depth recorded in CSV: depth_top + depth_slot."""
    return tree_depth_padded(n_list) + tree_depth_padded(slot_per_list)


def _visible_ratio(candidates, user, checkpoint) -> float:
    from auth_reference.policy import compute_visibility

    valid = [c for c in candidates if c.valid]
    if not valid:
        return 0.0
    visible = sum(
        1 for c in valid if compute_visibility(user, c.label, checkpoint)
    )
    return visible / len(valid)


def _learn_base_index(
    *,
    num_vectors: int,
    dim: int,
    n_list: int,
    n_iter: int,
    seed: int,
):
    rng = np.random.default_rng(seed)
    vecs = rng.integers(0, 4096, size=(num_vectors, dim), dtype=np.int64)
    query = rng.integers(0, 4096, size=dim, dtype=np.int64)
    learned = ivf_pq_learn(vecs, n_list=n_list, n_iter=n_iter)
    return query, learned


def _resize_proof_inputs(
    inputs: dict,
    *,
    id_groups: dict,
    quant_vecs: np.ndarray,
    n_list: int,
    slot_per_list: int,
) -> None:
    """Pad or truncate probed slot buffers; recompute IVF Merkle roots at target capacity."""
    vpqss = np.asarray(inputs["vpqss"], dtype=np.int64)
    valids = np.asarray(inputs["valids"], dtype=np.int64)
    itemss = np.asarray(inputs["itemss"], dtype=np.int64)
    n_probe, old_cap, m = vpqss.shape

    new_vpqss = np.zeros((n_probe, slot_per_list, m), dtype=np.int64)
    new_valids = np.zeros((n_probe, slot_per_list), dtype=np.int64)
    new_itemss = np.zeros((n_probe, slot_per_list), dtype=np.int64)
    copy_cap = min(old_cap, slot_per_list)
    new_vpqss[:, :copy_cap, :] = vpqss[:, :copy_cap, :]
    new_valids[:, :copy_cap] = valids[:, :copy_cap]
    new_itemss[:, :copy_cap] = itemss[:, :copy_cap]

    inputs["vpqss"] = new_vpqss
    inputs["valids"] = new_valids
    inputs["itemss"] = new_itemss

    cluster_idx_dis = inputs["cluster_idx_dis"]
    cluster_idxes = cluster_idx_dis[:n_probe, 0]
    ivf_roots = np.zeros((n_list,), dtype=np.uint64)
    visited = np.zeros((n_list,), dtype=bool)

    for probe_pos, cluster_index in enumerate(cluster_idxes):
        ci = int(cluster_index)
        ivf_roots[ci] = _compute_cluster_root(
            ci,
            new_vpqss[probe_pos],
            new_valids[probe_pos],
            new_itemss[probe_pos],
        )
        visited[ci] = True

    quant_vecs = np.asarray(quant_vecs, dtype=np.int64)
    for ci in range(n_list):
        if visited[ci]:
            continue
        vector_ids = id_groups[ci]
        vpqs = np.zeros((slot_per_list, m), dtype=np.int64)
        row_valids = np.zeros((slot_per_list,), dtype=np.int64)
        items = np.zeros((slot_per_list,), dtype=np.int64)
        for local_pos, vec_id in enumerate(vector_ids):
            if local_pos >= slot_per_list:
                break
            items[local_pos] = int(vec_id)
            row_valids[local_pos] = 1
            vpqs[local_pos, :] = quant_vecs[int(vec_id)]
        ivf_roots[ci] = _compute_cluster_root(ci, vpqs, row_valids, items)

    inputs["ivf_roots"] = ivf_roots
    inputs["buffers"] = V3DBSlotBuffers(
        vpqss=new_vpqss,
        valids=new_valids,
        itemss=new_itemss,
        cluster_idxes=inputs["buffers"].cluster_idxes,
        capacity=slot_per_list,
        n_probe=n_probe,
    )


def build_synthetic_workload(
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
    slot_per_list: int | None,
):
    """Build proof inputs + auth witnesses for one grid point."""
    inputs = _build_merkle_proof_inputs(
        query, center, code_books, quant_vecs, id_groups, n_probe
    )
    if slot_per_list is not None:
        _resize_proof_inputs(
            inputs,
            id_groups=id_groups,
            quant_vecs=quant_vecs,
            n_list=n_list,
            slot_per_list=slot_per_list,
        )

    buffers = inputs["buffers"]
    capacity = int(buffers.capacity)

    user = build_synthetic_user_context(clearance=10, epoch=DEFAULT_CHECKPOINT.epoch)
    checkpoint = DEFAULT_CHECKPOINT

    slot_rows = compute_v3db_slot_distances(
        query, center, code_books, buffers
    )
    valid_rows = [r for r in slot_rows if r[4]]
    by_dist = sorted(valid_rows, key=lambda r: r[5])
    invisible_cids = {by_dist[0][3], by_dist[1][3]} if len(valid_rows) >= 2 else set()
    visible_cids = {r[3] for r in valid_rows} - invisible_cids
    labels = build_partial_visible_labels(
        visible_cids, invisible_cids, user, checkpoint
    )
    candidates = candidate_records_from_slot_buffers(slot_rows, labels)
    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = encode_slot_auth_labels_for_zk(buffers, labels)
    committed_w = build_committed_auth_witness(buffers, labels)
    slot_aligned_w = build_slot_aligned_zk_witness_for_buffers(
        buffers, labels, n_list=n_list
    )

    meta = {
        "num_vectors": num_vectors,
        "dim": dim,
        "n_list": n_list,
        "n_probe": n_probe,
        "slot_per_list": capacity,
        "top_k": top_k,
        "N_sel": n_probe * capacity,
        "visible_ratio": _visible_ratio(candidates, user, checkpoint),
        "auth_tree_depth": auth_tree_depth(n_probe, capacity),
        "slot_aligned_auth_tree_depth": slot_aligned_auth_tree_depth(
            n_list, capacity
        ),
    }

    return {
        "inputs": inputs,
        "top_k": top_k,
        "user_w": user_w,
        "slot_w": slot_w,
        "committed_w": committed_w,
        "slot_aligned_w": slot_aligned_w,
        "meta": meta,
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
    slot_w = workload["slot_w"]
    committed_w = workload["committed_w"]
    slot_aligned_w = workload["slot_aligned_w"]

    if path == "baseline":
        metrics = py_set_based_with_merkle(*base, [])
    elif path == "auth_all_visible":
        metrics = py_set_based_auth_all_visible_with_merkle(*base, [])
    elif path == "auth_policy":
        metrics = py_set_based_auth_with_merkle(
            *base,
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            slot_w["object_tenant_ids"],
            slot_w["object_project_ids"],
            slot_w["object_levels"],
            slot_w["object_states"],
            slot_w["object_epochs"],
        )
    elif path == "auth_committed":
        metrics = py_set_based_auth_committed_with_merkle(
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
    elif path == "auth_slot_aligned":
        metrics = py_set_based_auth_slot_aligned_with_merkle(
            *base,
            int(slot_aligned_w["root_auth"]),
            int(user_w["user_tenant_id"]),
            list(user_w["user_project_ids"]),
            list(user_w["user_project_valids"]),
            int(user_w["user_clearance"]),
            int(user_w["user_epoch"]),
            int(user_w["checkpoint_epoch"]),
            slot_aligned_w["object_tenant_ids"],
            slot_aligned_w["object_project_ids"],
            slot_aligned_w["object_levels"],
            slot_aligned_w["object_states"],
            slot_aligned_w["object_epochs"],
            slot_aligned_w["list_ids"],
            slot_aligned_w["list_auth_roots"],
            slot_aligned_w["top_path_directions"],
            slot_aligned_w["top_path_siblings"],
            slot_aligned_w["intra_path_directions"],
            slot_aligned_w["intra_path_siblings"],
        )
    else:
        raise ValueError(f"unknown path: {path}")

    return metrics


def _row(path: str, repeat_id: int, meta: dict, metrics: tuple) -> dict:
    build_time, prove_time, verify_time, proof_size, memory, gates = metrics
    depth = (
        meta["slot_aligned_auth_tree_depth"]
        if path == "auth_slot_aligned"
        else meta["auth_tree_depth"]
    )
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
        "visible_ratio": f"{meta['visible_ratio']:.6f}",
        "auth_tree_depth": depth,
        "build_time": build_time,
        "prove_time": prove_time,
        "verify_time": verify_time,
        "proof_size": proof_size,
        "memory": memory,
        "gates": gates,
    }


def print_summary(rows: list[dict]) -> None:
    """Print scaling summary grouped by workload (repeat_id=0)."""
    repeat0 = [r for r in rows if int(r["repeat_id"]) == 0]
    if not repeat0:
        repeat0 = rows

    workloads: dict[tuple[int, int, int], dict[str, dict]] = {}
    for row in repeat0:
        key = (int(row["n_probe"]), int(row["slot_per_list"]), int(row["top_k"]))
        workloads.setdefault(key, {})[row["path"]] = row

    print("\n--- scaling summary (repeat_id=0) ---")
    print(
        f"{'n_probe':>7} {'slot':>5} {'N_sel':>6} {'depth':>5} "
        f"{'baseline':>9} {'policy':>9} {'committed':>9} {'slot_algn':>9} "
        f"{'c/b':>6} {'s/c':>6} {'s/p_t':>6}"
    )
    for key in sorted(workloads):
        n_probe, slot, top_k = key
        paths = workloads[key]
        baseline = paths.get("baseline")
        policy = paths.get("auth_policy")
        committed = paths.get("auth_committed")
        slot_aligned = paths.get("auth_slot_aligned")
        if not baseline or not committed:
            continue
        n_sel = int(baseline["N_sel"])
        depth = int(baseline["auth_tree_depth"])
        b_gates = int(baseline["gates"])
        p_gates = int(policy["gates"]) if policy else 0
        c_gates = int(committed["gates"])
        s_gates = int(slot_aligned["gates"]) if slot_aligned else 0
        c_ratio = c_gates / b_gates if b_gates else 0.0
        s_c_ratio = s_gates / c_gates if c_gates else 0.0
        if slot_aligned and committed:
            s_p_ratio = (
                float(slot_aligned["prove_time"]) / float(committed["prove_time"])
                if float(committed["prove_time"])
                else 0.0
            )
        else:
            s_p_ratio = 0.0
        print(
            f"{n_probe:7d} {slot:5d} {n_sel:6d} {depth:5d} "
            f"{b_gates:9d} {p_gates:9d} {c_gates:9d} {s_gates:9d} "
            f"{c_ratio:6.3f} {s_c_ratio:6.3f} {s_p_ratio:6.3f}"
        )
    print("  c/b = committed/baseline gates; s/c = slot/global gates; s/p_t = slot/global prove_time")
    print("-------------------------------------\n")


def run_benchmark(
    *,
    repeat: int,
    output: Path,
    num_vectors: int,
    dim: int,
    n_list: int,
    n_probe_list: list[int],
    slot_per_list_list: list[int | None],
    top_k_list: list[int],
    n_iter: int,
    seed: int,
) -> list[dict]:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    grid = list(
        itertools.product(n_probe_list, slot_per_list_list, top_k_list)
    )

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
            workload = build_synthetic_workload(
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
            meta = workload["meta"]
            for path in PATH_NAMES:
                metrics = run_path(path, workload)
                rows.append(_row(path, repeat_id, meta, metrics))

    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print_summary(rows)
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark AuthView ZK proof paths (overhead + scaling)."
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Repetitions per (workload, path) grid point (default: 1).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/auth_zk_path_metrics.csv"),
        help="CSV output path.",
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
        help='Comma-separated n_probe values, e.g. "2,4".',
    )
    parser.add_argument(
        "--slot-per-list-list",
        type=_parse_int_list,
        default=_parse_int_list("64"),
        help='Comma-separated slot capacities, e.g. "32,64,128".',
    )
    parser.add_argument(
        "--top-k-list",
        type=_parse_int_list,
        default=_parse_int_list("5"),
        help='Comma-separated top_k values, e.g. "3,5".',
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
        n_iter=args.n_iter,
        seed=args.seed,
    )
    n_workloads = len(args.n_probe_list) * len(args.slot_per_list_list) * len(args.top_k_list)
    print(
        f"Wrote {len(rows)} rows ({n_workloads} workloads × "
        f"{len(PATH_NAMES)} paths × {args.repeat} repeats) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
