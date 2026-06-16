#!/usr/bin/env python3
"""
Phase 2D: lightweight overhead snapshot for AuthView ZK proof paths.

Compares four paths on the same synthetic IVF-PQ workload:
  baseline, auth_all_visible, auth_policy, auth_committed
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import numpy as np

from auth_reference.attacks import DEFAULT_CHECKPOINT
from auth_reference.auth_commitment import next_pow2
from auth_reference.v3db_adapter import (
    build_candidates_from_v3db_query,
    build_committed_auth_witness,
    build_partial_visible_labels,
    build_synthetic_user_context,
    encode_slot_auth_labels_for_zk,
    encode_user_context_for_zk,
)
from ivf_pq.zk import ivf_pq_learn
from tests.test_auth_zk_all_visible import _build_merkle_proof_inputs
from zk_IVF_PQ.zk_IVF_PQ import (
    py_set_based_auth_all_visible_with_merkle,
    py_set_based_auth_committed_with_merkle,
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
)


def _auth_tree_depth(n_probe: int, slot_per_list: int) -> int:
    padded = next_pow2(n_probe * slot_per_list)
    depth = 0
    n = padded
    while n > 1:
        n //= 2
        depth += 1
    return depth


def _visible_ratio(
    candidates,
    user,
    checkpoint,
) -> float:
    from auth_reference.policy import compute_visibility

    valid = [c for c in candidates if c.valid]
    if not valid:
        return 0.0
    visible = sum(
        1 for c in valid if compute_visibility(user, c.label, checkpoint)
    )
    return visible / len(valid)


def build_synthetic_workload(
    *,
    num_vectors: int,
    dim: int,
    n_list: int,
    n_probe: int,
    top_k: int,
    n_iter: int,
    seed: int,
):
    """Mirror test fixtures: IVF-PQ learn + Merkle proof inputs + partial-visible labels."""
    rng = np.random.default_rng(seed)
    vecs = rng.integers(0, 4096, size=(num_vectors, dim), dtype=np.int64)
    query = rng.integers(0, 4096, size=dim, dtype=np.int64)
    _labels, center, code_books, quant_vecs, id_groups = ivf_pq_learn(
        vecs, n_list=n_list, n_iter=n_iter
    )

    inputs = _build_merkle_proof_inputs(
        query, center, code_books, quant_vecs, id_groups, n_probe
    )
    buffers = inputs["buffers"]
    slot_per_list = int(buffers.capacity)

    user = build_synthetic_user_context(clearance=10, epoch=DEFAULT_CHECKPOINT.epoch)
    checkpoint = DEFAULT_CHECKPOINT

    _candidates, slot_rows, _buffers = build_candidates_from_v3db_query(
        query,
        center,
        code_books,
        quant_vecs,
        id_groups,
        n_probe,
        labels={},
    )
    valid_rows = [r for r in slot_rows if r[4]]
    by_dist = sorted(valid_rows, key=lambda r: r[5])
    invisible_cids = {by_dist[0][3], by_dist[1][3]} if len(valid_rows) >= 2 else set()
    visible_cids = {r[3] for r in valid_rows} - invisible_cids
    labels = build_partial_visible_labels(
        visible_cids, invisible_cids, user, checkpoint
    )

    candidates, _slot_rows, buffers = build_candidates_from_v3db_query(
        query,
        center,
        code_books,
        quant_vecs,
        id_groups,
        n_probe,
        labels,
    )
    user_w = encode_user_context_for_zk(user, checkpoint)
    slot_w = encode_slot_auth_labels_for_zk(buffers, labels)
    committed_w = build_committed_auth_witness(buffers, labels)

    meta = {
        "num_vectors": num_vectors,
        "dim": dim,
        "n_list": n_list,
        "n_probe": n_probe,
        "slot_per_list": slot_per_list,
        "top_k": top_k,
        "N_sel": n_probe * slot_per_list,
        "visible_ratio": _visible_ratio(candidates, user, checkpoint),
        "auth_tree_depth": _auth_tree_depth(n_probe, slot_per_list),
    }

    return {
        "inputs": inputs,
        "top_k": top_k,
        "user_w": user_w,
        "slot_w": slot_w,
        "committed_w": committed_w,
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
    else:
        raise ValueError(f"unknown path: {path}")

    return metrics


def _row(path: str, repeat_id: int, meta: dict, metrics: tuple) -> dict:
    build_time, prove_time, verify_time, proof_size, memory, gates = metrics
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
        "auth_tree_depth": meta["auth_tree_depth"],
        "build_time": build_time,
        "prove_time": prove_time,
        "verify_time": verify_time,
        "proof_size": proof_size,
        "memory": memory,
        "gates": gates,
    }


def print_summary(rows: list[dict]) -> None:
    """Print a short stdout summary from repeat_id=0 rows (or first available)."""
    by_path = {}
    for row in rows:
        rid = int(row["repeat_id"])
        if rid not in by_path.get(row["path"], {}):
            by_path.setdefault(row["path"], {})[rid] = row

    def pick(path: str) -> dict | None:
        paths = by_path.get(path, {})
        return paths.get(0) or (paths[min(paths)] if paths else None)

    baseline = pick("baseline")
    committed = pick("auth_committed")
    policy = pick("auth_policy")
    if not baseline or not committed:
        return

    print("\n--- overhead summary (repeat_id=0) ---")
    print(f"baseline gates:        {baseline['gates']}")
    if policy:
        print(f"auth_policy gates:     {policy['gates']}")
    print(f"committed-auth gates:  {committed['gates']}")
    b_prove = float(baseline["prove_time"])
    c_prove = float(committed["prove_time"])
    b_size = int(baseline["proof_size"])
    c_size = int(committed["proof_size"])
    if b_prove > 0:
        print(f"committed/baseline prove_time ratio: {c_prove / b_prove:.3f}")
    if b_size > 0:
        print(f"committed/baseline proof_size ratio: {c_size / b_size:.3f}")
    print("--------------------------------------\n")


def run_benchmark(
    *,
    repeat: int,
    output: Path,
    num_vectors: int,
    dim: int,
    n_list: int,
    n_probe: int,
    top_k: int,
    n_iter: int,
    seed: int,
) -> list[dict]:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    for repeat_id in range(repeat):
        workload = build_synthetic_workload(
            num_vectors=num_vectors,
            dim=dim,
            n_list=n_list,
            n_probe=n_probe,
            top_k=top_k,
            n_iter=n_iter,
            seed=seed + repeat_id,
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
        description="Benchmark AuthView ZK proof path overhead (Phase 2D)."
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Number of repetitions per path (default: 1; use 3 for fuller snapshot).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/auth_zk_path_metrics.csv"),
        help="CSV output path (default: artifacts/auth_zk_path_metrics.csv).",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--num-vectors", type=int, default=400)
    parser.add_argument("--dim", type=int, default=64)
    parser.add_argument("--n-list", type=int, default=8)
    parser.add_argument("--n-probe", type=int, default=4)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--n-iter", type=int, default=8)
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
        n_probe=args.n_probe,
        top_k=args.top_k,
        n_iter=args.n_iter,
        seed=args.seed,
    )
    print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
