"""Phase 9A: shared authorization overlay utilities for public benchmark traces."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np

REFERENCE_SCOPE = "candidate_level"
DEFAULT_SELECTIVITIES = (0.1, 0.25, 0.5, 0.75)
DEFAULT_POLICY_MODES = ("uniform_random", "clustered_acl", "skewed_acl")
DEFAULT_KS = (1, 10, 100)

SUMMARY_OVERLAY_FIELDS = (
    "dataset",
    "policy_mode",
    "selectivity_target",
    "selectivity_observed",
    "seed",
    "num_base",
    "num_acl_classes",
    "visible_count",
    "mask_path",
    "sample_csv_path",
)

METRICS_FIELDS = (
    "dataset",
    "config",
    "policy_mode",
    "selectivity",
    "k",
    "num_queries",
    "visible_ratio",
    "unrestricted_recall",
    "post_filter_recall",
    "authorized_recall",
    "underfill_rate",
    "avg_visible_results",
    "violation_count",
    "violation_rate",
    "utility_gap",
    "affected_query_rate",
    "reference_scope",
)

EXPECTED_NUM_BASE = {"sift1m": 1_000_000, "gist1m": 1_000_000}


def seed_for(dataset: str, policy_mode: str, selectivity: float, base_seed: int) -> int:
    tag = f"{dataset}:{policy_mode}:{selectivity}:{base_seed}"
    return int(np.abs(hash(tag)) % (2**31 - 1))


def generate_uniform_random_mask(
    num_base: int,
    selectivity: float,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    visible = rng.random(num_base) < selectivity
    acl_class = rng.integers(0, max(4, int(1 / max(selectivity, 0.01))), size=num_base)
    return visible.astype(bool), acl_class.astype(np.int32)


def generate_clustered_acl_mask(
    num_base: int,
    selectivity: float,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    num_classes = max(8, min(256, int(round(1.0 / max(selectivity, 0.05)))))
    acl_class = (np.arange(num_base, dtype=np.int32) % num_classes).astype(np.int32)
    num_visible_classes = max(1, int(round(num_classes * selectivity)))
    visible_classes = set(range(num_visible_classes))
    visible = np.array([c in visible_classes for c in acl_class], dtype=bool)
    return visible, acl_class


def generate_skewed_acl_mask(
    num_base: int,
    selectivity: float,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    num_classes = max(16, min(512, int(round(2.0 / max(selectivity, 0.05)))))
    weights = 1.0 / (np.arange(1, num_classes + 1, dtype=np.float64) ** 1.2)
    weights /= weights.sum()
    acl_class = rng.choice(num_classes, size=num_base, p=weights).astype(np.int32)
    class_counts = np.bincount(acl_class, minlength=num_classes)
    target_visible = int(round(num_base * selectivity))
    # Prefer rare (tail) ACL classes first for skewed access patterns.
    order = np.argsort(class_counts)
    visible = np.zeros(num_base, dtype=bool)
    running = 0
    for cls in order:
        members = np.where(acl_class == cls)[0]
        visible[members] = True
        running += int(members.size)
        if running >= target_visible:
            break
    current = int(visible.sum())
    if current > target_visible:
        drop = rng.choice(np.where(visible)[0], size=current - target_visible, replace=False)
        visible[drop] = False
    elif current < target_visible:
        add = rng.choice(np.where(~visible)[0], size=target_visible - current, replace=False)
        visible[add] = True
    return visible, acl_class


def generate_overlay(
    *,
    dataset: str,
    policy_mode: str,
    selectivity: float,
    num_base: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, float]:
    rng = np.random.default_rng(seed)
    if policy_mode == "uniform_random":
        visible, acl_class = generate_uniform_random_mask(num_base, selectivity, rng)
    elif policy_mode == "clustered_acl":
        visible, acl_class = generate_clustered_acl_mask(num_base, selectivity, rng)
    elif policy_mode == "skewed_acl":
        visible, acl_class = generate_skewed_acl_mask(num_base, selectivity, rng)
    else:
        raise ValueError(f"unknown policy_mode: {policy_mode}")
    observed = float(visible.mean())
    return visible, acl_class, observed


def unrestricted_recall(pred: np.ndarray, gt_row: np.ndarray, k: int) -> float:
    best = int(gt_row[0])
    prefix = pred[: min(k, pred.size)]
    return 1.0 if best in prefix else 0.0


def post_filter_results(pred: np.ndarray, visible: np.ndarray, k: int) -> list[int]:
    out: list[int] = []
    for cid in pred[:k]:
        idx = int(cid)
        if idx < 0 or idx >= visible.size:
            continue
        if visible[idx]:
            out.append(idx)
    return out


def authorized_candidate_results(
    pred: np.ndarray,
    visible: np.ndarray,
    k: int,
    *,
    candidate_depth: int,
) -> list[int]:
    out: list[int] = []
    for cid in pred[:candidate_depth]:
        idx = int(cid)
        if idx < 0 or idx >= visible.size:
            continue
        if visible[idx]:
            out.append(idx)
            if len(out) >= k:
                break
    return out


def recall_from_result(result: list[int], gt_row: np.ndarray) -> float:
    best = int(gt_row[0])
    return 1.0 if best in result else 0.0


def count_violations(result: list[int], visible: np.ndarray) -> int:
    violations = 0
    for cid in result:
        idx = int(cid)
        if 0 <= idx < visible.size and not visible[idx]:
            violations += 1
    return violations


@dataclass
class TraceEvalAggregate:
    dataset: str
    config: str
    policy_mode: str
    selectivity: float
    k: int
    num_queries: int
    visible_ratio: float
    unrestricted_recall: float
    post_filter_recall: float
    authorized_recall: float
    underfill_rate: float
    avg_visible_results: float
    violation_count: int
    violation_rate: float
    utility_gap: float
    affected_query_rate: float
    reference_scope: str = REFERENCE_SCOPE

    def to_row(self) -> dict[str, str | float | int]:
        return {
            "dataset": self.dataset,
            "config": self.config,
            "policy_mode": self.policy_mode,
            "selectivity": self.selectivity,
            "k": self.k,
            "num_queries": self.num_queries,
            "visible_ratio": self.visible_ratio,
            "unrestricted_recall": self.unrestricted_recall,
            "post_filter_recall": self.post_filter_recall,
            "authorized_recall": self.authorized_recall,
            "underfill_rate": self.underfill_rate,
            "avg_visible_results": self.avg_visible_results,
            "violation_count": self.violation_count,
            "violation_rate": self.violation_rate,
            "utility_gap": self.utility_gap,
            "affected_query_rate": self.affected_query_rate,
            "reference_scope": self.reference_scope,
        }


def evaluate_trace_with_visibility(
    *,
    pred: np.ndarray,
    gt: np.ndarray,
    visible: np.ndarray,
    dataset: str,
    config: str,
    policy_mode: str,
    selectivity: float,
    ks: Iterable[int],
    candidate_depth: int,
) -> list[TraceEvalAggregate]:
    num_queries = int(pred.shape[0])
    visible_ratios_query: list[float] = []
    for i in range(num_queries):
        p = pred[i, :candidate_depth]
        vis_count = sum(1 for cid in p if 0 <= int(cid) < visible.size and visible[int(cid)])
        visible_ratios_query.append(vis_count / max(candidate_depth, 1))
    mean_visible_ratio = float(np.mean(visible_ratios_query))

    aggregates: list[TraceEvalAggregate] = []
    for k in ks:
        unrestricted_hits: list[float] = []
        post_hits: list[float] = []
        auth_hits: list[float] = []
        underfills: list[float] = []
        avg_visible: list[float] = []
        violations = 0
        affected = 0

        for i in range(num_queries):
            p = pred[i]
            g = gt[i]
            unrestricted_hits.append(unrestricted_recall(p, g, k))
            post = post_filter_results(p, visible, k)
            auth = authorized_candidate_results(
                p, visible, k, candidate_depth=candidate_depth
            )
            post_hits.append(recall_from_result(post, g))
            auth_hits.append(recall_from_result(auth, g))
            underfills.append(1.0 if len(post) < k else 0.0)
            avg_visible.append(float(len(post)))
            violations += count_violations(post, visible)
            if post != auth:
                affected += 1

        aggregates.append(
            TraceEvalAggregate(
                dataset=dataset,
                config=config,
                policy_mode=policy_mode,
                selectivity=selectivity,
                k=k,
                num_queries=num_queries,
                visible_ratio=mean_visible_ratio,
                unrestricted_recall=float(np.mean(unrestricted_hits)),
                post_filter_recall=float(np.mean(post_hits)),
                authorized_recall=float(np.mean(auth_hits)),
                underfill_rate=float(np.mean(underfills)),
                avg_visible_results=float(np.mean(avg_visible)),
                violation_count=violations,
                violation_rate=violations / max(num_queries, 1),
                utility_gap=float(np.mean(auth_hits)) - float(np.mean(post_hits)),
                affected_query_rate=affected / max(num_queries, 1),
            )
        )
    return aggregates


def write_sample_object_visibility_csv(
    path: Path,
    visible: np.ndarray,
    acl_class: np.ndarray,
    *,
    sample_size: int = 10_000,
    seed: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    num_base = visible.size
    n = min(sample_size, num_base)
    rng = np.random.default_rng(seed + 17)
    ids = rng.choice(num_base, size=n, replace=False)
    ids.sort()
    lines = ["object_id,acl_class,visible\n"]
    for oid in ids:
        lines.append(f"{int(oid)},{int(acl_class[oid])},{str(bool(visible[oid])).lower()}\n")
    path.write_text("".join(lines), encoding="utf-8")


def save_visibility_npz(
    path: Path,
    *,
    visible: np.ndarray,
    acl_class: np.ndarray,
    dataset: str,
    policy_mode: str,
    selectivity_target: float,
    selectivity_observed: float,
    seed: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path,
        visible=visible.astype(np.uint8),
        acl_class=acl_class,
        dataset=dataset,
        policy_mode=policy_mode,
        selectivity_target=selectivity_target,
        selectivity_observed=selectivity_observed,
        seed=seed,
        num_base=int(visible.size),
    )


def load_visibility_npz(path: Path) -> tuple[np.ndarray, dict[str, str | float]]:
    with np.load(path, allow_pickle=False) as data:
        visible = data["visible"].astype(bool)
        meta = {
            "dataset": str(data["dataset"]) if "dataset" in data else "",
            "policy_mode": str(data["policy_mode"]) if "policy_mode" in data else "",
            "selectivity_target": float(data["selectivity_target"])
            if "selectivity_target" in data
            else float("nan"),
        }
    return visible, meta
