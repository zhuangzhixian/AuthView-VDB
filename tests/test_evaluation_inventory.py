"""Phase 9C: tests for evaluation inventory builder and consolidation docs."""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

DOC_FILES = [
    ROOT / "docs/phase9c_evaluation_consolidation.md",
    ROOT / "docs/paper_ready_claims_and_evidence.md",
    ROOT / "docs/figure_table_decision_matrix.md",
]

FORBIDDEN_PHRASES = (
    "synthetic dataset",
    "toy dataset",
    "toy baseline",
    "small-scale",
    "sampled dataset",
    "synthetic acl overlay",
    "synthetic micro-workload",
    "synthetic micro-grid",
    "synthetic workload",
    "synthetic overlay",
    "non-toy",
)

REQUIRED_BOUNDARY_TERMS = (
    "full-base",
    "candidate-level",
    "full_base_calibration",
)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def test_inventory_script_on_mock_artifacts(tmp_path: Path):
    fig_dir = tmp_path / "figures"
    tab_dir = tmp_path / "tables"
    out_dir = tmp_path / "inventory"
    fig_dir.mkdir()
    tab_dir.mkdir()
    (fig_dir / "main_public_utility_recall.pdf").write_bytes(b"%PDF-1.4 mock")
    (tab_dir / "table_public_utility_summary.tex").write_text(
        "% mock table\n\\begin{tabular}{l}\\end{tabular}\n", encoding="utf-8"
    )

    pub = tmp_path / "public_utility.csv"
    auth = tmp_path / "auth_overlay.csv"
    cal = tmp_path / "auth_calibration.csv"
    _write_csv(
        pub,
        [
            {
                "dataset": "sift1m",
                "config": "high-acc",
                "full_base": "true",
                "num_base": "1000000",
                "num_queries": "10000",
                "recall_at_10": "0.75",
            }
        ],
    )
    _write_csv(
        auth,
        [
            {
                "dataset": "sift1m",
                "config": "high-acc",
                "policy_mode": "uniform_random",
                "selectivity": "0.1",
                "k": "10",
                "num_queries": "10000",
                "utility_gap": "0.02",
                "underfill_rate": "1.0",
                "reference_scope": "candidate_level",
            }
        ],
    )
    _write_csv(
        cal,
        [
            {
                "dataset": "sift1m",
                "config": "high-acc",
                "policy_mode": "uniform_random",
                "selectivity": "0.1",
                "k": "10",
                "num_queries": "11",
                "full_base": "True",
                "num_base": "1000000",
                "candidate_full_recall_gap": "-0.05",
                "post_full_recall_gap": "-0.1",
                "reference_scope": "full_base_calibration",
            }
        ],
    )

    py = sys.executable
    env = {**dict(__import__("os").environ), "PYTHONPATH": str(ROOT)}
    subprocess.run(
        [
            py,
            str(ROOT / "scripts/build_evaluation_inventory.py"),
            "--figures-dir",
            str(fig_dir),
            "--tables-dir",
            str(tab_dir),
            "--public-utility",
            str(pub),
            "--auth-overlay",
            str(auth),
            "--auth-calibration",
            str(cal),
            "--output-dir",
            str(out_dir),
        ],
        check=True,
        cwd=ROOT,
        env=env,
    )

    fig_inv = out_dir / "figure_table_inventory.csv"
    res_inv = out_dir / "result_summary_inventory.csv"
    assert fig_inv.is_file()
    assert res_inv.is_file()
    assert not list(out_dir.glob("*.json"))

    fig_rows = list(csv.DictReader(fig_inv.open()))
    assert any(r["artifact_type"] == "figure" for r in fig_rows)
    assert any(r.get("recommended_placement") for r in fig_rows)
    assert any("artifact_path" in r for r in fig_rows)

    res_rows = list(csv.DictReader(res_inv.open()))
    assert len(res_rows) == 3
    overlay = next(r for r in res_rows if "auth_overlay" in r["artifact_path"] or "auth.csv" in r["artifact_path"])
    assert overlay["row_count"] == "1"
    assert overlay["reference_scope"] == "candidate_level"
    cal_row = next(r for r in res_rows if "calibration" in r["artifact_path"] or "cal.csv" in r["artifact_path"])
    assert cal_row["full_base"] == "true"
    assert cal_row["reference_scope"] == "full_base_calibration"


@pytest.mark.parametrize("doc_path", DOC_FILES)
def test_consolidation_docs_exist_and_boundary_terms(doc_path: Path):
    assert doc_path.is_file(), f"missing {doc_path}"
    text = doc_path.read_text(encoding="utf-8").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"{doc_path.name} contains forbidden phrase: {phrase}"
    if doc_path.name == "phase9c_evaluation_consolidation.md":
        for term in REQUIRED_BOUNDARY_TERMS:
            assert term.replace("_", "-") in text or term in text, f"missing {term} in {doc_path.name}"


def test_figure_table_inventory_has_required_columns(tmp_path: Path):
    """Registry columns present when running on repo artifacts if they exist."""
    out_dir = tmp_path / "inv"
    pub = ROOT / "artifacts/public_utility/sift_gist_utility_summary.csv"
    if not pub.is_file():
        pytest.skip("public utility summary not present")
    py = sys.executable
    env = {**dict(__import__("os").environ), "PYTHONPATH": str(ROOT)}
    subprocess.run(
        [
            py,
            str(ROOT / "scripts/build_evaluation_inventory.py"),
            "--output-dir",
            str(out_dir),
        ],
        check=True,
        cwd=ROOT,
        env=env,
    )
    rows = list(csv.DictReader((out_dir / "figure_table_inventory.csv").open()))
    required = {"artifact_path", "phase", "recommended_placement"}
    assert required.issubset(set(rows[0].keys()))
