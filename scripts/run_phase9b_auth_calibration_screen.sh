#!/usr/bin/env bash
# Phase 9B: run full authorized-reference calibration in screen (long-running).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHONPATH=. .venv/bin/python scripts/select_authorized_calibration_queries.py \
  --auth-summary artifacts/auth_overlay/public_trace_auth_summary.csv \
  --auth-metrics artifacts/auth_overlay/public_trace_auth_metrics.csv \
  --output artifacts/auth_calibration/calibration_queries.csv \
  --queries-per-bucket 5 \
  --max-queries-per-dataset 500 \
  --seed 42

PYTHONPATH=. .venv/bin/python scripts/calibrate_full_authorized_reference.py \
  --calibration-queries artifacts/auth_calibration/calibration_queries.csv \
  --data-root data/public \
  --overlay-dir artifacts/auth_overlay \
  --trace-dir artifacts/public_utility/traces \
  --output-dir artifacts/auth_calibration \
  --ks 1,10,100 \
  --chunk-size 50000 \
  --resume \
  --skip-existing

PYTHONPATH=. .venv/bin/python scripts/plot_authorized_calibration_figures.py \
  --input artifacts/auth_calibration/full_authorized_reference_summary.csv \
  --output-dir artifacts/figures

PYTHONPATH=. .venv/bin/python scripts/make_authorized_calibration_table.py \
  --input artifacts/auth_calibration/full_authorized_reference_summary.csv \
  --output artifacts/tables/table_authorized_reference_calibration.tex

echo "Phase 9B calibration complete."
