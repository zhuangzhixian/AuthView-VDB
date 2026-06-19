#!/usr/bin/env bash
# Phase 8C: resumable public utility baseline for screen/tmux sessions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="${ROOT}/artifacts/logs/phase8c_public_utility_screen.log"
mkdir -p artifacts/logs artifacts/public_utility/traces artifacts/public_utility/per_config

{
  echo "=== Phase 8C public utility screen run: $(date -u '+%Y-%m-%d %H:%M UTC') ==="
  PYTHONPATH=. python scripts/run_public_utility_baseline.py \
    --datasets sift1m,gist1m \
    --configs high-acc,zk-opt \
    --data-root data \
    --output-dir artifacts/public_utility \
    --resume \
    --skip-existing

  PYTHONPATH=. python scripts/plot_public_utility_figures.py \
    --input artifacts/public_utility/sift_gist_utility_summary.csv \
    --output-dir artifacts/figures

  PYTHONPATH=. python scripts/make_public_utility_table.py \
    --input artifacts/public_utility/sift_gist_utility_summary.csv \
    --output artifacts/tables/table_public_utility_summary.tex

  echo "=== Phase 8C screen run complete: $(date -u '+%Y-%m-%d %H:%M UTC') ==="
} 2>&1 | tee -a "$LOG"
