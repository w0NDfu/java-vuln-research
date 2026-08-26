#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

dataset_name="${1:?usage: run_p0.sh DATASET_NAME DATASET_REVISION [RUN_ID] [DETECTOR_MANIFEST]}"
dataset_revision="${2:?usage: run_p0.sh DATASET_NAME DATASET_REVISION [RUN_ID] [DETECTOR_MANIFEST]}"
run_id="${3:-}"
detector_manifest="${4:-${PROJECT_ROOT}/experiments/frozen_configs/detector_manifest.yaml}"
require_file "${PATHS_CONFIG}"
require_file "${detector_manifest}"

args=(
  run-e0
  --project-root "${PROJECT_ROOT}"
  --paths-config "${PATHS_CONFIG}"
  --detector-manifest "${detector_manifest}"
  --config "${PROJECT_ROOT}/configs/p0.yaml"
  --dataset-name "${dataset_name}"
  --dataset-revision "${dataset_revision}"
  --codeql "${CODEQL_BIN:-codeql}"
)
if [[ -n "${run_id}" ]]; then
  args+=(--run-id "${run_id}")
fi
"${PYTHON_BIN}" -m java_vuln_research.cli "${args[@]}"
