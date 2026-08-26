#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

candidate_paths="${1:?usage: evaluate_w1_e1.sh CANDIDATE_PATHS DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"
detector_manifest="${2:?usage: evaluate_w1_e1.sh CANDIDATE_PATHS DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"
dataset_root="${3:?usage: evaluate_w1_e1.sh CANDIDATE_PATHS DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"
baseline_raw_dir="${4:?usage: evaluate_w1_e1.sh CANDIDATE_PATHS DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"
output_root="${5:?usage: evaluate_w1_e1.sh CANDIDATE_PATHS DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"

require_file "${candidate_paths}"
require_file "${detector_manifest}"
require_file "${dataset_root}/data/project_info.csv"
require_file "${dataset_root}/data/fix_info.csv"

"${PYTHON_BIN}" -m java_vuln_research.cli evaluate-w1-e1 \
  --candidate-paths "${candidate_paths}" \
  --detector-manifest "${detector_manifest}" \
  --project-info "${dataset_root}/data/project_info.csv" \
  --fix-info "${dataset_root}/data/fix_info.csv" \
  --baseline-raw-dir "${baseline_raw_dir}" \
  --output-root "${output_root}"
