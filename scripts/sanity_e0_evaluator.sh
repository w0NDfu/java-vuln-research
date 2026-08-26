#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

detector_manifest="${1:?usage: sanity_e0_evaluator.sh DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"
dataset_root="${2:?usage: sanity_e0_evaluator.sh DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"
baseline_raw_dir="${3:?usage: sanity_e0_evaluator.sh DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"
output_root="${4:?usage: sanity_e0_evaluator.sh DETECTOR_MANIFEST DATASET_ROOT E0_RAW_RUN OUTPUT_ROOT}"

require_file "${detector_manifest}"
require_file "${dataset_root}/data/project_info.csv"
require_file "${dataset_root}/data/fix_info.csv"
require_file "${baseline_raw_dir}/baseline/baseline_output.jsonl"

"${PYTHON_BIN}" -m java_vuln_research.cli sanity-e0-evaluator \
  --detector-manifest "${detector_manifest}" \
  --project-info "${dataset_root}/data/project_info.csv" \
  --fix-info "${dataset_root}/data/fix_info.csv" \
  --baseline-raw-dir "${baseline_raw_dir}" \
  --output-root "${output_root}"
