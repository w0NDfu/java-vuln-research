#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

detector_output="${1:?usage: evaluate_p0a.sh DETECTOR_OUTPUT DATASET_ROOT OUTPUT_ROOT}"
dataset_root="${2:?usage: evaluate_p0a.sh DETECTOR_OUTPUT DATASET_ROOT OUTPUT_ROOT}"
output_root="${3:?usage: evaluate_p0a.sh DETECTOR_OUTPUT DATASET_ROOT OUTPUT_ROOT}"

require_file "${detector_output}/external_inputs.jsonl"
require_file "${detector_output}/security_effects.jsonl"
require_file "${dataset_root}/data/project_info.csv"
require_file "${dataset_root}/data/fix_info.csv"

"${PYTHON_BIN}" -m java_vuln_research.cli evaluate-p0a \
  --detector-output "${detector_output}" \
  --project-info "${dataset_root}/data/project_info.csv" \
  --fix-info "${dataset_root}/data/fix_info.csv" \
  --output-root "${output_root}"
