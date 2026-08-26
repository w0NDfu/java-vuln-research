#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

endpoint_output_dir="${1:?usage: run_w1_e1.sh P0A_ENDPOINT_OUTPUT E0_RAW_RUN DATASET_NAME DATASET_REVISION [RUN_ID]}"
baseline_raw_dir="${2:?usage: run_w1_e1.sh P0A_ENDPOINT_OUTPUT E0_RAW_RUN DATASET_NAME DATASET_REVISION [RUN_ID]}"
dataset_name="${3:?usage: run_w1_e1.sh P0A_ENDPOINT_OUTPUT E0_RAW_RUN DATASET_NAME DATASET_REVISION [RUN_ID]}"
dataset_revision="${4:?usage: run_w1_e1.sh P0A_ENDPOINT_OUTPUT E0_RAW_RUN DATASET_NAME DATASET_REVISION [RUN_ID]}"
run_id="${5:-W1-E1-$(date -u +%Y%m%d-%H%M%S)}"

require_file "${PATHS_CONFIG}"
require_file "${endpoint_output_dir}/external_inputs.jsonl"
require_file "${endpoint_output_dir}/security_effects.jsonl"
require_file "${baseline_raw_dir}/baseline/baseline_output.jsonl"
dataset_root="$(yaml_value "${PATHS_CONFIG}" dataset_root)"
output_base="$(yaml_value "${PATHS_CONFIG}" experiment_output_root)"
require_value "dataset_root" "${dataset_root}"
require_value "experiment_output_root" "${output_base}"
output_root="${output_base}/${run_id}"
if [[ -e "${output_root}" ]]; then
  echo "ERROR: output already exists: ${output_root}" >&2
  exit 2
fi

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
bash "${PROJECT_ROOT}/scripts/run_w1_e1_paths.sh" "${endpoint_output_dir}" "${output_root}"
detector_exit=$?
set -e
# A partial detector run still has frozen candidate output that the independent
# evaluator must measure. A hard setup failure has no evaluable artifact.
if [[ ! -f "${output_root}/candidate_paths.jsonl" || ! -f "${output_root}/detector_metrics.json" ]]; then
  exit "${detector_exit}"
fi
bash "${PROJECT_ROOT}/scripts/evaluate_w1_e1.sh" \
  "${output_root}/candidate_paths.jsonl" \
  "${PROJECT_ROOT}/experiments/frozen_configs/detector_manifest.yaml" \
  "${dataset_root}" \
  "${baseline_raw_dir}" \
  "${output_root}"
"${PYTHON_BIN}" -m java_vuln_research.cli report-w1-e1 \
  --run-id "${run_id}" \
  --raw-run-dir "${output_root}" \
  --baseline-raw-dir "${baseline_raw_dir}" \
  --project-root "${PROJECT_ROOT}" \
  --dataset-name "${dataset_name}" \
  --dataset-revision "${dataset_revision}" \
  --detector-manifest "${PROJECT_ROOT}/experiments/frozen_configs/detector_manifest.yaml" \
  --config "${PROJECT_ROOT}/configs/p0.yaml" \
  --started-at "${started_at}" \
  --command "scripts/run_w1_e1.sh ${endpoint_output_dir} ${baseline_raw_dir} ${dataset_name} ${dataset_revision} ${run_id}"
exit "${detector_exit}"
