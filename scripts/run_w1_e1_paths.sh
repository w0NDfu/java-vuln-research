#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

endpoint_output_dir="${1:?usage: run_w1_e1_paths.sh P0A_ENDPOINT_OUTPUT W1_E1_OUTPUT [DETECTOR_MANIFEST]}"
output_root="${2:?usage: run_w1_e1_paths.sh P0A_ENDPOINT_OUTPUT W1_E1_OUTPUT [DETECTOR_MANIFEST]}"
detector_manifest="${3:-${PROJECT_ROOT}/experiments/frozen_configs/detector_manifest.yaml}"
config="${P0_CONFIG:-${PROJECT_ROOT}/configs/p0.yaml}"

require_file "${endpoint_output_dir}/external_inputs.jsonl"
require_file "${endpoint_output_dir}/security_effects.jsonl"
require_file "${detector_manifest}"
require_file "${config}"

threads="$("${PYTHON_BIN}" -c 'import sys; from java_vuln_research.common.io import load_yaml; print(load_yaml(sys.argv[1])["baseline"].get("threads", 0))' "${config}")"
ram_mb="$("${PYTHON_BIN}" -c 'import sys; from java_vuln_research.common.io import load_yaml; value=load_yaml(sys.argv[1])["baseline"].get("ram_mb"); print("" if value is None else value)' "${config}")"

args=(
  run-w1-e1-paths
  --detector-manifest "${detector_manifest}"
  --endpoint-output-dir "${endpoint_output_dir}"
  --query-root "${PROJECT_ROOT}/codeql"
  --output-root "${output_root}"
  --threads "${threads}"
)
if [[ -n "${ram_mb}" ]]; then
  args+=(--ram-mb "${ram_mb}")
fi
"${PYTHON_BIN}" -m java_vuln_research.cli "${args[@]}"
