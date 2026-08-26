#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

output_root="${1:?usage: run_p0a.sh OUTPUT_ROOT [DETECTOR_MANIFEST]}"
detector_manifest="${2:-${PROJECT_ROOT}/experiments/frozen_configs/detector_manifest.yaml}"
config="${P0_CONFIG:-${PROJECT_ROOT}/configs/p0.yaml}"
codeql_bin="${CODEQL_BIN:-codeql}"
require_file "${detector_manifest}"
require_file "${config}"

threads="$("${PYTHON_BIN}" -c 'import sys; from java_vuln_research.common.io import load_yaml; print(load_yaml(sys.argv[1])["baseline"].get("threads", 0))' "${config}")"
ram_mb="$("${PYTHON_BIN}" -c 'import sys; from java_vuln_research.common.io import load_yaml; value=load_yaml(sys.argv[1])["baseline"].get("ram_mb"); print("" if value is None else value)' "${config}")"

args=(
  discover-p0a
  --detector-manifest "${detector_manifest}"
  --query-root "${PROJECT_ROOT}/codeql"
  --output-root "${output_root}"
  --threads "${threads}"
  --codeql "${codeql_bin}"
)
if [[ -n "${ram_mb}" ]]; then
  args+=(--ram-mb "${ram_mb}")
fi
"${PYTHON_BIN}" -m java_vuln_research.cli "${args[@]}"
