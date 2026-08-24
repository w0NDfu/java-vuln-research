#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

output_root="${1:?usage: run_baseline.sh OUTPUT_ROOT [DETECTOR_MANIFEST]}"
detector_manifest="${2:-${PROJECT_ROOT}/experiments/frozen_configs/detector_manifest.yaml}"
config="${P0_CONFIG:-${PROJECT_ROOT}/configs/p0.yaml}"
require_file "${detector_manifest}"
require_file "${config}"

query_suite="$("${PYTHON_BIN}" -c 'import sys; from java_vuln_research.common.io import load_yaml; print(load_yaml(sys.argv[1])["baseline"]["query_suite"])' "${config}")"
threads="$("${PYTHON_BIN}" -c 'import sys; from java_vuln_research.common.io import load_yaml; print(load_yaml(sys.argv[1])["baseline"].get("threads", 0))' "${config}")"

"${PYTHON_BIN}" -m java_vuln_research.cli baseline \
  --detector-manifest "${detector_manifest}" \
  --output-root "${output_root}" \
  --query-suite "${query_suite}" \
  --threads "${threads}"
