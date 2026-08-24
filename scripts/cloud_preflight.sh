#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

require_file "${PATHS_CONFIG}"
environment_output="${1:-}"
args=(
  preflight
  --project-root "${PROJECT_ROOT}"
  --paths-config "${PATHS_CONFIG}"
)
if [[ -n "${environment_output}" ]]; then
  args+=(--environment-output "${environment_output}")
fi
"${PYTHON_BIN}" -m java_vuln_research.cli "${args[@]}"

