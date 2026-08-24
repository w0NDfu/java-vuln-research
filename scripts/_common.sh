#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PATHS_CONFIG="${CLOUD_PATHS_CONFIG:-${PROJECT_ROOT}/configs/local/cloud.paths.yaml}"
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "ERROR: required file is missing: ${path}" >&2
    exit 2
  fi
}

yaml_value() {
  local path="$1"
  local key="$2"
  "${PYTHON_BIN}" -c 'import sys; from java_vuln_research.common.io import load_yaml; value=load_yaml(sys.argv[1]); item=value.get(sys.argv[2]) if isinstance(value, dict) else None; print("" if item is None else item)' "${path}" "${key}"
}

require_value() {
  local key="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    echo "ERROR: ${key} is unresolved in ${PATHS_CONFIG}" >&2
    exit 2
  fi
}
