#!/usr/bin/env bash
set -euo pipefail

BASELINE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_PROJECT_ROOT="$(cd "${BASELINE_SCRIPT_DIR}/../.." && pwd)"
BASELINE_PYTHON="${BASELINE_PYTHON:-python3}"
BASELINE_MANIFEST="${BASELINE_MANIFEST:-${BASELINE_PROJECT_ROOT}/experiments/frozen_configs/baseline_repro_dev18_manifest.csv}"
BASELINE_METHOD_ROOT="${BASELINE_METHOD_ROOT:-/workspace/baseline-repro-methods}"
BASELINE_ARTIFACT_ROOT="${BASELINE_ARTIFACT_ROOT:-/workspace/experiment-output/artifacts/baseline_reproduction}"

manifest() {
  "${BASELINE_PYTHON}" "${BASELINE_SCRIPT_DIR}/manifest.py" --manifest "${BASELINE_MANIFEST}" "$@"
}

manifest_field() {
  manifest get "$1" "$2"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command is unavailable: $1" >&2
    exit 2
  fi
}

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "ERROR: required file is missing: $1" >&2
    exit 2
  fi
}

require_dir() {
  if [[ ! -d "$1" ]]; then
    echo "ERROR: required directory is missing: $1" >&2
    exit 2
  fi
}

assert_frozen_revision() {
  local project_id="$1"
  local source_path expected observed
  source_path="$(manifest_field "${project_id}" source_path)"
  expected="$(manifest_field "${project_id}" observed_cloud_revision)"
  require_dir "${source_path}"
  observed="$(git -C "${source_path}" rev-parse HEAD)"
  if [[ "${observed}" != "${expected}" ]]; then
    echo "ERROR: ${project_id} revision mismatch: expected ${expected}, got ${observed}" >&2
    exit 3
  fi
}

new_run_root() {
  local method="$1"
  local run_id="$2"
  local project_id="$3"
  local root="${BASELINE_ARTIFACT_ROOT}/raw/${method}/${run_id}/${project_id}"
  if [[ -e "${root}" ]]; then
    echo "ERROR: refusing to overwrite existing run root: ${root}" >&2
    exit 4
  fi
  mkdir -p "${root}/upstream"
  printf '%s\n' "${root}"
}
