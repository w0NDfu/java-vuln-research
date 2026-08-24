#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

require_file "${PATHS_CONFIG}"
dataset_root="${DATASET_ROOT:-$(yaml_value "${PATHS_CONFIG}" dataset_root)}"
require_value dataset_root "${dataset_root}"
output="${1:-${PROJECT_ROOT}/experiment-output/inventory/dataset_inventory.csv}"
"${PYTHON_BIN}" -m java_vuln_research.cli inventory-datasets \
  --root "${dataset_root}" \
  --output "${output}"

