#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

require_file "${PATHS_CONFIG}"
codeql_db_root="${CODEQL_DB_ROOT:-$(yaml_value "${PATHS_CONFIG}" codeql_db_root)}"
require_value codeql_db_root "${codeql_db_root}"
output="${1:-${PROJECT_ROOT}/experiment-output/inventory/codeql_db_inventory.csv}"
"${PYTHON_BIN}" -m java_vuln_research.cli inventory-dbs \
  --root "${codeql_db_root}" \
  --output "${output}"

