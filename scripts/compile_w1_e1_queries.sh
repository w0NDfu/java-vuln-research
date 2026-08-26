#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

codeql_bin="${CODEQL_BIN:-codeql}"
queries=(
  AnalysisAnchors
  InputForward
  EffectBackward
  DataCallConnected
  DataCallFrontier
)

for query in "${queries[@]}"; do
  echo "==== ${query} ===="
  "${codeql_bin}" query compile "${PROJECT_ROOT}/codeql/candidate_path/${query}.ql"
done
