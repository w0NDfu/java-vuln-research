#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 <java-repository-root> <output-directory>" >&2
  exit 2
fi

repository_root="$1"
output_directory="$2"

if [[ ! -d "${repository_root}" ]]; then
  echo "ERROR: Java repository root is not a directory: ${repository_root}" >&2
  exit 2
fi

mkdir -p "${output_directory}"
"${PYTHON_BIN}" -m java_vuln_research.work1_agent.repository.indexer \
  --repository-root "${repository_root}" \
  --output "${output_directory}/program_entities.jsonl" \
  --summary "${output_directory}/summary.json" \
  --diagnostics "${output_directory}/diagnostics.jsonl"
