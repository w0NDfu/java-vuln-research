#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(pwd)}"
artifact_base="${2:-/workspace/experiment-output/artifacts}"
output_root="${3:-$artifact_base/work1-agent-v11/m7_agent/killtest_freeze}"
v11_root="$artifact_base/work1-agent-v11"
git_sha="$(git -C "$repo_root" rev-parse HEAD)"

PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" python -m java_vuln_research.work1_agent.agent.killtest_manifest \
  --selected-cases "$v11_root/m6_killtest/selected_cases.csv" \
  --project-inventory "$v11_root/m1_repository_index/project_inventory.csv" \
  --m1-root "$v11_root/m1_repository_index" \
  --m2-root "$v11_root/m2_smoke" \
  --m3-root "$v11_root/m3_codeql_tools" \
  --m4-root "$v11_root/m4_proposals" \
  --m5-root "$v11_root/m5_hybrid_graph" \
  --baseline-root "$artifact_base/work1/p0_b_route_b/W1-P0-B-ROUTE-B-20260827-002" \
  --schema-root "$repo_root/schemas" \
  --output-root "$output_root" \
  --git-sha "$git_sha"
