#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(pwd)}"
artifact_base="${2:-/workspace/experiment-output/artifacts}"
phase="${3:-all}"
m7_root="$artifact_base/work1-agent-v11/m7_agent"
freeze_root="$m7_root/killtest_freeze"
output_root="$m7_root/killtest"
m6_root="$artifact_base/work1-agent-v11/m6_killtest"

if [[ "$phase" == "detector" || "$phase" == "all" ]]; then
  PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" python -m java_vuln_research.work1_agent.m7_killtest.detector \
    --frozen-manifest "$freeze_root/detector_manifest.json" \
    --repository-root "$repo_root" \
    --schema-root "$repo_root/schemas" \
    --output-root "$output_root"
fi

if [[ "$phase" == "evaluator" || "$phase" == "all" ]]; then
  PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" python -m java_vuln_research.work1_agent.m7_killtest.evaluator \
    --output-root "$output_root" \
    --freeze-root "$freeze_root" \
    --m6-root "$m6_root"
fi
