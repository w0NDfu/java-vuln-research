#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-/workspace/java-vuln-research-m7}"
git_sha="$(git -C "$repo_root" rev-parse HEAD)"
artifact_root="${2:-/workspace/experiment-output/artifacts/work1-agent-v11/m7_real_model_preflight/$git_sha}"

cd "$repo_root"
PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" python -m java_vuln_research.work1_agent.agent.real_model_preflight \
  --config "$repo_root/experiments/frozen_configs/m7_real_model_preflight.json" \
  --schema-root "$repo_root/schemas" \
  --artifact-root "$artifact_root" \
  --git-sha "$git_sha"
