#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(pwd)}"
artifact_root="${2:-/workspace/experiment-output/artifacts/work1-agent-v11/m7_agent}"
mode="${3:-deterministic-mock}"
git_sha="$(git -C "$repo_root" rev-parse HEAD)"

PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" python -m java_vuln_research.work1_agent.agent.controlled_smoke \
  --repository-root "$repo_root/tests/fixtures/work1_agent_m7" \
  --schema-root "$repo_root/schemas" \
  --artifact-root "$artifact_root" \
  --git-sha "$git_sha" \
  --mode "$mode"
