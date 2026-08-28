#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

output_dir="${1:-${BASELINE_ARTIFACT_ROOT}/preflight-$(date -u +%Y%m%d-%H%M%S)}"
if [[ -e "${output_dir}" ]]; then
  echo "ERROR: refusing to overwrite preflight output: ${output_dir}" >&2
  exit 4
fi
mkdir -p "${output_dir}"

manifest validate >"${output_dir}/manifest_validation.json"

{
  printf 'captured_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'host=%s\n' "$(hostname)"
  printf 'harness_branch=%s\n' "$(git -C "${BASELINE_PROJECT_ROOT}" branch --show-current)"
  printf 'harness_head=%s\n' "$(git -C "${BASELINE_PROJECT_ROOT}" rev-parse HEAD)"
  printf 'python=%s\n' "$(python3 --version 2>&1)"
  printf 'git=%s\n' "$(git --version 2>&1)"
  printf 'codeql=%s\n' "$(codeql version --format=terse 2>/dev/null || printf UNAVAILABLE)"
  printf 'docker=%s\n' "$(docker --version 2>/dev/null || printf UNAVAILABLE)"
  printf 'docker_compose=%s\n' "$(docker compose version 2>/dev/null || printf UNAVAILABLE)"
  printf 'conda=%s\n' "$(conda --version 2>/dev/null || printf UNAVAILABLE)"
  printf 'disk=%s\n' "$(df -h /workspace 2>/dev/null | tail -n 1 || printf UNAVAILABLE)"
} >"${output_dir}/environment.txt"

{
  printf 'credential,state\n'
  [[ -n "${OPENAI_API_KEY:-}" ]] && printf 'OPENAI_API_KEY,SET\n' || printf 'OPENAI_API_KEY,UNSET\n'
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] && printf 'ANTHROPIC_API_KEY,SET\n' || printf 'ANTHROPIC_API_KEY,UNSET\n'
  [[ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]] && printf 'CLAUDE_CODE_OAUTH_TOKEN,SET\n' || printf 'CLAUDE_CODE_OAUTH_TOKEN,UNSET\n'
} >"${output_dir}/credential_presence.csv"

printf 'project_id,source_exists,revision_match,frozen_db_exists,observed_revision\n' >"${output_dir}/project_preflight.csv"
while IFS= read -r project_id; do
  source_path="$(manifest_field "${project_id}" source_path)"
  database_path="$(manifest_field "${project_id}" codeql_db_path)"
  expected="$(manifest_field "${project_id}" observed_cloud_revision)"
  source_exists=false
  revision_match=false
  database_exists=false
  observed=UNAVAILABLE
  if [[ -d "${source_path}" ]]; then
    source_exists=true
    observed="$(git -C "${source_path}" rev-parse HEAD 2>/dev/null || printf NOT_A_GIT_CHECKOUT)"
    [[ "${observed}" == "${expected}" ]] && revision_match=true
  fi
  [[ -d "${database_path}" ]] && database_exists=true
  printf '%s,%s,%s,%s,%s\n' \
    "${project_id}" "${source_exists}" "${revision_match}" "${database_exists}" "${observed}" \
    >>"${output_dir}/project_preflight.csv"
done < <(manifest list)

if grep -q ',false,' "${output_dir}/project_preflight.csv"; then
  printf 'NOT_RUNNABLE: one or more frozen source/database checks failed\n' >"${output_dir}/status.txt"
elif grep -q ',UNSET' "${output_dir}/credential_presence.csv"; then
  printf 'REPRO_BLOCKED: one or more official-model credentials are absent; setup-only work may continue\n' >"${output_dir}/status.txt"
else
  printf 'PREFLIGHT_OK\n' >"${output_dir}/status.txt"
fi

printf 'Preflight artifacts: %s\n' "${output_dir}"
cat "${output_dir}/status.txt"
