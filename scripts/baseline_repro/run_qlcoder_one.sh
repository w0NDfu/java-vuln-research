#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

project_id="${1:?usage: run_qlcoder_one.sh PROJECT_ID RUN_ID}"
run_id="${2:?usage: run_qlcoder_one.sh PROJECT_ID RUN_ID}"
manifest get "${project_id}" project_id >/dev/null
run_root="$(new_run_root qlcoder "${run_id}" "${project_id}")"
upstream_output="${run_root}/upstream"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cve_id="$(manifest_field "${project_id}" cve_id)"
container_output="/baseline-output/raw/qlcoder/${run_id}/${project_id}/upstream"
command_text="python3 src/ql_agent.py --cve-id ${cve_id} --vuln-db cves/${cve_id}/${cve_id}-vul --fixed-db cves/${cve_id}/${cve_id}-fix --diff cves/${cve_id}/${cve_id}.diff --output-dir ${container_output} --model sonnet-4 --agent claude --max-iteration 5"

credential_present=false
credential_args=()
if [[ -n "${ANTHROPIC_API_KEY:-}" || -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]]; then
  credential_present=true
  credential_args+=(--credential-present)
fi

record_and_exit() {
  local status="$1" reason="$2" exit_code="$3"
  manifest record --method qlcoder --project-id "${project_id}" --run-id "${run_id}" \
    --run-root "${run_root}" --upstream-output "${upstream_output}" \
    --started-at "${started_at}" --ended-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --status "${status}" --reason "${reason}" --exit-code "${exit_code}" \
    "${credential_args[@]}" \
    --command "${command_text}"
  exit "${exit_code}"
}

if [[ "${credential_present}" != true ]]; then
  record_and_exit REPRO_BLOCKED ANTHROPIC_CREDENTIAL_UNSET 20
fi

assert_frozen_revision "${project_id}"
ql_root="${BASELINE_METHOD_ROOT}/qlcoder"
ql_src="${ql_root}/src"
require_file "${ql_root}/method-lock.txt"
require_file "${ql_root}/method.env"
source "${ql_root}/method.env"

compose=(docker compose -f docker-compose.yml -f docker-compose.baseline.yml)
(
  cd "${ql_src}"
  "${compose[@]}" up -d chroma
)

set +e
(
  cd "${ql_src}"
  "${compose[@]}" run --rm app python3 scripts/get_cve_repos.py --cve "${cve_id}"
  "${compose[@]}" run --rm app python3 scripts/build_codeql_dbs.py --cve-id "${cve_id}"
  "${compose[@]}" run --rm app python3 scripts/cves_fetcher.py
  "${compose[@]}" run --rm app python3 src/ql_agent.py \
    --cve-id "${cve_id}" \
    --vuln-db "cves/${cve_id}/${cve_id}-vul" \
    --fixed-db "cves/${cve_id}/${cve_id}-fix" \
    --diff "cves/${cve_id}/${cve_id}.diff" \
    --output-dir "${container_output}" \
    --model sonnet-4 --agent claude --max-iteration 5
) >"${run_root}/stdout.log" 2>"${run_root}/stderr.log"
run_exit=$?
set -e

if [[ "${run_exit}" -ne 0 ]]; then
  record_and_exit NOT_RUNNABLE QLCODER_UPSTREAM_EXECUTION_FAILURE "${run_exit}"
fi
if ! find "${upstream_output}" -name iterative_metadata.json -print -quit | grep -q .; then
  record_and_exit NOT_RUNNABLE QLCODER_EXPECTED_METADATA_MISSING 23
fi
record_and_exit RUNNABLE OUTPUT_FROZEN_GT_NOT_YET_EVALUATED 0
