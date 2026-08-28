#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

project_id="${1:?usage: run_iris_one.sh PROJECT_ID RUN_ID}"
run_id="${2:?usage: run_iris_one.sh PROJECT_ID RUN_ID}"
manifest get "${project_id}" project_id >/dev/null
run_root="$(new_run_root iris "${run_id}" "${project_id}")"
upstream_copy="${run_root}/upstream"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
command_text="python3 src/neusym_vul.py --query $(manifest_field "${project_id}" iris_query) --run-id ${run_id} --llm gpt-4 --skip-evaluation $(manifest_field "${project_id}" benchmark_project_slug)"
credential_args=()
if [[ -n "${OPENAI_API_KEY:-}" ]]; then
  credential_args+=(--credential-present)
fi

record_and_exit() {
  local status="$1" reason="$2" exit_code="$3"
  manifest record --method iris --project-id "${project_id}" --run-id "${run_id}" \
    --run-root "${run_root}" --upstream-output "${upstream_copy}" \
    --started-at "${started_at}" --ended-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --status "${status}" --reason "${reason}" --exit-code "${exit_code}" \
    "${credential_args[@]}" \
    --command "${command_text}"
  exit "${exit_code}"
}

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  record_and_exit REPRO_BLOCKED OPENAI_API_KEY_UNSET 20
fi

assert_frozen_revision "${project_id}"
iris_root="${BASELINE_METHOD_ROOT}/iris"
iris_src="${iris_root}/src"
iris_python="${iris_root}/conda-env/bin/python"
require_file "${iris_root}/method-lock.txt"
require_file "${iris_python}"
require_file "${iris_src}/codeql/codeql"

source_path="$(manifest_field "${project_id}" source_path)"
source_revision="$(manifest_field "${project_id}" observed_cloud_revision)"
slug="$(manifest_field "${project_id}" benchmark_project_slug)"
query="$(manifest_field "${project_id}" iris_query)"
source_slot="${iris_src}/data/cwe-bench-java/project-sources/${slug}"
database_path="${iris_src}/data/codeql-dbs/${slug}"
mkdir -p "$(dirname "${source_slot}")" "${iris_src}/data/codeql-dbs"
if [[ -L "${source_slot}" ]]; then
  unlink "${source_slot}"
elif [[ -e "${source_slot}" ]]; then
  record_and_exit NOT_RUNNABLE IRIS_SOURCE_SLOT_ALREADY_EXISTS 21
fi
ln -s "${source_path}" "${source_slot}"

if [[ -d "${database_path}/db-java" ]]; then
  if [[ ! -f "${database_path}/.baseline_repro_source_revision" ]] || \
     [[ "$(cat "${database_path}/.baseline_repro_source_revision")" != "${source_revision}" ]]; then
    record_and_exit NOT_RUNNABLE IRIS_METHOD_DB_REVISION_UNPROVEN 22
  fi
else
  export PATH="${iris_src}/codeql:${PATH}"
  set +e
  "${iris_python}" "${iris_src}/scripts/build_codeql_dbs.py" \
    --project "${slug}" \
    --db-path "${iris_src}/data/codeql-dbs" \
    --sources-path "${iris_src}/data/cwe-bench-java/project-sources" \
    --cwe-bench-java-path "${iris_src}/data/cwe-bench-java" \
    >"${run_root}/database_build.log" 2>&1
  build_exit=$?
  set -e
  if [[ "${build_exit}" -ne 0 ]] || [[ ! -d "${database_path}/db-java" ]]; then
    record_and_exit NOT_RUNNABLE IRIS_CODEQL_DATABASE_BUILD_FAILURE "${build_exit}"
  fi
  printf '%s\n' "${source_revision}" >"${database_path}/.baseline_repro_source_revision"
fi

fix_info="${iris_src}/data/cwe-bench-java/data/fix_info.csv"
fix_backup="${run_root}/fix_info.original.csv"
cp "${fix_info}" "${fix_backup}"
restore_fix_info() {
  cp "${fix_backup}" "${fix_info}"
}
trap restore_fix_info EXIT
printf '%s\n' 'project_slug,cve_id,github_username,github_repository_name,commit,file,class,class_start,class_end,method,method_start,method_end,signature' >"${fix_info}"

upstream_output="${iris_src}/output/${slug}/${run_id}"
readme_head="${upstream_output}/common/logs/label_func_params/readme_head.txt"
manifest readme-head "${project_id}" "${source_path}" "${readme_head}"
{
  printf 'detector_ground_truth_access=false\n'
  printf 'target_cwe=%s\n' "$(manifest_field "${project_id}" cwe_id)"
  printf 'fix_info=header_only\n'
  printf 'readme_source=frozen_checkout\n'
  printf 'skip_evaluation=true\n'
  printf 'filter_by_module=false\n'
  printf 'posthoc_filtering_skip_fp=false\n'
} >"${run_root}/detector_policy.txt"

export PATH="${iris_src}/codeql:${PATH}"
set +e
(
  cd "${iris_src}"
  "${iris_python}" src/neusym_vul.py \
    --query "${query}" --run-id "${run_id}" --llm gpt-4 --skip-evaluation "${slug}"
) >"${run_root}/stdout.log" 2>"${run_root}/stderr.log"
run_exit=$?
set -e
restore_fix_info
trap - EXIT

if [[ -d "${upstream_output}" ]]; then
  cp -a "${upstream_output}/." "${upstream_copy}/"
fi
if [[ "${run_exit}" -ne 0 ]]; then
  record_and_exit NOT_RUNNABLE IRIS_UPSTREAM_EXECUTION_FAILURE "${run_exit}"
fi
if [[ ! -f "${upstream_copy}/${query}-posthoc-filter/results.sarif" ]]; then
  record_and_exit NOT_RUNNABLE IRIS_EXPECTED_SARIF_MISSING 23
fi
record_and_exit RUNNABLE OUTPUT_FROZEN_GT_NOT_YET_EVALUATED 0
