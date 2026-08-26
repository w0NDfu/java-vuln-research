#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

output_root="${1:?usage: run_w1_e1_toy.sh OUTPUT_ROOT}"
codeql_bin="${CODEQL_BIN:-codeql}"
fixture_root="${PROJECT_ROOT}/tests/fixtures/w1_e1_toy"
database_root="${output_root}/codeql-db"
classes_root="${output_root}/classes"
manifest="${output_root}/detector_manifest.yaml"
endpoint_root="${output_root}/p0a"
path_root="${output_root}/w1-e1"

if [[ -e "${output_root}" ]]; then
  echo "ERROR: output already exists: ${output_root}" >&2
  exit 2
fi
mkdir -p "${output_root}" "${classes_root}"

"${codeql_bin}" database create "${database_root}" \
  --language=java \
  --source-root="${fixture_root}" \
  --command="javac -d ${classes_root} ${fixture_root}/src/org/springframework/web/bind/annotation/RequestParam.java ${fixture_root}/src/toy/ToyCases.java"

fixture_revision="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
sed \
  -e "s|__REVISION__|${fixture_revision}|g" \
  -e "s|__SOURCE_PATH__|${fixture_root}|g" \
  -e "s|__DATABASE_PATH__|${database_root}|g" \
  "${fixture_root}/detector_manifest.template.yaml" > "${manifest}"

bash "${PROJECT_ROOT}/scripts/run_p0a.sh" "${endpoint_root}" "${manifest}"
bash "${PROJECT_ROOT}/scripts/run_w1_e1_paths.sh" "${endpoint_root}" "${path_root}" "${manifest}"

"${PYTHON_BIN}" - "${path_root}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
metrics = json.loads((root / "detector_metrics.json").read_text(encoding="utf-8"))
diagnostics = [json.loads(line) for line in (root / "candidate_diagnostics.jsonl").read_text(encoding="utf-8").splitlines() if line]

checks = {
    "inputs_mappable": metrics["input_anchor_mappable"] >= 3,
    "effects_mappable": metrics["effect_anchor_mappable"] >= 3,
    "forward_active": metrics["fw_active_inputs"] >= 2,
    "backward_active": metrics["bw_active_effects"] >= 2,
    "toy_a_connected": metrics["static_candidate_paths"] >= 1,
    "toy_b_disconnected": any(row["classification"] in {"EMPTY_FW", "EMPTY_BW", "DIFFERENT_CALL_REGION"} for row in diagnostics),
    "toy_c_structural": metrics["structural_frontier_count"] >= 1,
}
failed = [name for name, passed in checks.items() if not passed]
print(json.dumps({"checks": checks, "metrics": metrics}, ensure_ascii=False, indent=2))
if failed:
    raise SystemExit("toy controls failed: " + ", ".join(failed))
PY
