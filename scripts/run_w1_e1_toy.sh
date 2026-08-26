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
endpoint_root = root.parent / "p0a"

def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

metrics = json.loads((root / "detector_metrics.json").read_text(encoding="utf-8"))
paths = read_jsonl(root / "candidate_paths.jsonl")
frontiers = read_jsonl(root / "structural_frontiers.jsonl")
candidates = read_jsonl(endpoint_root / "external_inputs.jsonl") + read_jsonl(endpoint_root / "security_effects.jsonl")
entity_by_id = {row["candidate_id"]: row["entity"] for row in candidates}

connected_pairs = [
    (entity_by_id[row["input_candidate_id"]], entity_by_id[row["effect_candidate_id"]])
    for row in paths
]
frontier_pairs = [
    (entity_by_id[row["input_candidate_id"]], entity_by_id[row["effect_candidate_id"]])
    for row in frontiers
]

checks = {
    "inputs_mappable": metrics["input_anchor_mappable"] >= 3,
    "effects_mappable": metrics["effect_anchor_mappable"] >= 3,
    "forward_active": metrics["fw_active_inputs"] >= 2,
    "backward_active": metrics["bw_active_effects"] >= 2,
    "toy_a_connected": any("ToyCases.connected" in left and "ToyCases.connected" in right for left, right in connected_pairs),
    "toy_b_disconnected": not any("ToyCases.disconnected" in left and "ToyCases.disconnected" in right for left, right in connected_pairs),
    "toy_c_structural": any("ToyCases.structural" in left and "ToyCases.structural" in right for left, right in frontier_pairs),
    "frontiers_diagnostic_only": bool(frontiers) and all(
        row["diagnostic_only"] is True and row["adds_propagation_edge"] is False
        for row in frontiers
    ),
}
failed = [name for name, passed in checks.items() if not passed]
print(json.dumps({"checks": checks, "metrics": metrics}, ensure_ascii=False, indent=2))
if failed:
    raise SystemExit("toy controls failed: " + ", ".join(failed))
PY
