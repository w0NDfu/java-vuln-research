# W1-E1 CloudStudio runbook

## Verified environment

- Repository: `/workspace/java-vuln-research`
- Branch: `exp/w1-e1-candidate-path-coverage`
- CodeQL executable: `/workspace/tools/codeql-2.26.3/codeql`
- Dataset root: `/workspace/datasets/cwe-bench-java`
- Frozen P0-A endpoint artifact:
  `/workspace/experiment-output/MSA-P0-A-20260824-001`
- Frozen E0 baseline artifact:
  `/workspace/experiment-output/MSA-P0-E0-20260824-005`
- Dataset: `msa-p0-devset` at revision
  `afe0ebd0ac237abb46255f9ccd479b1d71819136`

## Preflight

Run these in a CloudStudio terminal:

```bash
cd /workspace/java-vuln-research
git status --short --branch
git branch --show-current
git pull --ff-only
/workspace/tools/codeql-2.26.3/codeql version
java -version
mvn -version
for query in \
  AnalysisAnchors InputForward EffectBackward DataCallConnected DataCallFrontier
do
  /workspace/tools/codeql-2.26.3/codeql query compile "codeql/candidate_path/${query}.ql"
done
```

Before a dataset run, execute the three Java/CodeQL controls. Toy A must
produce a static connection, Toy B must stay disconnected, and Toy C must
produce a diagnostic-only structural frontier:

```bash
CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql \
bash scripts/run_w1_e1_toy.sh \
  /workspace/experiment-output/W1-E1-TOY-YYYYMMDD-NNN
```

## Frozen E0 reference and a fresh E0 rerun

The completed E1 reference uses the frozen E0 output at
`/workspace/experiment-output/MSA-P0-E0-20260824-005`; do not overwrite it.
For a fresh, separately named E0 result on the same project manifest and DBs:

```bash
cd /workspace/java-vuln-research
CLOUD_PATHS_CONFIG=/workspace/java-vuln-research/configs/local/cloud.paths.yaml \
CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql \
bash scripts/run_p0.sh \
  msa-p0-devset \
  afe0ebd0ac237abb46255f9ccd479b1d71819136 \
  MSA-P0-E0-YYYYMMDD-NNN
```

## W1-E1 execution

Use a fresh `RUN_ID` every time. The script rejects an existing output
directory, so it cannot overwrite a frozen result.

```bash
cd /workspace/java-vuln-research
RUN_ID=W1-E1-YYYYMMDD-NNN
CLOUD_PATHS_CONFIG=/workspace/java-vuln-research/configs/local/cloud.paths.yaml \
W1_E1_DATASET_ROOT=/workspace/datasets/cwe-bench-java \
CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql \
bash scripts/run_w1_e1.sh \
  /workspace/experiment-output/MSA-P0-A-20260824-001 \
  /workspace/experiment-output/MSA-P0-E0-20260824-005 \
  msa-p0-devset \
  afe0ebd0ac237abb46255f9ccd479b1d71819136 \
  "$RUN_ID"
run_exit=$?
printf 'W1-E1 exit_code=%s\n' "$run_exit"
test "$run_exit" -eq 0
```

The E1 wrapper executes the evaluator and report automatically. These are the
equivalent exact standalone commands, useful only for an already persisted
new run directory:

```bash
cd /workspace/java-vuln-research
RUN_DIR=/workspace/experiment-output/W1-E1-YYYYMMDD-NNN
bash scripts/evaluate_w1_e1.sh \
  "$RUN_DIR/candidate_paths.jsonl" \
  experiments/frozen_configs/detector_manifest.yaml \
  /workspace/datasets/cwe-bench-java \
  /workspace/experiment-output/MSA-P0-E0-20260824-005 \
  "$RUN_DIR"

python3 -m java_vuln_research.cli report-w1-e1 \
  --run-id W1-E1-YYYYMMDD-NNN \
  --raw-run-dir "$RUN_DIR" \
  --baseline-raw-dir /workspace/experiment-output/MSA-P0-E0-20260824-005 \
  --project-root /workspace/java-vuln-research \
  --dataset-name msa-p0-devset \
  --dataset-revision afe0ebd0ac237abb46255f9ccd479b1d71819136 \
  --detector-manifest experiments/frozen_configs/detector_manifest.yaml \
  --config configs/p0.yaml \
  --started-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --command "manual W1-E1 report regeneration"
```

## Required post-run verification

```bash
RUN_DIR=/workspace/experiment-output/W1-E1-YYYYMMDD-NNN
ls -la "$RUN_DIR"
ls -la "$RUN_DIR/logs"
cat "$RUN_DIR/detector_metrics.json"
cat "$RUN_DIR/analysis_anchors.jsonl"
cat "$RUN_DIR/input_forward_funnel.jsonl"
cat "$RUN_DIR/effect_backward_funnel.jsonl"
cat "$RUN_DIR/structural_frontiers.jsonl"
cat "$RUN_DIR/candidate_diagnostics.jsonl"
cat "$RUN_DIR/project_status.jsonl"
cat "$RUN_DIR/coverage_metrics.json"
cat "$RUN_DIR/e0_evaluator_sanity.json"
cat "$RUN_DIR/run_manifest.json"
cat "$RUN_DIR/summary.md"
```

The detector must report `status: SUCCESS`, four runnable projects, and
`detector_ground_truth_access: false` in the manifest. The evaluator may
report zero coverage; that is a result, not a failure, if all required files
exist and the manifest exit code is zero.

## Historical pre-interface reference run

`W1-E1-20260826-003` completed in CloudStudio at
`/workspace/experiment-output/W1-E1-20260826-003` with exit code 0.
It used commit `9fec1cb`, completed all four frozen projects, ran 50.378
seconds of CodeQL query time, and preserved detector/ground-truth isolation.
Its zero-path result predates the explicit AnalysisAnchor and one-sided
FW/BW funnel diagnostics, so it is an implementation baseline rather than a
scientific conclusion.
