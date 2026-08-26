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
git pull --ff-only
/workspace/tools/codeql-2.26.3/codeql version
java -version
mvn -version
/workspace/tools/codeql-2.26.3/codeql query compile codeql/candidate_path/DataCallConnected.ql
/workspace/tools/codeql-2.26.3/codeql query compile codeql/candidate_path/DataCallFrontier.ql
```

## W1-E1 execution

Use a fresh `RUN_ID` every time. The script rejects an existing output
directory, so it cannot overwrite a frozen result.

```bash
cd /workspace/java-vuln-research
RUN_ID=W1-E1-YYYYMMDD-NNN
W1_E1_DATASET_ROOT=/workspace/datasets/cwe-bench-java \
CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql \
bash scripts/run_w1_e1.sh \
  /workspace/experiment-output/MSA-P0-A-20260824-001 \
  /workspace/experiment-output/MSA-P0-E0-20260824-005 \
  msa-p0-devset \
  afe0ebd0ac237abb46255f9ccd479b1d71819136 \
  "$RUN_ID"
```

## Required post-run verification

```bash
RUN_DIR=/workspace/experiment-output/W1-E1-YYYYMMDD-NNN
cat "$RUN_DIR/detector_metrics.json"
cat "$RUN_DIR/project_status.jsonl"
cat "$RUN_DIR/coverage_metrics.json"
cat "$RUN_DIR/run_manifest.json"
cat "$RUN_DIR/summary.md"
```

The detector must report `status: SUCCESS`, four runnable projects, and
`detector_ground_truth_access: false` in the manifest. The evaluator may
report zero coverage; that is a result, not a failure, if all required files
exist and the manifest exit code is zero.

## Completed reference run

`W1-E1-20260826-003` completed in CloudStudio at
`/workspace/experiment-output/W1-E1-20260826-003` with exit code 0.
It used commit `9fec1cb`, completed all four frozen projects, ran 50.378
seconds of CodeQL query time, and preserved detector/ground-truth isolation.
