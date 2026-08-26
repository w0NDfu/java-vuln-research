# W1-E1 Dev16 CloudStudio Runbook

## Scope

This run is the validation expansion of W1-E1 from frozen Dev8 to frozen Dev16. The detector/query/configuration is unchanged. The only new inputs are the eight validation repositories and their CodeQL databases.

All commands below run in CloudStudio. No local checkout, local build, local CodeQL database, or local dataset is used.

## Frozen inputs

- Branch: exp/w1-e1-candidate-path-coverage
- Manifest: /workspace/java-vuln-research/experiments/frozen_configs/w1_e1_dev16_manifest.yaml
- Dataset metadata: /workspace/datasets/cwe-bench-java
- CodeQL: /workspace/tools/codeql-2.26.3/codeql
- Java baseline: JDK8u202 with Maven 3.5.0; V007 uses JDK17 as recorded in the pre-run build metadata.
- Existing Dev8 source/DB roots remain unchanged.
- New validation roots: /workspace/w1-e1-dev16/projects and /workspace/w1-e1-dev16/codeql-dbs.

## Provisioning and pre-run audit

1. Clone only the eight frozen repositories at the exact revisions in the manifest. Do not inspect or copy fix files, vulnerability locations, or GT labels.
2. Build each source tree with the recorded Java/build toolchain.
3. Create a CodeQL Java database with the same central build strategy used for Dev8. Verify each database with codeql resolve database.
4. Record revision, build exit code, database exit code, and database path in an audit file. If a selected project fails before the W1-E1 run starts, apply only the predeclared replacement policy in W1_E1_DEV16_SELECTION.md, update the manifest, and refreeze. Never replace after detector execution begins.

## Detector run order

Use distinct run IDs and preserve all raw outputs. Run from /workspace/java-vuln-research:

    DEV16_MANIFEST=/workspace/java-vuln-research/experiments/frozen_configs/w1_e1_dev16_manifest.yaml
    CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql bash scripts/run_p0a.sh /workspace/experiment-output/W1-E1-DEV16-P0A-20260826-001 $DEV16_MANIFEST

    CLOUD_PATHS_CONFIG=/workspace/java-vuln-research/configs/local/cloud.paths.yaml CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql bash scripts/run_p0.sh msa-p0-devset afe0ebd0adc237abb46255f9cd479b1d71819136 W1-E1-DEV16-E0-20260826-001 $DEV16_MANIFEST

    CLOUD_PATHS_CONFIG=/workspace/java-vuln-research/configs/local/cloud.paths.yaml W1_E1_DATASET_ROOT=/workspace/datasets/cwe-bench-java CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql bash scripts/run_w1_e1.sh /workspace/experiment-output/W1-E1-DEV16-P0A-20260826-001 /workspace/experiment-output/W1-E1-DEV16-E0-20260826-001 msa-p0-devset afe0ebd0adc237abb46255f9cd479b1d71819136 W1-E1-DEV16-20260826-001 $DEV16_MANIFEST

The wrapper must persist detector_metrics.json, analysis_anchors.jsonl, input_forward_funnel.jsonl, effect_backward_funnel.jsonl, structural_frontiers.jsonl, candidate_diagnostics.jsonl, project_status.jsonl, coverage_metrics.json, e0_evaluator_sanity.json, run_manifest.json, and summary.md before evaluator results are accepted.

## Independent evaluator and attribution

After the detector run exits successfully, run the existing evaluator against the persisted candidate_paths.jsonl and the Dev16 E0 raw output. Then run the existing offline attribution analyzer with an explicit P0A directory:

    PYTHONPATH=src python -m java_vuln_research.analysis.w1_e1_attribution --run-dir /workspace/experiment-output/W1-E1-DEV16-20260826-001 --output-dir /workspace/experiment-output/W1-E1-DEV16-ATTRIBUTION-20260826-001 --p0a-dir /workspace/experiment-output/W1-E1-DEV16-P0A-20260826-001

No CodeQL rerun is allowed after attribution. Do not run Route B, LLM candidate expansion, Work2, final CWE labeling, or E2 during this task.

## Acceptance and reporting

The final report must include per-project funnel counts and rates, Dev8 versus validation versus combined metrics, raw and deduplicated frontier totals, project concentration, BW root causes, coverage/recovery, and all isolation fields. It must state scientific_method_changed=NO, detector_ground_truth_access=false, and whether CodeQL was rerun for new projects. Stop after Dev16, evaluator, attribution, and comparison report.
