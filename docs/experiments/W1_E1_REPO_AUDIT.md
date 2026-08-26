# W1-E1 repository audit

**Audit date:** 2026-08-26  
**Audit branch:** `exp/w1-e1-candidate-path-coverage`  
**Implementation starting commit:** `941d5abac248a6bf98188f717c90beff8e7b114e`

## Scope and evidence boundary

This audit is limited to the checked-out Git repository plus read-only
CloudStudio UI state. Raw experiment outputs are intentionally ignored by
Git. CloudStudio terminal verification on 2026-08-26 establishes the raw
artifact locations recorded below; it does not add those raw files to Git.

## Answers required before W1-E1

1. **Latest reliable Work1 baseline commit:**
   `30e2d48905709fa1c7901ae27a22c9a2ba96d0b5` on
   `exp/msa-p0-e0-infra` is the latest committed frozen E0 run record.
   Its report records four successful projects, 85 native alerts, and 59
   native paths.  The current implementation start is `941d5ab`, which adds
   the independent P0-A evaluator on top of deterministic P0-A discovery.
2. **E0 implementation:** `src/java_vuln_research/baseline.py` runs the
   configured native CodeQL query suite and writes per-project SARIF plus
   `baseline_output.jsonl`. `scripts/run_p0.sh` / CLI `run-e0` create the
   run manifest and compact report. The frozen project manifest is
   `experiments/frozen_configs/detector_manifest.yaml`.
3. **61/22 candidate artifact:** the tracked implementation writes
   `external_inputs.jsonl`, `security_effects.jsonl`, `project_status.jsonl`,
   and `summary.json` below the caller-supplied P0-A output root. These raw
   files are excluded by `.gitignore` (`experiment-output/`, `raw-results/`,
   `*.bqrs`, and logs). CloudStudio verification established the frozen P0-A
   directory as `/workspace/experiment-output/MSA-P0-A-20260824-001`: its
   summary reports 4 successful projects, 61 external inputs, and 22
   security effects. The frozen E0 directory is
   `/workspace/experiment-output/MSA-P0-E0-20260824-005`; its baseline
   output reports 85 alerts and 59 paths across the same four projects.
   These raw directories remain immutable inputs; W1-E1 must not regenerate
   or overwrite them.
4. **Stable entity identity:** yes for candidate identity within a frozen
   discovery run. `discovery.runner._candidate_id` hashes the project and
   decoded deterministic CodeQL row. Each candidate also retains project,
   revision, relative file, line, entity display string, mechanism, and
   evidence kind. This is not yet a canonical CodeQL entity identifier across
   changed queries; W1-E1 must retain the original candidate ID and evidence
   tuple rather than reinterpret it.
5. **Existing path IR:** no. `schemas/candidate.schema.json` models an
   unresolved semantic relation, not a candidate vulnerability path. There is
   no `candidate_paths.jsonl`, path query, or path runner.
6. **Existing evaluator:** yes, `evaluation/p0a.py` is independent and reads
   `project_info.csv` / `fix_info.csv` only after detector JSONL exists. It
   reports fix-location overlap for endpoint candidates and deliberately
   leaves final adjudication `UNKNOWN`. It is not a Candidate Coverage
   Evaluator and cannot evaluate paths.
7. **Detector/ground-truth isolation:** source-level isolation exists:
   detector modules do not import `evaluation`, enforced by
   `tests/unit/test_import_boundary.py`; the detector manifest contains only
   project, revision, source path, and DB path. The W1-E1 detector must keep
   this boundary and never receive evaluator files or outputs.
8. **Reusable code:** the P0-A candidate export runner, deterministic
   external-input and security-effect CodeQL queries, candidate JSONL helpers,
   frozen manifest loader, E0 baseline runner/SARIF parser, run-manifest
   builder, and import-boundary test can be reused. No reusable bidirectional
   Data/Call path extractor exists yet.
9. **Known blockers:**
   - Historical P0-A and E0 raw JSONL/SARIF are not represented by a tracked
     artifact pointer. Their verified CloudStudio locations are recorded in
     this audit and the runbook, but remain environment-specific.
   - No Candidate Path IR, Data/Call query, coverage matcher, or frontier
     report exists.
   - E0 raw SARIF is ignored, so a W1-E1 evaluator must accept the E0 raw run
     directory explicitly rather than assume it is in Git.
   - `msa_p0_devset.yaml` still says `FROZEN_PENDING_CLOUD_BUILD_AND_DB` and
     targets 12--20 samples, while the committed E0 report records the
     actually runnable four-project subset. W1-E1 must use the frozen
     detector manifest and record that four-project scope explicitly.
10. **Artifacts to keep frozen:** all `reports/runs/MSA-P0-E0-*` records;
    the E0 raw run and its SARIF/logs when found; the original P0-A raw
    candidates when found; `experiments/frozen_configs/detector_manifest.yaml`;
    `experiments/manifests/msa_p0_devset.yaml`; and commits `30e2d48` and
    `941d5ab`. W1-E1 must write a new run directory and never overwrite any
    of these assets.

## Candidate source inventory

| Candidate kind | Query | Output fields | Discovery scope |
| --- | --- | --- | --- |
| External input | `codeql/external_input/ExternalInputDiscovery.ql` | ID, entity, mechanism, evidence location, source | Spring MVC, Servlet, JAX-RS, one-hop return wrappers |
| Security effect | `codeql/security_effect/SecurityEffectDiscovery.ql` | ID, effect type, entity, critical role, evidence location, source | filesystem, process execution, rendering, dynamic evaluation, one-hop parameter wrappers |

The checked-in queries are deterministic Route-A-style high-confidence
discovery. They do not implement Route B, LLM, or a path graph.

## W1-E1 compatibility decision

W1-E1 will introduce one compatible `CandidatePath` model and keep the
existing endpoint candidate JSONL unchanged. Candidate paths will reference
endpoint candidate IDs and preserve their evidence/provenance. The detector
will read only endpoint JSONL, manifest metadata, and CodeQL database facts;
the evaluator will read frozen detector output plus ground-truth CSV/SARIF
only after path output is persisted.
