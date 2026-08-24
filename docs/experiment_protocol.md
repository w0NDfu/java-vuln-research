# Experiment protocol

## Roles and write boundaries

- Local Windows is the only source-editing authority.
- CloudStudio executes committed code and may create ignored local path config,
  caches, logs, and raw outputs.
- Existing cloud datasets, CodeQL databases, Work1/IRIS assets, and past results
  are read-only unless a later explicit protocol says otherwise.
- Cloud commits may contain only `reports/runs/**`. Source defects are recorded,
  fixed locally, pushed, pulled into Cloud, and rerun.

Before an official run, `scripts/cloud_preflight.sh` must pass and the tracked
working tree must be clean. The run manifest records the exact commit, branch,
tool versions, dataset revision, configuration/rule/prompt hashes, model
settings (or `null`), project accounting, timestamps, duration, and status.

## MSA-P0-E0 completion gates

1. Local push and Cloud pull work.
2. Cloud preflight passes.
3. A runnable CodeQL database collection is found or established safely.
4. The frozen baseline runs on real projects.
5. Every run automatically generates a manifest.
6. Results identify one Git commit.
7. Raw data is excluded from GitHub.
8. The compact report can be committed and pulled back locally.

Detector execution stops after writing `baseline_output.jsonl`. Evaluation is a
separate process. Per-project failures retain stage, exit code, and error class;
they are never silently replaced or counted as clean findings.

## Report contract

Each `reports/runs/<RUN_ID>/report.md` records status, commit, cloud environment,
dataset and database inventory, runnable projects, baseline summary, failures,
scientific interpretation, and next action. Unmeasured fields are
`NOT_APPLICABLE`, not fabricated zeroes.

