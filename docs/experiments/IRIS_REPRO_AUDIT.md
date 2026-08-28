# IRIS Reproduction Audit

## Reproduction identity

- Official repository: <https://github.com/iris-sast/iris>
- Paper-code branch: `v1`
- Pinned IRIS commit: `67140e84e6a01da2b44803a6208be2ea7bd4bd51`
- Pinned CWE-Bench-Java submodule: `698fb7248ae30cb7f7782d59c841f05ad70ea9cc`
- Paper: *LLM-Assisted Static Analysis for Detecting Security Vulnerabilities*, ICLR 2025
- Role in this study: `PRIOR-ASSISTED POSITIVE CONTROL / SANITY BASELINE`

The repository README explicitly directs paper reproduction to the `v1` branch. The later `v2` branch is not used because it expands the supported CWEs, changes the pipeline, and targets newer CodeQL releases.

## Required input and prior knowledge

IRIS takes a Java project, a target CWE, and an LLM. Its pipeline extracts external APIs and internal function parameters, asks the LLM to classify sources, sinks, and taint-propagation summaries, builds a project/CWE-specific CodeQL query, runs it, and then performs contextual LLM filtering.

For this Dev18 reproduction:

- Target-CWE prior: **YES**, using the benchmark CWE attached to each already-frozen case.
- Hand-written Source/Sink specification: **NO**; IRIS generates the project-specific specification with the LLM.
- CVE description or patch as detector input: **NO**.
- Vulnerable file/method/location as detector input: **NO**.
- Project identity and source revision: **YES**, because IRIS is a project-level analyzer.

The v1 implementation reads `project_info.csv` to fetch a README at a fixing commit when it has no cached project description. The reproduction harness must preseed `readme_head.txt` from the frozen source checkout so that CVE/fix metadata is not consulted for detector prompting. It must also replace `fix_info.csv` with a header-only detector view and pass `--skip-evaluation`. Ground truth is restored only in the independent post-hoc evaluator.

## LLM model and provider

- Paper/default CLI argument: `--llm gpt-4`
- v1 implementation mapping: `gpt-4-0125-preview`
- Provider: OpenAI Chat Completions API
- Required environment variable: `OPENAI_API_KEY`
- Default temperature: `0`
- Default seed in the GPT wrapper: `345`; pipeline CLI seed default: `1234`

The Dev18 sanity run will use `gpt-4` exactly as the v1 pipeline exposes it. Substitution with Qwen, a newer GPT model, or a compatible third-party endpoint would be a protocol deviation and is not silently permitted.

## CodeQL and runtime environment

- Required CodeQL: the IRIS release `codeql-0.8.3-patched`, described by the authors as patched CodeQL `2.15.3`.
- Release asset: <https://github.com/iris-sast/iris/releases/tag/codeql-0.8.3-patched>
- Python: `3.10` from `environment.yml`
- Main dependency families: pandas, requests, tqdm, OpenAI SDK, transformers, PyTorch 2.5.
- Java/Maven/Gradle versions: selected per project from the pinned CWE-Bench-Java `build_info.csv` and version configuration files.

The frozen Work1 databases were created/resolved with CodeQL 2.26.3. They are evidence inputs for Native/Work1 but are not treated as IRIS v1 databases. IRIS must create method-owned databases from the same frozen source revisions with its patched CodeQL. Until those databases exist, the existing frozen DB status is `DB_INCOMPATIBLE`, not `MISS`.

## Invocation

The official single-project entry point is:

```bash
python3 src/neusym_vul.py \
  --query cwe-022wLLM \
  --run-id IRIS-SMOKE-D002-YYYYMMDD-NNN \
  --llm gpt-4 \
  --skip-evaluation \
  perwendel__spark_CVE-2018-9159_2.7.1
```

The query argument is selected without modification from the four v1-supported values: `cwe-022wLLM`, `cwe-078wLLM`, `cwe-079wLLM`, and `cwe-094wLLM`.

## Outputs and alert format

For project slug `P`, run id `R`, and query `Q`, v1 writes beneath `output/P/R/`:

- `cwe-<id>/candidate_apis.csv`
- `cwe-<id>/llm_labelled_source_apis.json`
- `cwe-<id>/llm_labelled_sink_apis.json`
- `cwe-<id>/llm_labelled_taint_prop_apis.json`
- `cwe-<id>/MySources.qll`, `MySinks.qll`, `MySummaries.qll`, and `Spec.yml`
- `common/func_params.csv`
- `common/llm_labelled_source_func_params.json`
- `Q/results.sarif` and `Q/results.csv`
- `Q/results_pp.sarif` after rule-based path post-processing
- `Q-posthoc-filter/results.sarif`, `results.json`, and `stats.json`
- raw LLM responses and logs in the associated `logs/` directories

SARIF `codeFlows` are the candidate/native taint paths. The reproduction harness additionally records wall-clock runtime, exit status, model identity, call/log inventory, and token information if the provider response exposes it. IRIS v1 does not provide a reliable aggregate cost counter, so unavailable token/cost fields must be reported as `NOT_RECORDED_BY_UPSTREAM`, not estimated.

## Detection success definition

Detector output is frozen before GT evaluation.

- Execution success: the official pipeline exits successfully and produces the expected pre- and post-filter SARIF artifacts.
- IRIS alert: a result/codeFlow remaining in `Q-posthoc-filter/results.sarif`.
- GT `HIT`: at least one frozen post-filter path overlaps the independent benchmark vulnerability at the common evaluable method granularity.
- GT `MISS`: the method ran successfully and emitted no independently matching path.
- `NOT_RUNNABLE`: environment, build, database, metadata, or upstream execution failure.
- `NOT_EVALUABLE`: output exists but the benchmark case cannot be aligned at the frozen common GT granularity.

An alert count greater than zero is not by itself a GT hit.

## Detector ground-truth access

`detector_ground_truth_access = false` is an enforced reproduction condition. It is achieved by:

1. staging a detector-only, header-only `fix_info.csv`;
2. preseeding the project description from the frozen checkout rather than a fixing commit;
3. leaving `--filter-by-module` and `--posthoc-filtering-skip-fp` disabled;
4. passing `--skip-evaluation`; and
5. running the independent evaluator only after IRIS artifacts are frozen.

This isolation does not change IRIS source/sink generation or taint semantics.

## Dev18 compatibility decision

All Dev18 CWE categories are among the four CWEs supported by IRIS v1. Project-level compatibility still depends on successfully rebuilding a patched-2.15.3 CodeQL database from each frozen source checkout. No project is excluded merely because it may produce zero detections.

