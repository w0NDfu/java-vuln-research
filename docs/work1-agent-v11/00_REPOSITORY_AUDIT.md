# Work1 V11 M0 Repository and Environment Audit

Audit date: 2026-08-29 (Asia/Shanghai)

## 1. Scope and method boundary

This document freezes the M0 facts for Work1 V11. No M1 repository index, M2 repository tool, M3 CodeQL tool, proposal, evidence graph, path builder, or Agent implementation was added during this audit.

The checked-out workspace is the local Windows repository, not the CloudStudio host named in the execution brief. Cloud-only tool and dataset claims are therefore treated as historical report evidence, not as facts observed in this environment.

## 2. Repository and Git state

| Fact | Observed value |
| --- | --- |
| Repository root | `F:\ForGithub\java-vuln-research` |
| Source branch at audit start | `exp/w1-e1-candidate-path-coverage` |
| V11 branch | `work1/agent-active-security-v11` |
| Baseline HEAD | `b4c11c31b3a0e6e6d100513802c24b737b694be1` |
| Baseline subject | `docs(w1-e1): record executable SecurityEffect validation` |
| Remote | `origin https://github.com/w0NDfu/java-vuln-research.git` |
| Worktree at audit start | Dirty; exact state is frozen in `PREEXISTING_WORKTREE.md` |

The V11 branch was created from `b4c11c3`. No reset, checkout-based discard, force push, or cleanup was performed. The pre-existing modified and untracked files remain present and unstaged.

The 15 commits visible at audit start were:

```text
b4c11c3 docs(w1-e1): record executable SecurityEffect validation
079d4b9 docs(w1-e1): complete SecurityEffect semantic audit
5307464 test(w1-e1): execute SecurityEffect taxonomy contract
02faada w1-e1: harden SecurityEffect identity and aggregation tests
ff2a912 w1-e1: extend generic SecurityEffect primitives and taxonomy
2603177 w1-e1: audit SecurityEffect taxonomy coverage gaps
188fca4 docs: add W1-E1 effect identity audit
2e6dabf docs: add W1-E1 path traceability audit
97f8ae3 docs: add W1-E1 offline audit report
af74739 docs(w1-e1): record final report commit
065a039 docs(w1-e1): clarify freeze and report commits
85ae87c w1-e1: record expanded W1-E1 validation results
8996d09 w1-e1: freeze 18-project validation cohort
1f6636f w1-e1: freeze Dev16 validation manifest and runbook
4d1a197 w1-e1: add attribution report and recommendation
```

Top-level implementation areas observed:

```text
codeql/{candidate_path,external_input,route_b,security_effect,tests}
configs/{examples}
docs/{experiments,work1-agent-v11}
experiments/{frozen_configs,manifests}
reports/runs
schemas
scripts
src/java_vuln_research/{analysis,common,discovery,evaluation,frontier,llm,semantics,validator}
tests/{controlled,fixtures,integration,unit}
```

## 3. Pre-existing worktree provenance

The dirty files are not anonymous local experiments. Hash comparison shows that every checked V10-era native-pool/Route-B file is byte-for-byte identical to its committed form on `origin/exp/w1-p0-b-route-b-static` at `22c7429`.

This includes:

- the five modified tracked files recorded in `PREEXISTING_WORKTREE.md`;
- `src/java_vuln_research/native_pool.py`;
- `src/java_vuln_research/route_b_detector.py`;
- `src/java_vuln_research/evaluation/route_b.py`;
- `codeql/route_b/*`;
- the native-pool and Route-B tests and reports.

The canonical remote history is:

```text
22c7429 w1: evaluate baseline-preserving static augmentation
0baca37 fix(work1): remove redundant call source predicate
0b304be fix(work1): use supported CodeQL Java type APIs
c1df310 w1: add seed-independent Route B static candidates
4178bdc w1: record P0-A1 native pool validation
406fb26 w1: add baseline-preserving native path adapter
b2fc266 w1-e1: record SecurityEffect-refactored validation run
b4c11c3 docs(w1-e1): record executable SecurityEffect validation
```

M0 intentionally does not claim or recommit those user-owned changes. Before M1 modifies overlapping files, V11 needs a clean integration decision: base the implementation on `22c7429`, or cherry-pick `406fb26..22c7429` into the V11 branch after safely reconciling the identical worktree content.

## 4. Toolchain observed in this workspace

| Tool | Result |
| --- | --- |
| CodeQL | Unavailable on `PATH`; `codeql version` could not execute |
| Java | Amazon Corretto OpenJDK `1.8.0_412` |
| Python requested as `python3` | WindowsApps launcher exists but cannot execute in this workspace |
| Python usable as `python` | CPython `3.10.3` at `C:\Users\戴超杰\AppData\Local\Programs\Python\Python310\python.exe` |
| Maven | Apache Maven `3.8.1` using Java `1.8.0_412` |
| Gradle | Unavailable on `PATH`; no Gradle wrapper is present |
| Git | `2.45.2.windows.1` |
| ripgrep | `15.2.0` |

No `CODEQL_*` environment variable or CodeQL executable was found in the small set of conventional local install paths checked. Historical reports record CodeQL `2.26.3` on CloudStudio, but that version was not independently executable here.

The repository declares Python `>=3.10` and no runtime dependencies beyond the standard library. Neither `javalang` nor `tree_sitter` is installed. No local Maven or Gradle wrapper exists because this repository is a Python/CodeQL research harness rather than a benchmark Java project checkout.

Baseline test status in the current preserved worktree:

```text
59 passed, 1 skipped in 3.11s
```

The skipped integration test is consistent with CodeQL being unavailable.

## 5. Dataset and execution-environment availability

The following cloud/local runtime inputs are absent from this checkout:

- `configs/local/`;
- `experiment-output/`;
- `raw-results/`;
- benchmark Java source checkouts;
- local CodeQL databases.

Tracked detector manifests exist under `experiments/frozen_configs/`, and compact reports exist under `reports/runs/`, but their source and database paths refer to an external execution environment. Consequently, M1 code can be developed and fixture-tested here, while the required two-real-project M2 smoke test and executable M3 CodeQL validation require the CloudStudio assets or another supplied project/DB root.

## 6. Historical naming audit: V8/V9/V10 and A4

No tracked file, branch, tag, or reachable commit message defines literal Work1 components named `V8`, `V9`, `V10`, or `A4`. A history search for `V8` produced incidental Dev8 cohort commits; `V9`, `V10`, and `A4` produced no implementation identity. There are no Git tags.

The actual repository generations are named by experiment:

1. `MSA-P0-E0`: native CodeQL baseline.
2. `P0-A` / Route A: deterministic external-input and security-effect endpoint discovery.
3. `W1-E1`: analysis-anchor mapping plus forward/backward Data/Call queries and structural frontier diagnostics.
4. `P0-A1`: native SARIF path adapter and unified candidate pool.
5. `P0-B`: seed-independent fixed Route B candidates and static augmentation experiment.

Therefore this audit does not invent V8/V9/V10/A4 file mappings. When the V11 brief refers to old A4/frontier behavior, the nearest concrete assets are `frontier/analysis_anchor.py`, `DataCallFrontier.ql`, and the frontier portions of `frontier/runner.py`.

## 7. Asset inventory and classification

### A. Reuse in the V11 main chain

| Capability | Existing location | V11 decision and caveat |
| --- | --- | --- |
| Native CodeQL baseline runner | `src/java_vuln_research/baseline.py`, `scripts/run_p0.sh`, `configs/p0.yaml` | Reuse native results unchanged and preserve their priority. Extend failure taxonomy; do not make it an Agent prerequisite. |
| Detector manifest and non-leakage validation | `src/java_vuln_research/common/contracts.py`, `tests/unit/test_detector_contract.py`, `tests/unit/test_import_boundary.py` | Reuse directly. Keep detector/evaluator separation. |
| JSON/JSONL/CSV helpers | `src/java_vuln_research/common/io.py` | Reuse directly for traces, indices, proposals, graphs, candidates, and manifests. |
| Provenance and hashing | `src/java_vuln_research/common/provenance.py`, `src/java_vuln_research/common/run_manifest.py` | Reuse and extend with prompt/schema/model/tool-call fields required by V11. |
| CodeQL DB inventory | `src/java_vuln_research/common/inventory.py`, `scripts/inventory_codeql_dbs.sh` | Reuse as DB discovery/metadata support. It is inventory, not full DB lifecycle management. |
| NativePathAdapter | `src/java_vuln_research/native_pool.py` on remote commits `406fb26..4178bdc`; matching file is present in the dirty worktree | Reuse its stable native path IDs, locations, and preservation invariants. Move the SARIF parser out of `evaluation.coverage` because the current detector-side module imports an evaluator module. |
| Candidate path IR | `src/java_vuln_research/frontier/candidate_path.py`, `schemas/candidate_path.schema.json` | Reuse identity, endpoint, location, provenance, origin, and native preservation fields. Generalize the DATA/CALL-only edge contract rather than replacing the IR wholesale. Add `AGENT_HYBRID` and edge-level evidence status/provenance. |
| Endpoint facts | `src/java_vuln_research/discovery/runner.py`, `codeql/external_input/ExternalInputDiscovery.ql`, `codeql/security_effect/*` | Retain as optional deterministic facts. They must not be the only repository exploration entry point or proof by method name. |
| Existing fixtures and test conventions | `tests/fixtures/w1_e1_toy`, `tests/fixtures/security_effect_taxonomy`, `tests/unit/*` | Reuse for local contracts and add repository-only fixtures. They do not replace the required real-project smoke test. |

There is no stable bounded source reader or local slice implementation to reuse. `Path.read_text` is used in several modules, but no reusable `read_file_range`, method-range resolver, or bounded context-slice API exists.

There is also no implemented CodeQL overlay compiler/executor. `codeql/{propagation,library,state,validator}` contain only `.gitkeep`; `src/java_vuln_research/semantics` and `validator` contain docstring-only `__init__.py` files. No `isAdditionalFlowStep` or `AdditionalTaintStep` implementation exists.

### B. Downgrade to Agent-callable tools

| Historical capability | Existing location | V11 tool role |
| --- | --- | --- |
| Forward reachability | `codeql/candidate_path/InputForward.ql` and `W1E1ForwardFlow` in `EndpointCandidates.qll` | Wrap as optional `codeql_forward_flow(entity_id, options)`. Never gate Agent startup on a non-empty result. |
| Backward reachability | `codeql/candidate_path/EffectBackward.ql` and `W1E1BackwardFlow` | Wrap as optional `codeql_backward_flow(entity_id, options)`. |
| Full Data/Call connection | `codeql/candidate_path/DataCallConnected.ql` | Retain as high-confidence local/global dataflow evidence, not as the definition of candidate existence. |
| Structural frontier | `codeql/candidate_path/DataCallFrontier.ql`, `src/java_vuln_research/frontier/analysis_anchor.py` | Retain historical diagnostic and optionally expose bounded neighboring facts. It is not a universal semantic-break detector. |
| Analysis-anchor mapping | `codeql/candidate_path/AnalysisAnchors.ql`, `frontier/analysis_anchor.py` | Reuse mapping concepts and roles where possible, but ProgramEntity must cover more than DataFlow nodes and calls. |
| Query execution/parsing | private `_run_query` / `_run_table_query` helpers in `discovery/runner.py`, `frontier/runner.py`, and `route_b_detector.py` | Refactor into a shared structured CodeQL executor with explicit DB-unavailable, timeout, OOM, compile, run, and decode statuses. |
| Call relations | `directlyCalls` predicates embedded in `EndpointCandidates.qll` and `RouteBModels.qll` | Extract into entity-parameterized caller/callee tools. No standalone call-graph API currently exists. |
| DataFlow facts | current CodeQL DataFlow/TaintTracking queries | Build entity-parameterized local-flow and neighbor tools. No standalone `codeql_local_flow` or neighbor API exists. |
| CFG | none | New M3 tool/query is required. |
| Implementation/override/type/field/annotation facts | partial facts embedded in CodeQL endpoint/Route B queries | Re-express as neutral RepositoryIndex/CodeQL facts without Source/Sink classification. |

The existing `frontier/runner.py` remains useful for historical reproduction, but its five-query orchestration is not imported as a V11 prerequisite.

### C. Stop extending

| Asset | Location | Decision |
| --- | --- | --- |
| Fixed Route B input/effect/pair rules | `codeql/route_b/RouteBModels.qll`, `RouteBInputCandidates.ql`, `RouteBEffectCandidates.ql`, `RouteBGatedPairs.ql`, `RouteBConnected.ql` | Freeze for reproduction. Do not add annotations, callbacks, receiver/type/API lists, project cases, or new structural gates. |
| Route B orchestration/evaluation | `src/java_vuln_research/route_b_detector.py`, `src/java_vuln_research/evaluation/route_b.py`, `tests/unit/test_route_b.py` | Preserve as a historical comparator only. Do not make it a V11 detector route. |
| Route B report | `docs/experiments/W1_P0_B_ROUTE_B_REPORT.md` | Preserve as evidence: 2,716 inputs, 88 effects, 13,214 structurally gated pairs, zero new connected paths, and zero incremental coverage. |
| A4-as-universal-break behavior | no literal A4 module; nearest assets are `frontier/analysis_anchor.py` and `DataCallFrontier.ql` | Stop treating anchor/frontier success as a prerequisite or a complete semantic-gap oracle. Keep bounded anchor/frontier facts as optional tools. |
| Empty semantic-overlay placeholders | `codeql/{propagation,library,state,validator}`, `src/java_vuln_research/{semantics,validator}` | Do not fill these with a growing fixed-case Route B replacement. V11 overlay support, when implemented, must compile controlled evidence-gated proposals. |

## 8. Current architectural gaps against M1-M3

### M1 ProgramEntity and RepositoryIndex

- No general ProgramEntity exists.
- Current identity is candidate/path-specific, not a stable repository entity identity.
- No neutral Java file/package/type/method/parameter/call/field/annotation index exists.
- No bounded file reader or exact method inspector exists.
- No Java parser dependency is available; the initial filesystem fallback should use standard-library lexical/brace scanning plus `rg`, and treat CodeQL structural facts as an optional enrichment.

### M2 bounded Repository Tools

- No `search_code`, `search_symbols`, `inspect_method`, `inspect_type`, `get_callers`, `get_callees`, `get_implementations`, `get_overrides`, `get_fields`, or `get_annotations` API exists.
- No per-call bounded result contract or JSONL tool trace exists.
- Existing whole-run queries require endpoint candidate JSONL and therefore cannot satisfy the repository-first startup requirement.

### M3 CodeQL analysis tools

- Native analysis and SARIF parsing exist, but are run-oriented rather than callable tool APIs.
- Forward/backward/connected facts exist, but are endpoint-model-bound and not parameterized by ProgramEntity.
- Call graph, local flow, dataflow neighbors, and CFG are not exposed as structured tools.
- Overlay compile/execute support is absent.
- Current errors collapse many failures into `QUERY_FAILURE` / `QUERY_ERROR`; V11 requires separate unavailable, build/DB, timeout, OOM, compile, execute, and decode classifications.

## 9. Planned M1-M3 files

The existing `java_vuln_research` package will remain the top-level namespace. The following is the current estimate; M1 may adjust names only when an equivalent existing abstraction is discovered during implementation.

### M1

```text
src/java_vuln_research/work1_agent/__init__.py
src/java_vuln_research/work1_agent/repository/__init__.py
src/java_vuln_research/work1_agent/repository/entity.py
src/java_vuln_research/work1_agent/repository/indexer.py
src/java_vuln_research/work1_agent/repository/search.py
src/java_vuln_research/work1_agent/repository/reader.py
schemas/program_entity.schema.json
tests/unit/test_program_entity.py
tests/unit/test_repository_index.py
docs/work1-agent-v11/01_REPOSITORY_INDEX.md
```

### M2

```text
src/java_vuln_research/work1_agent/repository/tools.py
src/java_vuln_research/work1_agent/repository/trace.py
tests/unit/test_repository_tools.py
tests/fixtures/work1_agent_repository/
docs/work1-agent-v11/02_REPOSITORY_TOOLS.md
artifacts/work1-agent-v11/tool_traces/
```

The later Agent adapter can call this tool facade; M2 will not add an Agent controller or prompt.

### M3

```text
src/java_vuln_research/work1_agent/codeql/__init__.py
src/java_vuln_research/work1_agent/codeql/executor.py
src/java_vuln_research/work1_agent/codeql/native_runner.py
src/java_vuln_research/work1_agent/codeql/analysis_tools.py
src/java_vuln_research/work1_agent/codeql/overlay_compiler.py
src/java_vuln_research/work1_agent/codeql/overlay_executor.py
codeql/work1_agent/EntityFacts.ql
codeql/work1_agent/CallGraph.ql
codeql/work1_agent/LocalFlow.ql
codeql/work1_agent/DataFlowNeighbors.ql
codeql/work1_agent/Cfg.ql
tests/unit/test_codeql_analysis_tools.py
tests/unit/test_codeql_failure_classification.py
docs/work1-agent-v11/03_CODEQL_TOOLS.md
artifacts/work1-agent-v11/codeql_runs/
```

The exact overlay query/module filenames will be frozen only after the controlled proposal schema exists. M3 may initially expose a capability/status boundary and defer semantic overlay admission to the evidence-gate milestone; it must not accept arbitrary model-authored QL.

## 10. Can V11 start without partial-flow?

**Engineering answer: yes.** Nothing in the repository prevents a source-first implementation of ProgramEntity, RepositoryIndex, bounded `rg` search, and bounded source inspection. These components can be constructed and unit-tested without CodeQL, endpoint candidates, forward/backward funnels, or a partial path.

Practical validation blockers are separate:

1. This local workspace has no benchmark Java source checkout, so the required two-real-project M2 smoke test cannot be completed here yet.
2. CodeQL and local CodeQL databases are absent, so M3 execution and overlay validation cannot run here.
3. Only JDK 8 is installed, which may be insufficient for rebuilding modern Java benchmark cases even after source projects are supplied.
4. The V10 native/Route-B baseline is present as a dirty materialization of remote commit `22c7429`, not as ancestors of the V11 branch. That history must be reconciled before M1 edits overlapping candidate/CLI files.

These issues do not force partial-flow as an entry condition. They constrain where the real-project and CodeQL-backed verification must run.

## 11. M0 decision

M0 is complete when this report and the pre-existing-worktree record are committed alone. The next implementation action is M1 ProgramEntity + RepositoryIndex, but it must not begin until the branch-history integration issue above is resolved without losing or silently absorbing user-owned worktree changes.
