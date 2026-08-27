# Work1 P0-B Route B Static Augmentation Report

## Run identity

- Run ID: `W1-P0-B-ROUTE-B-20260827-002`
- Branch: `exp/w1-p0-b-route-b-static`
- Detector commit: `0baca37524ba7a810175b6aba526fe7be53886b5`
- Frozen P0-A1 baseline commit: `4178bdc8f47646c543d75acdc0f13970fc8af68b`
- CodeQL: `2.26.3`
- Projects: `18/18 SUCCESS`
- Tests: `59 passed, 1 skipped`
- Route B queries: all four compiled successfully under CodeQL 2.26.3 before the formal run
- Detector frozen before GT evaluation: `true`
- Detector ground-truth access: `false`
- Scientific method changed: `NO`
- CodeQL databases reused: `true`; rebuilt: `false`
- LLM used: `false`

## 1. Native baseline

P0-B consumed the frozen P0-A1 `native_candidate_paths.jsonl` without rerunning the E0 CodeQL baseline. The baseline contains 437 `CODEQL_NATIVE` candidate paths.

## 2. Route B design

Route B performs seed-independent structural discovery. It does not import the frozen Route A endpoint models and does not require an existing CodeQL source/sink seed.

Input candidates are proposed from handler annotations, message/event annotations, callback or override parameters, and request/context/event/message/payload-like parameter types. Effect candidates are proposed from strong receiver/type plus operation-name evidence for storage, process, output/template, third-party client/message, and deserialization abstractions.

Candidates are not confirmed sources or sinks. They retain deterministic IDs, structural reasons, locations, value roles, confidence tiers, evidence references, and detector provenance. No new propagation semantics were added.

## 3. Route B Input candidate count

Route B produced 2,716 unique input candidates.

| Structural reason | Count |
|---|---:|
| `OVERRIDE_PARAMETER` | 1,928 |
| `REQUEST_CONTEXT_TYPE` | 683 |
| `ANNOTATED_BOUNDARY` | 98 |
| `CALLBACK_PARAMETER` | 7 |

Confidence tiers were 2,026 `STRUCTURE_HIGH`, 7 `STRUCTURE_MEDIUM`, and 683 `OPEN_CANDIDATE`.

## 4. Route B Effect candidate count

Route B produced 88 unique effect candidates.

| Structural reason | Count |
|---|---:|
| `THIRD_PARTY_EFFECT` | 41 |
| `STORAGE_ABSTRACTION` | 24 |
| `FRAMEWORK_OUTPUT` | 23 |

Confidence tiers were 24 `STRUCTURE_HIGH` and 64 `STRUCTURE_MEDIUM`.

## 5. Structural gating

The arithmetic-only candidate product was 95,939 pairs. Structural gating retained 13,214 unique pairs and rejected 82,725; the detector never materialized the full Cartesian product as candidate paths.

All 13,214 retained pairs had `SAME_PACKAGE` evidence. A subset also had stronger evidence: 20 `SAME_METHOD` and 18 `EFFECT_CALLS_INPUT_REGION`. No gated pair was connected by the frozen CodeQL base taint/data graph.

The concentration is material: V023 contributed 13,206 gated pairs and V007 contributed 8. The same-package rule therefore dominated candidate-pair volume, while stronger call/method relations covered only 38 pairs and still yielded no complete connection.

| Project | Inputs | Effects | Gated | Rejected | Static paths | Query s | Wall s |
|---|---:|---:|---:|---:|---:|---:|---:|
| P006 | 143 | 0 | 0 | 0 | 0 | 20.221 | 20.225 |
| P007 | 4 | 0 | 0 | 0 | 0 | 18.414 | 18.414 |
| P010 | 317 | 2 | 0 | 634 | 0 | 45.790 | 45.799 |
| P012 | 1 | 0 | 0 | 0 | 0 | 18.561 | 18.562 |
| D001 | 34 | 0 | 0 | 0 | 0 | 18.460 | 18.462 |
| D002 | 35 | 0 | 0 | 0 | 0 | 18.393 | 18.394 |
| D003 | 112 | 0 | 0 | 0 | 0 | 19.004 | 19.007 |
| D004 | 161 | 0 | 0 | 0 | 0 | 20.341 | 20.345 |
| V001 | 10 | 0 | 0 | 0 | 0 | 21.337 | 21.338 |
| V004 | 2 | 0 | 0 | 0 | 0 | 18.576 | 18.577 |
| V005 | 0 | 0 | 0 | 0 | 0 | 17.796 | 17.797 |
| V007 | 75 | 21 | 8 | 1,567 | 0 | 45.428 | 45.430 |
| V021 | 0 | 0 | 0 | 0 | 0 | 17.685 | 17.685 |
| V022 | 64 | 0 | 0 | 0 | 0 | 19.998 | 20.001 |
| V023 | 1,442 | 65 | 13,206 | 80,524 | 0 | 46.982 | 47.183 |
| V025 | 316 | 0 | 0 | 0 | 0 | 20.402 | 20.413 |
| V009 | 0 | 0 | 0 | 0 | 0 | 18.777 | 18.777 |
| V011 | 0 | 0 | 0 | 0 | 0 | 17.440 | 17.441 |

## 6. STATIC_AUGMENTED paths

`RouteBFlow::flow(input, effect)` found zero complete CodeQL base-graph connections after structural gating. Consequently:

- `STATIC_AUGMENTED paths = 0`
- `unique new candidate paths = 0`
- `COMPLETE_STATIC` Route B paths = 0

Structurally associated but unconnected pairs remain diagnostics and were not admitted to the final candidate path pool.

## 7. Native duplicates

There were zero static paths, so `NATIVE_DUPLICATE paths = 0`. No duplicate was counted as gain.

## 8. Unified pool

`UnifiedPool = CODEQL_NATIVE ∪ STATIC_AUGMENTED = 437 ∪ 0 = 437`.

The persisted artifacts contain 437 native rows, 0 static rows, and 437 unified rows.

## 9. Baseline preservation

All 437 native paths were retained byte-for-object after JSONL persistence.

- Native paths retained: `437/437`
- Native preservation rate: `1.0`
- Baseline preservation loss: `0`
- `NativePool ⊆ UnifiedPool`: `true`
- Native objects unchanged: `true`
- Preservation status: `PASS`

This is identity preservation, not vulnerability coverage.

## 10. GT Candidate Coverage

GT was loaded only by the post-hoc evaluator after the detector manifest marked the artifacts frozen. Twelve vulnerabilities were evaluable at method level; line-level coverage was not evaluable from the available GT.

| Metric | Native | Native + Route B |
|---|---:|---:|
| Candidate coverage | 2/12 (0.166667) | 2/12 (0.166667) |
| File-level covered | 2/12 | 2/12 |
| Method-level covered | 2/12 | 2/12 |
| Line-level covered | `NOT_EVALUABLE` | `NOT_EVALUABLE` |

Only D001 and D002 were covered in both B0 and B1. No project changed coverage status.

Per-CWE coverage was unchanged: CWE-022 2/7, CWE-078 0/2, CWE-079 0/1, and CWE-094 0/2.

## 11. StaticAugGain

`StaticAugGain = Coverage(Native + RouteB) - Coverage(Native) = 2 - 2 = 0`.

The registered conclusion is therefore:

`ROUTE_B_STATIC_NO_INCREMENTAL_COVERAGE`

The detector rules were not widened after observing this result.

## 12. Baseline-miss Recovery

Native missed 10/12 evaluable cases. Route B recovered 0/10:

- Baseline misses: `10`
- Recovery cases: `0`
- Recovery rate: `0.0`
- Recovery projects: none

`baseline_miss_recovery.jsonl` is empty, so there is no recovery provenance to attribute.

## 13. Incremental Expansion

The final candidate-path expansion is:

`(|UnifiedPool| - |NativePool|) / |NativePool| = (437 - 437) / 437 = 0.0`.

Although the final pool did not expand, the detector generated 2,804 endpoints and retained 13,214 structural pairs before base-graph connectivity rejected them. This is an endpoint/pair-scale cost without candidate-path or coverage gain.

## 14. Cost

- CodeQL query time: `423.609 s`
- Detector wall clock: `424.522 s`
- Peak child RSS: `1,170,016 KiB`
- Adapter-unmapped rows: `0`
- Projects successful: `18/18`
- CodeQL databases rebuilt: `false`

## 15. Route B source attribution

Because no `STATIC_AUGMENTED` path covered GT, all gain-attribution maps are empty:

- Boundary-only gain: `0`
- Effect-only gain: `0`
- Both-new-endpoints gain: `0`
- Gain by input structural reason: none
- Gain by effect structural reason: none

Candidate volume was dominated by `OVERRIDE_PARAMETER` inputs, while gated-pair volume was dominated by V023 and `SAME_PACKAGE`. Neither source produced a complete base-graph path.

## 16. Unresolved cases

The detector persisted 2,716 unresolved input candidates for later semantic adjudication. Of these, 683 are explicitly `OPEN_CANDIDATE`; the remainder retain high/medium structural confidence but are still not confirmed external sources.

There are 13,214 structurally gated yet base-graph-unconnected pairs. The 13,214 `SAME_PACKAGE` evidences are too weak and too concentrated to justify adding semantic propagation. The 38 stronger `SAME_METHOD` or direct call-region evidences also produced no base-graph connection.

This experiment does not support adding Wrapper/Library, Field/State, or framework semantic edges. No cross-project recovery attribution exists to justify any of them.

## 17. NEXT_RECOMMENDED_EXPERIMENT

`P0-C CONTEXT_SLICE_LLM_ON_FROZEN_HIGH_SIGNAL_ROUTE_B_FRONTIERS`

If a later experiment is approved, use only frozen, non-`SAME_PACKAGE`-only Route B frontier evidence (the 38 stronger same-method/direct-call cases) to construct bounded context slices for LLM adjudication. Keep the 437 native paths immutable, do not enlarge the Route B candidate rules, and do not add Wrapper/Library or Field/State semantics without independent cross-project recovery evidence.

P0-C was not started in this run.

## Artifact paths

- Raw detector and evaluator artifacts: `/workspace/experiment-output/artifacts/work1/p0_b_route_b/W1-P0-B-ROUTE-B-20260827-002/`
- Frozen native pool: `/workspace/experiment-output/artifacts/work1/p0_a1_native_pool/W1-P0-A1-NATIVE-POOL-20260827-001/native_candidate_paths.jsonl`

