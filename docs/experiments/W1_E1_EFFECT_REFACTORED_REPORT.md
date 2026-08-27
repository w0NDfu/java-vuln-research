# W1-E1 SecurityEffect Refactored Validation Report

## Scope and freeze boundary

- Logical run: `W1-E1-EFFECT-REFACTORED-20260827-001-RUN`
- Branch: `exp/w1-e1-candidate-path-coverage`
- Frozen manifest: `experiments/frozen_configs/w1_e1_dev16_manifest.yaml`
- Cloud raw run root: `/workspace/experiment-output/W1-E1-EFFECT-REFACTORED-20260827-001-RUN/`
- Endpoint discovery root: `/workspace/experiment-output/W1-E1-EFFECT-REFACTORED-20260827-001/endpoint/`
- Detector commit recorded in candidate paths: `b4c11c31b3a0e6e6d100513802c24b737b694be1`
- CodeQL: `2.26.3`; Java: `17.0.10`
- Manifest SHA-256: `594a4ee9902d98f7a6455e59313c8da0084e317d6624657cd46f7175004004b`
- SecurityEffectDiscovery SHA-256: `2764e98ac24700edbc3e1aa2c831244246829606a083e49ef51290558c099d5d`
- SecurityEffectModels SHA-256: `b656e82fae973cb6ceda063891b5637aa0a76b894087611ecd5d93d3c2e2d2b`
- Tests: `42 passed in 2.09s`
- Projects: `18/18 SUCCESS`; CodeQL query errors `0`
- `detector_ground_truth_access=false`; `scientific_method_changed=NO`

This is still W1-E1. No detector redesign, new effect rule, Wrapper/Library, Field/State, Route B, E2, or LLM was run.

## Old versus refactored W1-E1

| Metric | Old W1-E1 | Refactored W1-E1 |
|---|---:|---:|
| ExternalInput candidates | 254 | 254 |
| SecurityEffect candidates (unique `candidate_id`) | 59 | 1,950 |
| Candidate expansion factor | 1.0x | 33.050847x (1,950/59) |
| FW-active inputs | 123 | 123 |
| BW-active effects | 14 | 704 |
| E0 source matched | 151 | 151 |
| E0 effect matched | 0 | 150 |
| E0 both endpoints matched | 0 | 38 |
| E0 both endpoints active | 0 | 38 |
| E0-derived admitted unique pairs | 0 | 35 |
| E0-derived STATIC_CONNECTED rows | 0 | 38 |
| Overall STATIC_CONNECTED rows | 0 | 118 |
| Structural-frontier projects | 1 | 5 |
| Candidate Coverage | `NOT_EVALUABLE/0` | `1/12` (8.33%, file/method; line `NOT_EVALUABLE`) |
| Baseline-miss Recovery | 0 | 0/10 |

The refactor is effective at endpoint recovery: E0 effect identity matches rise from 0 to 150, both-endpoint cases appear for the first time, and the frozen Base Data/Call layer produces 118 static candidate paths. The gain is distributed across the newly covered effect families (`CRYPTOGRAPHIC_CONFIGURATION`, `DESERIALIZATION`, `DYNAMIC_EVALUATION`, `FILESYSTEM_ACCESS`, `NETWORK_OUTPUT`, `PROCESS_EXECUTION`, `REGEX_EVALUATION`, and `RENDERING`) rather than one duplicated label.

The cost is a large candidate expansion and incomplete BW reachability: 1,236/1,950 effects are `EMPTY_BW`, 3 effects are unmappable, and 11 candidate diagnostics are adapter errors. Thus the refactor fixes the former zero-effect-match bottleneck but does not establish high benchmark coverage.

## Unique SecurityEffect accounting

All counts below are keyed by unique `candidate_id`; downstream diagnostic/frontier rows are not added to candidate totals.

| effect_type | unique candidates | BW-active | BW-empty |
|---|---:|---:|---:|
| `CRYPTOGRAPHIC_CONFIGURATION` | 40 | 13 | 27 |
| `DESERIALIZATION` | 104 | 26 | 78 |
| `DYNAMIC_EVALUATION` | 19 | 2 | 17 |
| `FILESYSTEM_ACCESS` | 1,042 | 319 | 715 |
| `NETWORK_OUTPUT` | 101 | 71 | 30 |
| `PROCESS_EXECUTION` | 16 | 14 | 2 |
| `REGEX_EVALUATION` | 544 | 227 | 317 |
| `RENDERING` | 84 | 32 | 44 |
| **Total** | **1,950** | **704** | **1,236** |

Any earlier table whose sum differs from 1,950 is a record/label-grain aggregation error, not additional SecurityEffect candidates.

## Input–Effect pair funnel

The frozen pipeline persists endpoint-level funnel records and observed pair records; these grains are deliberately kept separate and are not additive.

| Funnel item | Refactored count | Grain / interpretation |
|---|---:|---|
| `EMPTY_FW` | 131 | Input candidates with no forward-reachable node |
| `EMPTY_BW` | 1,236 | Effect candidates with no backward-reachable node |
| `DIFFERENT_CALL_COMPONENT` | 250,357 raw rows | `CALL_ADJACENT` + `NEAR_CALL_REGION`; component split is a post-hoc interpretation |
| `SAME_COMPONENT_BUT_FAR` | Not observable | Frozen artifacts do not persist a call-component ID or longer-distance relation |
| `STRUCTURAL_FRONTIER` | 656 unique candidate pairs / 320,424 raw rows | Five projects; reasons: `CALL_ADJACENT` 139,030, `NEAR_CALL_REGION` 111,327, `SAME_METHOD` 69,987, `FIELD_RELATED` 8, `SAME_RECEIVER` 72 |
| `STATIC_CONNECTED` | 118 unique pairs / 118 rows | Five projects: P010 4, D001 16, D002 16, V022 64, V025 18 |

Structural frontiers now occur in `P010`, `D001`, `D002`, `V022`, and `V025`. Among the ten added validation projects, `V022` and `V025` now produce frontiers (269,247 and 4,885 rows respectively); the other eight remain at zero because one endpoint side is empty or no stored structural relation qualifies. The prior “all added projects are zero frontier” observation therefore does not hold after the refactored SecurityEffect inventory.

## E0 path-level post-hoc traceability

The audit reads the frozen E0 SARIF only after detector output was persisted. It does not feed labels, CVEs, or E0 paths back into candidate discovery.

- E0 native paths: `437`
- Route A source matched: `151`
- Route A effect matched: `150`
- Both endpoints matched: `38`
- Both endpoints FW/BW active: `38`
- E0-derived admitted unique input/effect pairs: `35`
- E0-derived STATIC_CONNECTED rows: `38`

E0-path failure taxonomy (mutually exclusive at path grain):

| Classification | Count |
|---|---:|
| `MISSING_INPUT_CANDIDATE` | 112 |
| `MISSING_EFFECT_CANDIDATE` | 113 |
| `MISSING_BOTH_CANDIDATES` | 174 |
| `INPUT_FW_EMPTY` | 0 |
| `EFFECT_BW_EMPTY` | 0 |
| `PAIR_GATE_REJECTED` | 0 |
| `SAME_REGION_NO_BASE_FLOW` | 0 |
| `STRUCTURAL_FRONTIER` | 0 |
| `STATIC_CONNECTED` | 38 |
| `NOT_EVALUABLE` | 0 |
| `IMPLEMENTATION_ERROR` | 0 |
| **Total** | **437** |

The 38 cases with both endpoints present are all active and connected; there is no frozen evidence of a both-active pair being rejected by the connector. The remaining E0 paths fail before pair connection (112 input-only misses, 113 effect-only misses, 174 misses on both sides).

## Independent evaluator

The independent evaluator ran after candidate paths were written. It reports 12 evaluable cases out of 14 projects with matching dataset revisions: file-level and method-level candidate coverage `1/12` (8.33%), line-level `NOT_EVALUABLE`; E0 baseline coverage `2/12`; baseline misses `10`; W1-E1 recovery `0`. This is an evaluation limitation/coverage result, not a detector feedback channel.

## Decision

**Primary outcome: `BASE_DATA_CALL_NOW_FORMS_CANDIDATE_PATHS`.**

The refactor is demonstrably effective and the Base Data/Call W1-E1 layer now forms static candidate paths. A residual endpoint/scale problem remains (large SecurityEffect expansion, 1,236 BW-empty effects, 3 unmappable effects, 11 adapter diagnostics, and only 1/12 independent coverage), so this run does not justify adding propagation semantics. The evidence supports preparing the next controlled Route B decision/review, but Route B is not started by this report. It does not support claiming Wrapper/Library or Field/State.

`NEXT_RECOMMENDED_EXPERIMENT=ROUTE_B_CONTROLLED_REVIEW_AFTER_ENDPOINT_SCALE_AUDIT`

STOP. No next experiment was started.

## Cloud raw artifacts

All artifacts below are under `/workspace/experiment-output/W1-E1-EFFECT-REFACTORED-20260827-001-RUN/`:

- `summary.md`, `metrics.json`, `detector_metrics.json`, `funnel_metrics.json`
- `endpoint_candidates.jsonl` (discovery copy is under the parent endpoint root)
- `input_forward_funnel.jsonl`, `effect_backward_funnel.jsonl`
- `candidate_paths.jsonl`, `frontier_cases.jsonl`, `structural_frontiers.jsonl`
- `path_traceability.jsonl`, `failure_taxonomy.json`, `audit_summary.json`
- `project_metrics.csv`, `run_manifest.json`, `coverage_metrics.json`, `coverage_cases.jsonl`, `baseline_miss_recovery.jsonl`, `e0_evaluator_sanity.json`
