# W1-E1 Attribution Analysis

## 1. Scope

Read-only attribution of frozen W1-E1 artifacts. No new detector run, no CodeQL
rerun, no scientific method change, no semantic edge, no LLM, and no Route B.

## 2. Frozen W1-E1 facts

8/8 projects; 114 ExternalInput; 78 FW-active; 23 SecurityEffect; 5 BW-active;
287 structural frontiers; 0 static connected paths.

## 3. Frontier taxonomy

| frontier_reason | count | percentage |
| --- | --- | --- |
| CALL_ADJACENT | 222 | 77.3519 |
| SAME_METHOD | 36 | 12.5436 |
| NEAR_CALL_REGION | 29 | 10.1045 |

Distance buckets:

| distance_bucket | count | percentage |
| --- | --- | --- |
| 1 | 222 | 77.3519 |
| 0 | 36 | 12.5436 |
| 2 | 29 | 10.1045 |

## 4. Deduplicated frontier distribution

{
  "raw_frontier_count": 287,
  "unique_frontier_node_pair_count": 287,
  "unique_input_effect_pair_count": 6,
  "unique_project_method_region_count": 11
}

## 5. Frontier by project

| project | frontier_count | unique_input_effect_pairs | percentage |
| --- | --- | --- | --- |
| P010 | 287 | 6 | 100.0 |

top1_project_share=1.000000; top3_project_share=1.000000

## 6. Frontier by input mechanism

| input_mechanism | count | percentage |
| --- | --- | --- |
| SERVLET_PARAMETER | 185 | 64.4599 |
| SERVLET_PARAMETER_VALUES | 102 | 35.5401 |

## 7. Frontier by effect type

| effect_type | count | percentage |
| --- | --- | --- |
| RENDERING | 287 | 100.0 |

## 8. Likely semantic class

These are LIKELY_FRONTIER_CLASS attributions, not confirmed semantic gaps.

| likely_class | count | percentage |
| --- | --- | --- |
| DIRECT_DATA_CALL_NEAR_MISS | 222 | 77.3519 |
| SAME_METHOD_UNRESOLVED | 36 | 12.5436 |
| CALL_BOUNDARY_UNRESOLVED | 29 | 10.1045 |

## 9. SecurityEffect BW funnel

| effect_type | total_candidates | mapped | bw_active | bw_inactive | bw_active_rate |
| --- | --- | --- | --- | --- | --- |
| DYNAMIC_EVALUATION | 19 | 19 | 2 | 17 | 0.105263 |
| RENDERING | 4 | 4 | 3 | 1 | 0.75 |

## 10. BW inactive root causes

| root_cause | count |
| --- | --- |
| NO_PREDECESSOR_IN_BASE_DATA_CALL | 18 |

## 11. BW failure by effect type

| effect_type | total_candidates | mapped | bw_active | bw_inactive | bw_active_rate |
| --- | --- | --- | --- | --- | --- |
| DYNAMIC_EVALUATION | 19 | 19 | 2 | 17 | 0.105263 |
| RENDERING | 4 | 4 | 3 | 1 | 0.75 |

## 12. BW failure by anchor/value role

| anchor_role | total | mapped | bw_active | bw_inactive | bw_active_rate |
| --- | --- | --- | --- | --- | --- |
| CALL_ARGUMENT | 23 | 23 | 5 | 18 | 0.217391 |

## 13. Key findings

Raw frontier count=287; deduplicated node-pair count=287.
Top frontier reason=CALL_ADJACENT; top likely class=DIRECT_DATA_CALL_NEAR_MISS.
Project concentration=PROJECT_CONCENTRATED evidence; post-hoc GT overlay=NOT_AVAILABLE.

## 14. NEXT_RECOMMENDED_EXPERIMENT

PROJECT_CONCENTRATED_EVIDENCE; INSUFFICIENT_EVIDENCE_FOR_E2

Do not start E2 from this Dev8 result. Preserve the current W1-E1 scientific
method; if implementation fixes are pursued, validate them under W1-E1 before
selecting a new semantic mechanism.
