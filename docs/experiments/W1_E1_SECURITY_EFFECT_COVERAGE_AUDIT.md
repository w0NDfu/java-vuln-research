# W1-E1 SecurityEffect Coverage Audit

## 1. Scope and freeze boundary

This is a detector-freeze, offline audit of the existing 18-project W1-E1 artifacts. It does not rerun CodeQL, alter E0, use benchmark positions to select rules, or start Route B, Wrapper/Library, Field/State, LLM, E2, or Work2.

Frozen headline counts:

| Item | Count |
|---|---:|
| ExternalInput candidates | 254 |
| SecurityEffect candidates (unique candidate_id) | 59 |
| FW-active candidates | 123 |
| BW-active candidates (unique candidate_id) | 14 |
| Structural-frontier rows | 287 |
| STATIC_CONNECTED candidate paths | 0 |
| E0 baseline paths | 437 |

## 2. SecurityEffect aggregation audit

### 2.1 Why 59 became 62

The detector emitted 59 unique SecurityEffect candidate identities. The earlier effect-type table was built after joining candidates to downstream frontier/diagnostic rows. A candidate can appear more than once after that join, so the table counted attribution rows rather than candidates. The three extra rows are repeated downstream representations, not three additional SecurityEffect candidates.

The same grain error affected the BW-active breakdown: filtering joined rows by BW state does not guarantee one row per candidate. Candidate-level statistics must first collapse by candidate_id; BW-active is the logical OR of all rows for the same candidate.

### 2.2 Correct unique-candidate statistics

All SecurityEffect candidates, deduplicated by candidate_id:

| effect_type | Unique candidates |
|---|---:|
| FILESYSTEM_ACCESS | 19 |
| DYNAMIC_EVALUATION | 19 |
| PROCESS_EXECUTION | 16 |
| RENDERING | 5 |
| **Total** | **59** |

BW-active SecurityEffect candidates, deduplicated by candidate_id:

| effect_type | Unique BW-active candidates |
|---|---:|
| FILESYSTEM_ACCESS | 7 |
| RENDERING | 3 |
| PROCESS_EXECUTION | 2 |
| DYNAMIC_EVALUATION | 2 |
| **Total** | **14** |

Structural-frontier participation has a different denominator: 287 raw frontier rows reduce to 6 unique input/effect pairs, 11 unique project/method regions, and 2 unique effect candidates. Both participating effects are RENDERING candidates. These numbers must not be added to candidate counts.

Candidate aggregation contract: every candidate-level table is keyed by unique candidate_id. Per-project, effect-type, mechanism, BW-active, and funnel totals are projections of that deduplicated relation. Pair- and frontier-level tables must name their own grain explicitly.

## 3. Input–Effect pair funnel

The frozen classifier works at candidate level, not Cartesian input/effect-pair level. Its exact mutually exclusive result is:

| Frozen outcome | Candidates | Interpretation |
|---|---:|---|
| EMPTY_FW | 131 | Input candidate has no persisted forward-reachable node |
| EMPTY_BW | 45 | Effect candidate has no persisted backward-reachable node |
| STRUCTURAL_FRONTIER | 5 | Candidate participates in at least one structural frontier but no static connection |
| STATIC_CONNECTED | 0 | Candidate participates in a persisted static candidate path |
| DIFFERENT_CALL_REGION | 132 | Endpoint is mapped/reachable but has neither a connection nor a stored radius-2 structural relation |
| **Total** | **313** | **254 Input + 59 Effect candidates** |

The requested labels DIFFERENT_CALL_COMPONENT and SAME_COMPONENT_BUT_FAR cannot be recovered exactly from the frozen artifacts. The persisted schema contains reachability, frontier relations, and candidate diagnostics, but no call-component identifier or distance beyond the accepted radius. Therefore the exact frozen value is:

- DIFFERENT_CALL_COMPONENT: not separately observable;
- SAME_COMPONENT_BUT_FAR: not separately observable;
- unresolved parent bucket DIFFERENT_CALL_REGION: 132.

Splitting 132 between those two labels would require a new CodeQL query or a detector rerun, both outside this audit. The report intentionally does not infer a split.

### 3.1 Why the added ten projects produced zero frontier

All 287 frontier rows still come from P010. They consist of 222 CALL_ADJACENT, 29 NEAR_CALL_REGION, and 36 SAME_METHOD rows; inputs are Servlet Parameter (185) and Parameter Values (102), and effects are RENDERING only.

A frontier exists only when both sides have persisted reachable nodes and satisfy one of the stored structural relations: same method, direct call adjacency, same receiver/field relation, or near-call region within the fixed radius. None of the ten added projects produced such a relation. The frozen evidence supports two causes:

1. one endpoint side is empty (the global EMPTY_FW=131 and EMPTY_BW=45 buckets);
2. both sides are mapped/reachable but no accepted radius-2 relation was persisted (part of DIFFERENT_CALL_REGION=132).

Because component membership and longer distance were not persisted, the offline audit cannot say how much of cause 2 is disconnected component versus same component but farther away. The scientifically valid conclusion is zero qualifying stored relation, not zero possible program path.

## 4. E0 post-hoc endpoint audit

E0 is used only after detector freeze as an independent sink-space audit. It did not choose projects, methods, files, lines, patches, CVEs, or candidate identities, and it is not fed back into individual detector exceptions.

### 4.1 Strict endpoint identity

Across 437 E0 paths:

| Check | Paths |
|---|---:|
| Route A Input identity present | 151 |
| Route A Input identity absent/unmatched | 286 |
| Route A Effect identity present | 0 |
| Both strict endpoint identities present | 0 |

The missing-input and missing-effect counts overlap. Since no E0 terminal effect has an exact Route A EffectIdentity match, there is no frozen case with both exact endpoints present for which a connection failure can be localized. Thus the dominant audited problem precedes path connection: effect endpoint identity/taxonomy coverage.

A looser effect audit classified the 437 E0 terminals as:

| Class | Paths | Meaning |
|---|---:|---|
| CALLSITE | 10 | Nearby/same-family callsite evidence, but identity differs |
| EFFECT_TYPE | 346 | Project has Route A effects, but the E0 terminal belongs to an uncovered semantic family/type |
| TRUE_MISSING | 81 | No Route A effect candidate exists in the project inventory |

The 81 TRUE_MISSING paths occur in D001, D003, D004, and P006. At rule-family level they are log injection 9, path injection 48, polynomial ReDoS 12, and regex injection 12. This is an aggregate post-hoc diagnosis, not a detector rule list.

### 4.2 E0 sink-space distribution

| E0 rule family | Paths | Unique terminal sites |
|---|---:|---:|
| log injection | 118 | 41 |
| path injection | 97 | 23 |
| sensitive log | 85 | 39 |
| user-controlled bypass | 39 | 8 |
| polynomial ReDoS | 23 | 6 |
| potentially weak crypto algorithm | 15 | 5 |
| regex injection | 12 | 3 |
| unvalidated redirect | 12 | 4 |
| unsafe deserialization | 7 | 2 |
| HTTP response splitting | 6 | 2 |
| local temp information disclosure | 4 | 3 |
| SSRF | 4 | 1 |
| weak crypto algorithm | 4 | 1 |
| CSRF-unprotected request | 3 | 1 |
| XSS | 3 | 1 |
| XXE | 3 | 1 |
| trust-boundary violation | 2 | 1 |
| **Total** | **437** | **120** |

## 5. Coverage judgment

The frozen run exposed two foundation-level Route A issues:

1. candidate aggregation used a downstream row grain and inflated type/BW tables;
2. SecurityEffect taxonomy and identity coverage were too narrow to represent the E0 sink space.

It does not yet prove a Route B path-construction deficit. Route A endpoint coverage and aggregation must be rerun once with the generic refactor before attributing remaining failures to interprocedural path search.

The evidence gives some support for future Wrapper/Library work because many missed effects are library-call families and wrappers, but that is not tested here. It does not currently support Field/State as the next move: the frozen artifacts lack the component/distance/state evidence required for that claim.

## 6. Audit conclusion

- E1 still had foundation implementation problems in the frozen run: **YES**.
- Those problems are identifiable without changing GT or rerunning CodeQL: **YES**.
- The frozen evidence alone supports moving directly to Route B: **NO**.
- Required next decision point: rerun W1-E1 once with the corrected generic Route A contract, then reassess the residual funnel.
