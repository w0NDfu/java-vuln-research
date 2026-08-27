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

### 4.2 E0 semantic-space distribution

The audit keeps four grains separate. The 437 path rows contain 142 rule-scoped sink identities, because one physical callsite may be reported by more than one rule. Removing rule_id from the identity gives 120 global sink identities and 120 global callsites, distributed over 9 projects.

| rule_id | Neutral family | Paths | Rule-scoped sink identities / callsites | Projects | Callee/API family observed at the terminal | CALLSITE | EFFECT_TYPE | TRUE_MISSING |
|---|---|---:|---:|---:|---|---:|---:|---:|
| `java/log-injection` | log injection | 118 | 41 | 5 | SLF4J/Log4j/JUL-style logging calls | 1 | 108 | 9 |
| `java/path-injection` | path injection | 97 | 23 | 4 | file/path constructors, streams and resource/file operations | 4 | 45 | 48 |
| `java/sensitive-log` | sensitive data in logs | 85 | 39 | 3 | logging calls with data-bearing arguments | 0 | 85 | 0 |
| `java/user-controlled-bypass` | user-controlled security bypass | 39 | 8 | 3 | authorization/policy decisions and security-sensitive branches | 0 | 39 | 0 |
| `java/polynomial-redos` | polynomial ReDoS | 23 | 6 | 5 | regex compilation/evaluation APIs | 0 | 11 | 12 |
| `java/potentially-weak-cryptographic-algorithm` | potentially weak crypto configuration | 15 | 5 | 1 | JCA/JCE algorithm factory calls | 0 | 15 | 0 |
| `java/regex-injection` | regex injection | 12 | 3 | 3 | Pattern/String regex APIs | 0 | 0 | 12 |
| `java/unvalidated-url-redirection` | unvalidated redirect | 12 | 4 | 2 | servlet redirect APIs | 0 | 12 | 0 |
| `java/unsafe-deserialization` | unsafe deserialization | 7 | 2 | 1 | object/XML deserialization readers | 0 | 7 | 0 |
| `java/http-response-splitting` | HTTP response splitting | 6 | 2 | 2 | servlet response header APIs | 2 | 4 | 0 |
| `java/local-temp-file-or-directory-information-disclosure` | local temporary resource disclosure | 4 | 3 | 2 | temporary-file/directory construction and access | 0 | 4 | 0 |
| `java/ssrf` | server-side request forgery | 4 | 1 | 1 | URL/HTTP client request APIs | 0 | 4 | 0 |
| `java/weak-cryptographic-algorithm` | weak crypto configuration | 4 | 1 | 1 | JCA/JCE algorithm factory calls | 0 | 4 | 0 |
| `java/csrf-unprotected-request-type` | CSRF-unprotected request | 3 | 1 | 1 | request-handler/policy semantics | 0 | 3 | 0 |
| `java/xss` | cross-site scripting | 3 | 1 | 1 | response rendering/output APIs | 3 | 0 | 0 |
| `java/xxe` | XML external entity handling | 3 | 1 | 1 | XML parser/factory configuration | 0 | 3 | 0 |
| `java/trust-boundary-violation` | trust-boundary violation | 2 | 1 | 1 | session/state boundary operations | 0 | 2 | 0 |
| **Total** |  | **437** | **142 rule-scoped / 120 global** | **9 global** |  | **10** | **346** | **81** |

The mismatch columns are a post-hoc decomposition of the frozen identity audit. They do not assert that a newly modeled family now covers every E0 callsite. In particular, `COVERED_BY_EXISTING_PRIMITIVE` below means that the refactored generic taxonomy has a suitable primitive family; exact callsite coverage remains a rerun question.

### 4.3 Cross-project distribution

| project_id | E0 paths | Global sink identities / callsites | Rule families |
|---|---:|---:|---:|
| D001 | 57 | 14 | 2 |
| D002 | 55 | 14 | 2 |
| D003 | 8 | 2 | 2 |
| D004 | 8 | 2 | 2 |
| P006 | 8 | 2 | 2 |
| P010 | 51 | 30 | 5 |
| V009 | 8 | 3 | 2 |
| V022 | 136 | 24 | 11 |
| V025 | 106 | 29 | 9 |
| **Total** | **437** | **120** | **17 distinct globally** |

The distribution is not a single-project anomaly: 9 projects and 17 rule families contribute terminals. V022 and V025 account for 242 paths, but every reported family is evaluated through the same generic taxonomy rather than a project-specific exception.

## 5. Taxonomy gap matrix

This matrix classifies semantic families, not individual vulnerable locations. It was produced after detector freeze and is used only to decide whether a generic primitive family exists. It does not encode any project, CVE, file, method, line, patch, or GT location.

| E0 family | Audit class | Generic rationale / current boundary |
|---|---|---|
| log injection | `EFFECT_FAMILY_MISSING` | No logging SecurityEffect family; overload and placeholder roles need a generic logging model. |
| path injection | `TAXONOMY_EXISTS_BUT_PRIMITIVE_MISSING` | FILESYSTEM_ACCESS exists, but constructors/stream and broader path-consuming APIs are not yet modeled. |
| sensitive log | `EFFECT_FAMILY_MISSING` | Same missing logging family, with a distinct data-sensitivity interpretation outside a bare callee name. |
| user-controlled bypass | `OUT_OF_CURRENT_WORK1_SCOPE` | Primarily authorization/control-policy semantics, not a single terminal call primitive. |
| polynomial ReDoS | `COVERED_BY_EXISTING_PRIMITIVE` | REGEX_EVALUATION models Pattern and String regex evaluation with an explicit critical value. |
| potentially weak crypto | `COVERED_BY_EXISTING_PRIMITIVE` | CRYPTOGRAPHIC_CONFIGURATION models JCA/JCE getInstance algorithm argument 0. |
| regex injection | `COVERED_BY_EXISTING_PRIMITIVE` | REGEX_EVALUATION covers typed Pattern/String regex APIs. |
| unvalidated redirect | `COVERED_BY_EXISTING_PRIMITIVE` | RENDERING includes HttpServletResponse.sendRedirect argument 0. |
| unsafe deserialization | `COVERED_BY_EXISTING_PRIMITIVE` | DESERIALIZATION includes typed ObjectInputStream/XMLDecoder receiver effects. |
| HTTP response splitting | `COVERED_BY_EXISTING_PRIMITIVE` | RENDERING includes typed setHeader/addHeader value argument 1. |
| local temporary resource disclosure | `TAXONOMY_EXISTS_BUT_PRIMITIVE_MISSING` | FILESYSTEM_ACCESS exists, but constructor/lifecycle identity is intentionally deferred. |
| SSRF | `COVERED_BY_EXISTING_PRIMITIVE` | NETWORK_OUTPUT covers URL/URLConnection, Java HttpClient and Spring RestOperations families. |
| weak crypto | `COVERED_BY_EXISTING_PRIMITIVE` | CRYPTOGRAPHIC_CONFIGURATION models the algorithm/transformation argument. |
| CSRF-unprotected request | `OUT_OF_CURRENT_WORK1_SCOPE` | Requires request-handler and policy/control-flow semantics. |
| XSS | `CALLSITE_ROLE_MISMATCH` | A RENDERING family exists, but the frozen near matches are different callsites/roles, not identical effects. |
| XXE | `OUT_OF_CURRENT_WORK1_SCOPE` | Requires parser factory/object-state configuration rather than the current terminal-call contract. |
| trust-boundary violation | `OUT_OF_CURRENT_WORK1_SCOPE` | Requires session/state-boundary semantics. |

Class coverage across the requested vocabulary:

| Class | Families |
|---|---:|
| `COVERED_BY_EXISTING_PRIMITIVE` | 8 |
| `TAXONOMY_EXISTS_BUT_PRIMITIVE_MISSING` | 2 |
| `EFFECT_FAMILY_MISSING` | 2 |
| `CALLSITE_ROLE_MISMATCH` | 1 |
| `OUT_OF_CURRENT_WORK1_SCOPE` | 4 |
| `UNKNOWN` | 0 |

No family is left UNKNOWN at this semantic granularity. That does not eliminate callsite-level uncertainty: only a new Route A rerun can measure the exact post-refactor candidate coverage.

## 6. Coverage judgment

The frozen run exposed two foundation-level Route A issues:

1. candidate aggregation used a downstream row grain and inflated type/BW tables;
2. SecurityEffect taxonomy and identity coverage were too narrow to represent the E0 sink space.

It does not yet prove a Route B path-construction deficit. Route A endpoint coverage and aggregation must be rerun once with the generic refactor before attributing remaining failures to interprocedural path search.

The evidence gives some support for future Wrapper/Library work because many missed effects are library-call families and wrappers, but that is not tested here. It does not currently support Field/State as the next move: the frozen artifacts lack the component/distance/state evidence required for that claim.

## 7. Audit conclusion

- E1 still had foundation implementation problems in the frozen run: **YES**.
- Those problems are identifiable without changing GT or rerunning CodeQL: **YES**.
- The frozen evidence alone supports moving directly to Route B: **NO**.
- Required next decision point: rerun W1-E1 once with the corrected generic Route A contract, then reassess the residual funnel.
