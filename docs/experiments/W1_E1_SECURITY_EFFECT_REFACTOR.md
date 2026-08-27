# W1-E1 SecurityEffect Refactor

## 1. Decision and boundaries

This change repairs generic Route A SecurityEffect coverage, identity, and candidate-level aggregation. It does not change the scientific question, project selection, frozen revisions, E0 baseline, structural radius, graph search, or evaluation protocol.

No project name, CVE, benchmark file, method, line, patch, ground-truth position, or known vulnerable path is encoded in the detector. E0 was consulted only after freeze to identify aggregate missing semantic families. Route B, Wrapper/Library expansion, Field/State, LLM, E2, and Work2 are not implemented or executed.

scientific_method_changed: **NO**

## 2. Original taxonomy

The frozen detector had four SecurityEffect types:

| effect_type | Original generic primitives |
|---|---|
| FILESYSTEM_ACCESS | selected java.nio.file.Files methods, critical argument 0 |
| PROCESS_EXECUTION | Runtime.exec argument 0; ProcessBuilder.start receiver |
| RENDERING | servlet writer/output-stream body argument 0 |
| DYNAMIC_EVALUATION | ScriptEngine.eval and Spring parseExpression argument 0 |

The effect model was duplicated between SecurityEffectDiscovery.ql and EndpointCandidates.qll. Identity metadata was also reconstructed differently by discovery and candidate-path extraction. That drift made audits fragile and encouraged downstream tables to infer identity from display columns.

## 3. Refactored taxonomy

SecurityEffectModels.qll is now the single generic model consumed by discovery and candidate-path extraction.

| effect_type | New or adjusted generic families | Critical anchor |
|---|---|---|
| FILESYSTEM_ACCESS | NIO Files; Class/ClassLoader resource lookup; java.io.File operations | path/name arg 0 or File receiver |
| PROCESS_EXECUTION | Runtime.exec; ProcessBuilder.start | command arg 0 or builder receiver |
| RENDERING | servlet writer/output-stream body; sendRedirect; setHeader/addHeader | body/URL arg 0; header value arg 1 |
| DYNAMIC_EVALUATION | ScriptEngine.eval; Spring expression parsing | expression arg 0 |
| REGEX_EVALUATION | Pattern.compile; Pattern.matcher input; String regex APIs | regex or evaluated input arg 0 |
| DESERIALIZATION | ObjectInputStream.readObject/readUnshared; XMLDecoder.readObject | stream/decoder receiver |
| NETWORK_OUTPUT | URL/URLConnection; Java HttpClient send/sendAsync; Spring RestOperations URL | request/URL arg 0 or URL receiver |
| CRYPTOGRAPHIC_CONFIGURATION | JCA/JCE getInstance factories | algorithm/transformation arg 0 |

The additions are semantic API families defined by declaring type, method signature/name, and critical argument role. They are not lists of benchmark callsites.

### 3.1 Intentionally deferred

- Logging sinks: overloads and placeholder conventions require a separate critical-argument model.
- Authorization, CSRF, and trust-boundary effects: control-flow or policy semantics rather than one call primitive.
- XXE configuration: requires object state/configuration modeling.
- Constructor/object-creation families such as FileInputStream: pending a consistent constructor identity.
- Project-specific third-party APIs and arbitrary wrappers.
- Field/state propagation and Route B graph expansion.

## 4. Stable SecurityEffect contract

Every persisted SecurityEffect candidate now has at least:

candidate_id, project_id, effect_type, entity, callee_identity, method_identity, call_identity, critical_role, argument_index, anchor_kind, location, discovery_route, evidence_kind, primitive_rule_id, provenance.

Compatibility fields such as mechanism, confidence, source, and critical_roles remain available where existing consumers require them.

Identity responsibilities are centralized:

- callee_identity describes the resolved called method;
- method_identity describes the enclosing method;
- call_identity describes the concrete callsite;
- critical_role is `arg0`, `arg1`, or `receiver` for direct primitives, and
  `parameter:<name>` for a direct one-hop wrapper;
- argument_index is the zero-based critical argument, or -1 for receiver;
- anchor_kind is `CALL_ARGUMENT`, `RECEIVER`, or `METHOD_PARAMETER`;
- primitive_rule_id identifies the generic model rule;
- provenance records direct primitive versus one-hop wrapper discovery.

EndpointCandidates.qll and SecurityEffectDiscovery.ql both import SecurityEffectModels.qll, so discovery and graph anchors cannot silently diverge by maintaining separate taxonomies.

## 5. Candidate aggregation contract

Candidate-level analysis must deduplicate by candidate_id before grouping. The implementation now:

1. collapses duplicate candidate rows to one canonical row;
2. computes BW-active as a logical OR across duplicate rows;
3. builds effect-type summaries from the unique effect-candidate map;
4. keeps frontier-row, frontier-pair, and candidate grains separate;
5. persists security_effect_candidate_count and the aggregation contract in the summary.

This directly repairs the frozen 59-versus-62 discrepancy and the inconsistent BW-active type totals. It does not mutate the frozen artifacts; it corrects future attribution runs and provides regression coverage.

## 6. Generic validation

### 6.1 Fixture contract

The isolated taxonomy fixture uses JDK APIs plus a minimal local Jakarta servlet interface stub. For each newly added or adjusted family it includes:

- a positive correctly typed API use;
- a same-name method on an unrelated type, which must not match;
- a call where the critical argument/receiver position is explicit.

The contract test checks shared-model use, effect-type enumeration, type/signature guards, critical argument mapping, primitive rule IDs, identity fields, and absence of project/CVE/file/method/line special cases.

### 6.2 Executed checks

Executed in CloudStudio:

    python -m pytest -q tests/unit
    42 passed in 4.51s

Executable CodeQL taxonomy/AnalysisAnchor contract against an isolated, non-benchmark Java fixture database:

    CODEQL_BIN=/workspace/tools/codeql/codeql \
      python -m pytest -q tests/integration/test_security_effect_taxonomy_codeql.py
    1 passed in 71.46s

The executable contract observed the expected typed JDK/Jakarta calls for regex evaluation, deserialization, filesystem receiver access, cryptographic configuration, network output, redirect, and response-header output. It asserted the exact effect_type, primitive_rule_id, argument index, critical role, and AnalysisAnchor kind; every same-name call on the unrelated fixture types was absent.

Python compilation:

    python -m py_compile src/java_vuln_research/discovery/runner.py src/java_vuln_research/analysis/w1_e1_attribution.py tests/unit/test_discovery.py tests/unit/test_w1_e1_attribution.py tests/unit/test_security_effect_taxonomy_contract.py
    PASS

CodeQL query-plan compilation:

    /workspace/tools/codeql/codeql query compile \
      codeql/security_effect/SecurityEffectDiscovery.ql \
      codeql/candidate_path/InputForward.ql \
      codeql/candidate_path/AnalysisAnchors.ql \
      codeql/candidate_path/EffectBackward.ql \
      codeql/candidate_path/DataCallFrontier.ql \
      codeql/candidate_path/DataCallConnected.ql
    Done [6/6]

SecurityEffectDiscovery.ql was compiled again after adding its stable query id and completed successfully without the prior table-query metadata warning. git diff --check also passed.

Only the isolated toy fixture database was created and queried. No frozen project CodeQL database was queried and no 18-project W1-E1 rerun was executed.

## 7. Next-stage rerun

Rerun W1-E1: **YES, but only in the next stage after this report/commit; not during this task.** Reuse the frozen P0-A/E0 outputs and frozen 18-project manifest. Use a new run id so frozen evidence is not overwritten:

    DEV16_MANIFEST=/workspace/java-vuln-research/experiments/frozen_configs/w1_e1_dev16_manifest.yaml

    CLOUD_PATHS_CONFIG=/workspace/java-vuln-research/configs/local/cloud.paths.yaml \
    W1_E1_DATASET_ROOT=/workspace/datasets/cwe-bench-java \
    CODEQL_BIN=/workspace/tools/codeql-2.26.3/codeql \
    bash scripts/run_w1_e1.sh \
      /workspace/experiment-output/W1-E1-DEV16-P0A-20260826-001 \
      /workspace/experiment-output/W1-E1-DEV16-E0-20260826-001 \
      msa-p0-devset \
      afe0ebd0adc237abb46255f9ccd479b1d71819136 \
      W1-E1-DEV18-SE-YYYYMMDD-001 \
      "$DEV16_MANIFEST"

Acceptance checks for that rerun:

- unique SecurityEffect totals equal the sum of effect-type totals;
- unique BW-active totals equal the sum of BW-active effect-type totals;
- all required identity fields are non-empty or use the documented receiver sentinel;
- funnel categories are reported at one declared grain;
- compare endpoint coverage and STATIC_CONNECTED only after those invariants pass.

## 8. Remaining risks

The refactor is compiled and unit-tested but has not been executed against the 18 CodeQL databases. Coverage can increase false positives, especially for broad File, URL, and String regex APIs; the rerun must inspect generic mechanism/type distributions before any path-quality claim.

Current evidence supports testing the corrected Route A first. If endpoints improve while paths remain disconnected, Route B becomes justified. Wrapper/Library has a plausible later rationale from the aggregate E0 library-call families. Field/State is not yet evidenced by the frozen schema and should not be selected before component/distance diagnostics exist.
