# Research protocol

## Scope

This repository currently implements only Work 1: project-level vulnerability
path discovery from multi-semantic security behavior. P0 supports:

1. M1 — data and call semantics.
2. M2 — library and wrapper semantics.
3. M3 — field and state semantics.

Adaptive ranking/routing/stopping, fine-tuning, the 120-CVE formal experiment,
persistence modeling, broad control/framework modeling, whole-project agents,
reinforcement learning, and learning-to-rank are out of scope.

## Non-leakage contract

The formal Detector receives only a Java project `P` and environment facts
needed to locate that project or its CodeQL database. Detector code and runtime
input must not read or use:

- true CWE or CVE identifiers or descriptions;
- fix patches, fix commits, or `fix_info`;
- true vulnerable files, functions, or line numbers;
- manually annotated sources or sinks; or
- any ground-truth-derived scan scope.

The Detector must finish and persist its immutable output before the independent
Evaluator may read ground truth. Failure to build or analyze is an execution
failure, never a negative example.

The Detector must not import evaluation or ground-truth modules. The detector
manifest is limited to `project`, `revision`, `source_path`, and
`codeql_db_path`.

## Method boundary

The conceptual pipeline is:

```text
Java project
  -> CodeQL static facts
  -> external-input + security-effect discovery
  -> forward/backward multi-semantic search
  -> semantic-gap candidate
  -> static resolver
  -> local LLM only when static evidence is insufficient
  -> evidence validator
  -> sparse semantic overlay
  -> incremental re-analysis
  -> unsafe-context / effective-protection analysis
  -> vulnerability typing
  -> candidate vulnerabilities
```

The method must never regress to “receive the true CWE, find known CWE
sources/sinks, then scan.” A candidate is not a vulnerability merely because an
external input reaches a sensitive operation. Final typing requires:

```text
ExternalInput AND Reachability AND SecurityEffect
AND UnsafeContext AND NOT EffectiveProtection
```

## Development and formal evaluation

Development samples may inform debugging. Results on an instance used to
change the Detector are not claimed as formal performance. Formal tests require
a repository-level split followed by frozen method, prompts, rules, and model,
then one protocol run and independent evaluation.

