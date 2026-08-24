# Architecture

The repository separates four trust domains:

```text
versioned detector code -> ignored raw execution output
                         -> immutable detector JSONL
                         -> independent evaluator
                         -> compact versioned report
```

`src/java_vuln_research/common` owns provenance, hashing, manifest validation,
and process helpers. `discovery`, `frontier`, and `semantics` implement Work 1.
`evaluation` may access ground truth but is never imported by detector modules.
`scripts/` are thin Cloud entry points. `configs/local/` maps discovered server
paths and is always ignored.

The initial baseline invokes native/existing CodeQL Java security suites without
project-specific ground truth. Later P0-A discovery emits evidence-backed
`EXTERNAL_INPUT` and `SECURITY_EFFECT` candidates; it does not declare
vulnerabilities.

