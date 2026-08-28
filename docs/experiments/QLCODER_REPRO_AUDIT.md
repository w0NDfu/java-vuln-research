# QLCoder Reproduction Audit

## Reproduction identity

- Official repository: <https://github.com/neuralprogram/qlcoder>
- Pinned QLCoder commit: `6095f90f3b4906f36e2e2fe7d1d0bc987750ca2b`
- Pinned CodeQL LSP MCP dependency: `a33ea82bba156dc8352a0ecd85baff34cbb950ed`
- Paper: *QLCoder: A Query Synthesizer For Static Analysis of Security Vulnerabilities*, ICLR 2026
- Role in this study: `PRIOR-ASSISTED POSITIVE CONTROL / SANITY BASELINE`

QLCoder is not a no-prior project scanner. It synthesizes a CVE-specific query from an existing vulnerability and validates the query against vulnerable and fixed versions.

## Required input and prior knowledge

- CVE metadata/description: **YES**.
- CVE identifier: **YES**.
- Patch/diff: **YES**; the initial path-query template is populated with an AST extracted from the diff.
- Vulnerable/fixed repository pair: **YES**.
- Vulnerable and fixed CodeQL databases: **YES**.
- Fix files/methods for execution-guided success evaluation: **YES**.

These inputs are retained because they are part of the original protocol. They are never copied into Current Work1, Route A, Route B, Route C, SecurityEffect, ExternalInput, or propagation semantics.

## LLM model, agent, and provider

- Paper/default model: `sonnet-4`
- Concrete model id in the implementation: `claude-sonnet-4-20250514`
- Agent backend: Claude Code
- Paper Claude Code version: `1.0.120`
- Required credential: `ANTHROPIC_API_KEY` or the supported Claude Code OAuth token
- Default ablation mode: `full`
- Default maximum iterations: `5`

The upstream Dockerfile currently installs the latest Claude Code. The reproduction environment must pin `@anthropic-ai/claude-code@1.0.120` so that an unrecorded client upgrade is not mistaken for the paper environment.

## CodeQL and supporting services

- Paper CodeQL version: `2.22.2`
- Paper Gemini CLI version: `0.6.0` (not used in the primary run)
- Paper Codex CLI version: `0.38.0` (not used in the primary run)
- Python environment: `3.11.11`
- Required services: ChromaDB, CodeQL LSP MCP server, CodeQL packs/document retrieval, and the selected agent backend.

The pinned LSP MCP commit has no package lock, uses semver ranges, and fixes TypeScript `moduleResolution` to legacy `node`. On 2026-08-28, the official `npm install && npm run build` command resolved a dependency layout that TypeScript could not compile (`TS2307` for `vscode-languageserver-protocol`). The cloud harness applies only the compiler-resolution overlay `--moduleResolution bundler`; this was verified to compile at the same source commit and does not alter QLCoder queries, prompts, priors, tools, or success semantics. Both the upstream failure and the successful overlay build are retained as raw artifacts.

The official setup builds vulnerable and fixed databases separately with `--build-mode=none`. Those method-owned databases are distinct from the frozen Work1 2.26.3 databases and must be recorded under the QLCoder raw-artifact tree.

## Official invocation

The upstream workflow is:

```bash
python3 scripts/get_cve_repos.py --cve CVE-2018-9159
python3 scripts/build_codeql_dbs.py --cve-id CVE-2018-9159
python3 scripts/cves_fetcher.py
./run_cve.sh CVE-2018-9159 --model sonnet-4 --agent claude --max-iteration 5
```

`run_cve.sh` passes all three required conditioned inputs explicitly:

```text
--vuln-db cves/<CVE>/<CVE>-vul
--fixed-db cves/<CVE>/<CVE>-fix
--diff cves/<CVE>/<CVE>.diff
```

## Generated query and output artifacts

Each analysis creates a timestamped `ql_agent_<CVE>_*` directory containing a `results/` directory. At minimum the reproduction retains:

- phase prompts and raw agent outputs;
- the extracted diff/AST context;
- every `*-query-iter-<n>.ql` generated query;
- `compilation_iter_<n>.txt`;
- `execution_iter_<n>.txt`;
- vulnerable/fixed BQRS, CSV, and SARIF/evaluation outputs when emitted;
- `feedback_iter_<n>.txt`;
- per-phase metrics;
- `token_usage_summary.txt`;
- `iterative_metadata.json` with duration, model usage, cost, iteration status, and file inventory.

## Query compilation and success definitions

The official implementation marks compilation successful when the compilation summary contains `COMPILATION SUCCESS`.

The final synthesis success criterion is stricter:

1. the query compiles;
2. `vuln_tp_methods > 0`; and
3. `fixed_recall_method == false`.

In other words, a successful query must hit at least one target method in the vulnerable database and must not hit the target method in the fixed database. Merely compiling, returning arbitrary rows, or returning more vulnerable rows than fixed rows is not a successful synthesis under the current official implementation.

Study-level reporting separates:

- `successful synthesis / runnable`, using the official criterion above; and
- common GT `HIT / evaluable-compatible`, only where QLCoder output can be mapped to the same frozen comparison granularity.

QLCoder synthesis success is not equated with Work1 Candidate Coverage.

## Detector ground-truth access

`detector_ground_truth_access = true (original protocol)`.

QLCoder uses the CVE patch, vulnerable/fixed pair, and fix-method evaluation inside its iterative synthesis loop. This is intentional and is the reason its results are labeled prior-assisted rather than a fair main baseline.

## Dev18 compatibility decision

All 18 case identities have CVE metadata and a vulnerable/fixed pair in the current official QLCoder `data/project_info.csv`. The frozen V011 checkout is not the benchmark buggy commit, so QLCoder can reproduce its official CVE pair but the result is `NOT_COMPARABLE` to Current Work1 at the frozen revision unless a common post-hoc mapping is established. Build, database, provider, and service failures are reported independently and never converted to `MISS`.
