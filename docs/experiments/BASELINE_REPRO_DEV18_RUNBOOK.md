# Baseline Reproduction Dev18 Cloud Runbook

All commands in this runbook are executed in CloudStudio. Local Codex work is limited to integration, review, commits, and pushes. The frozen Work1 source checkouts and CodeQL 2.26.3 databases are read-only inputs.

## Pinned identities

| Component | Pin |
|---|---|
| Harness branch | `exp/baseline-repro-iris-qlcoder-dev18` |
| IRIS | `67140e84e6a01da2b44803a6208be2ea7bd4bd51` (`v1`) |
| IRIS CWE-Bench-Java | `698fb7248ae30cb7f7782d59c841f05ad70ea9cc` |
| IRIS CodeQL | patched 2.15.3, release `codeql-0.8.3-patched` |
| IRIS model | upstream `gpt-4`, mapped to `gpt-4-0125-preview` |
| QLCoder | `6095f90f3b4906f36e2e2fe7d1d0bc987750ca2b` |
| CodeQL LSP MCP | `a33ea82bba156dc8352a0ecd85baff34cbb950ed` |
| QLCoder CodeQL | 2.22.2 |
| QLCoder agent/model | Claude Code 1.0.120 / `claude-sonnet-4-20250514` |

## 1. Isolated checkout and preflight

Do not run from the existing `/workspace/java-vuln-research` checkout because it may contain another experiment's state.

```bash
cd /workspace
git clone git@github.com:david4cheng/java-vuln-research.git baseline-repro-dev18
cd /workspace/baseline-repro-dev18
git checkout exp/baseline-repro-iris-qlcoder-dev18
git status --short --branch
git rev-parse HEAD
bash scripts/baseline_repro/preflight.sh
```

The preflight writes immutable evidence under `/workspace/experiment-output/artifacts/baseline_reproduction/preflight-*`. It records only whether provider credentials are present; it never prints their values.

Expected credentials must be exported in the CloudStudio shell by the operator or secret manager:

```bash
test -n "${OPENAI_API_KEY:-}" && echo OPENAI_API_KEY_SET || echo OPENAI_API_KEY_UNSET
test -n "${ANTHROPIC_API_KEY:-}${CLAUDE_CODE_OAUTH_TOKEN:-}" && echo CLAUDE_CREDENTIAL_SET || echo CLAUDE_CREDENTIAL_UNSET
```

No substitute model/provider is allowed without a separately documented protocol deviation.

## 2. IRIS setup and smoke

```bash
cd /workspace/baseline-repro-dev18
bash scripts/baseline_repro/setup_iris.sh
bash scripts/baseline_repro/run_iris_one.sh D002 IRIS-SMOKE-D002-001
```

IRIS uses the official pipeline. Before invocation, the harness verifies the frozen revision, builds a separate patched-2.15.3 database, stages a header-only detector `fix_info.csv`, and preseeds `readme_head.txt` from the frozen checkout. It invokes `--skip-evaluation`; module and fixed-method filters remain disabled. The original `fix_info.csv` is restored by a trap even when the upstream command fails.

The setup script downloads JDK 8u202 and Maven 3.5.0 for D002 directly into IRIS's method-owned `data/cwe-bench-java/java-env` layout. Oracle's 8u202 archive requires an interactive account, so the automated harness uses AdoptOpenJDK 8u202-b08 and records this vendor deviation plus both archive hashes. It does not change IRIS detection logic. Toolchains needed by later Dev18 cases are downloaded only after both smoke gates pass.

## 3. QLCoder setup and smoke

```bash
cd /workspace/baseline-repro-dev18
bash scripts/baseline_repro/setup_qlcoder.sh
bash scripts/baseline_repro/run_qlcoder_one.sh D002 QLCODER-SMOKE-D002-001
```

The setup retains the pinned official source commit, downloads the official CodeQL Action bundle 2.22.2, builds the pinned LSP MCP server, populates the official CodeQL/CWE RAG collections, and creates a recorded environment overlay that pins Claude Code 1.0.120. Because the LSP commit has no package lock and its legacy TypeScript module resolver fails against dependencies resolved on 2026-08-28, the harness records and applies the build-only compiler overlay `--moduleResolution bundler`. The official CVE retrieval, vulnerable/fixed database build, diff, Chroma service, and iterative `ql_agent.py` path are otherwise unchanged. QLCoder intentionally has `detector_ground_truth_access=true` under its original patch-conditioned protocol.

## 4. Smoke gate

Do not launch Dev18 until both smoke manifests say `RUNNABLE` and contain the expected frozen upstream artifacts:

```bash
find /workspace/experiment-output/artifacts/baseline_reproduction/raw \
  -path '*/SMOKE-*/*/run_manifest.json' -print -exec sed -n '1,80p' {} \;
```

Missing credentials are `REPRO_BLOCKED`. Build/database/upstream failures are `NOT_RUNNABLE`, never `MISS`. A successful process is still not a GT `HIT` until outputs are frozen and the independent evaluator runs.

## 5. Dev18 execution after the smoke gate

```bash
cd /workspace/baseline-repro-dev18
while IFS= read -r project_id; do
  bash scripts/baseline_repro/run_iris_one.sh "${project_id}" "IRIS-DEV18-001"
done < <(python3 scripts/baseline_repro/manifest.py list)

while IFS= read -r project_id; do
  bash scripts/baseline_repro/run_qlcoder_one.sh "${project_id}" "QLCODER-DEV18-001"
done < <(python3 scripts/baseline_repro/manifest.py list)
```

V011 may execute in QLCoder's official CVE pair, but remains `NOT_COMPARABLE` to the frozen Work1 revision unless a common post-hoc mapping is proven. Do not silently remove it from the 18 attempted projects.

## 6. Artifact freeze and evaluation boundary

Raw run roots are:

```text
/workspace/experiment-output/artifacts/baseline_reproduction/raw/iris/<run_id>/<project_id>/
/workspace/experiment-output/artifacts/baseline_reproduction/raw/qlcoder/<run_id>/<project_id>/
```

Each `run_manifest.json` inventories frozen upstream files with sizes and SHA-256 hashes. Only after all detector outputs are frozen may an independent evaluator read benchmark GT. Evaluation must report execution scope (18 attempted projects) separately from the common GT-evaluable denominator.

## Stop conditions

- Do not modify Route A, Route B, Route C, SecurityEffect, ExternalInput, propagation semantics, or frozen Work1 artifacts.
- Do not start P0-C.
- Do not broaden beyond the same 18 cases.
- Do not map setup failure, unavailable credentials, or output incompatibility to `MISS`.
- If an official dependency blocker persists, record `REPRO_BLOCKED` and stop that method instead of patching its semantics.
