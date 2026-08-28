# Baseline Reproduction Dev18 Manifest

## Freeze statement

- `projects_total = 18`
- Source cohort: `experiments/frozen_configs/w1_e1_dev16_manifest.yaml`
- Enriched machine-readable manifest: `experiments/frozen_configs/baseline_repro_dev18_manifest.csv`
- Initial compatibility table: `experiments/baseline_reproduction/baseline_repro_compatibility.csv`
- Selection policy: no project was added, removed, or replaced.
- Detector/result signals used for selection: none.

This study uses the same 18 frozen Work1 project checkouts. The enriched manifest adds repository and benchmark identity needed by IRIS and QLCoder; it does not alter the original frozen YAML.

## Project identities

| ID | Repository | Observed cloud revision | Benchmark identity | CWE | Revision alignment | Frozen CodeQL DB |
|---|---|---|---|---|---|---|
| P006 | x-stream/xstream | `f04bbec` | CVE-2021-21345 | CWE-078 | MATCH | `/workspace/msa-p0-devset/codeql-dbs/P006` |
| P007 | nahsra/antisamy | `8bebe1e` | CVE-2016-10006 | CWE-079 | MATCH | `/workspace/msa-p0-devset/codeql-dbs/P007` |
| P010 | spring-attic/spring-security-oauth | `97e39dd` | CVE-2018-1260 | CWE-094 | MATCH | `/workspace/msa-p0-devset/codeql-dbs/P010` |
| P012 | jmrozanec/cron-utils | `34493c6` | CVE-2021-41269 | CWE-094 | MATCH | `/workspace/msa-p0-devset/codeql-dbs/P012` |
| D001 | perwendel/spark | `ce57dfb` | CVE-2016-9177 | CWE-022 | MATCH | `/workspace/w1-e1-dev8/codeql-dbs/D001` |
| D002 | perwendel/spark | `5316c0d` | CVE-2018-9159 | CWE-022 | MATCH | `/workspace/w1-e1-dev8/codeql-dbs/D002` |
| D003 | x-stream/xstream | `768c6e4` | CVE-2013-7285 | CWE-078 | MATCH | `/workspace/w1-e1-dev8/codeql-dbs/D003` |
| D004 | x-stream/xstream | `d03f698` | CVE-2020-26217 | CWE-078 | MATCH | `/workspace/w1-e1-dev8/codeql-dbs/D004` |
| V001 | square/retrofit | `7158698` | CVE-2018-1000850 | CWE-022 | MATCH | `/workspace/w1-e1-dev16/codeql-dbs/V001` |
| V004 | codehaus-plexus/plexus-archiver | `b9f9a42` | CVE-2018-1002200 | CWE-022 | MATCH | `/workspace/w1-e1-dev16/codeql-dbs/V004` |
| V005 | iris-sast/zip4j | `d87ffa2` | CVE-2018-1002202 | CWE-022 | MATCH | `/workspace/w1-e1-dev16/codeql-dbs/V005` |
| V007 | jstachio/jstachio | `9ce2000` | CVE-2023-33962 | CWE-079 | MATCH | `/workspace/w1-e1-dev16/codeql-dbs/V007` |
| V021 | whitesource/CureKit | `7b275a6` | CVE-2022-23082 | CWE-022 | MANIFEST_TYPO; observed matches benchmark | `/workspace/w1-e1-dev16/codeql-dbs/V021` |
| V022 | ESAPI/esapi-java-legacy | `2e8694c` | CVE-2022-23457 | CWE-022 | MANIFEST_TYPO; observed matches benchmark | `/workspace/w1-e1-dev16/codeql-dbs/V022` |
| V023 | vert-x3/vertx-web | `2146b72` | CVE-2019-17640 | CWE-022 | MATCH | `/workspace/w1-e1-dev16/codeql-dbs/V023` |
| V025 | apache/shiro | `adb56c8` | CVE-2023-34478 | CWE-022 | MANIFEST_TYPO; observed matches benchmark | `/workspace/w1-e1-dev16/codeql-dbs/V025` |
| V009 | apache/commons-io | `2ae025f` | CVE-2021-29425 | CWE-022 | MATCH | `/workspace/w1-e1-dev16/codeql-dbs/V009` |
| V011 | OWASP/json-sanitizer | `fc612ab` | CVE-2020-13973 | CWE-079 | FROZEN_REVISION_DIFFERS_FROM_BENCHMARK | `/workspace/w1-e1-dev16/codeql-dbs/V011` |

## Revision audit

Cloud-side `git remote get-url origin` and `git rev-parse HEAD` were recorded for all 18 checkouts before baseline integration.

The original frozen YAML contains transcription errors for V021, V022, and V025. The actual cloud checkouts match the official benchmark buggy commits. This study does not edit the frozen YAML; it records both the original text and observed Git truth in the enriched CSV.

V011 is a real revision mismatch: the frozen checkout is `fc612ab374de73d03864d56fb87b6a103b234489`, while the QLCoder/CWE-Bench vulnerable commit is `bb41f80ad575cb90ea6535976d7c17accb4b4c87`. IRIS may still scan the frozen V011 source with its target-CWE prior, but QLCoder's official CVE pair is not a same-revision comparison to Work1 and must be reported `NOT_COMPARABLE` at that level.

## CodeQL database identity

The paths in the final column are the frozen CodeQL 2.26.3 databases used by Native CodeQL and Current Work1. They remain immutable.

- IRIS v1 requires its patched CodeQL 2.15.3 and therefore builds separate method-owned databases from the same observed source revisions.
- QLCoder requires CodeQL 2.22.2 vulnerable/fixed pairs and therefore builds separate CVE-conditioned databases.

Method-owned databases do not replace or mutate the frozen Work1 database paths.

## Prior-information comparison

| Method | Prior knowledge |
|---|---|
| Native CodeQL | none |
| Current Work1 | none: NO CVE, true CWE, patch, vulnerable file/method/location |
| IRIS | original protocol: project plus target CWE; LLM-generated taint specification |
| QLCoder | original CVE/patch-conditioned protocol, including vulnerable/fixed pair and fix-method feedback |

