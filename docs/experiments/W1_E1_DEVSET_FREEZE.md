# W1-E1 eight-project development-set freeze

**Freeze date:** 2026-08-26  
**Dataset revision:** `afe0ebd0adc237abb46255f9cd479b1d71819136`  
**Detector manifest:** `experiments/frozen_configs/w1_e1_dev8_manifest.yaml`  
**Scientific method changed:** `NO`

## Purpose and boundary

The original four-project cohort remains the Dev-A engineering validation
set. Dev-B adds four independently buildable revisions, producing one frozen
eight-project manifest for the expanded W1-E1 measurement. The manifest was
frozen before running expanded P0-A discovery, E0, or W1-E1 path measurement.

Selection did not inspect endpoint counts, path counts, ground-truth files,
fix locations, or evaluator output. Structural-frontier rows remain
diagnostic-only and never add a propagation edge.

## Deterministic selection procedure

1. Keep the four already validated Dev-A revisions (`P006`, `P007`, `P010`,
   and `P012`) unchanged.
2. Enumerate the remaining CWE-Bench-Java source directories in lexical order
   and exclude revisions already represented by Dev-A.
3. Require an exact Git revision and a CodeQL database that completes a
   generic Java build capture.
4. Permit only generic build-infrastructure compatibility changes: JDK 8 for
   legacy builds, Maven's unmodified upstream settings instead of the
   CloudStudio catch-all mirror, and `mvn ... compile` when test-only or
   packaging-only dependencies prevent `test-compile`.
5. Accept the first four successful distinct revisions and retain all failed
   attempts in the CloudStudio audit logs.

No candidate, vulnerability, CWE category, or fix-file signal was used as a
selection criterion.

## Frozen cohorts

| Role | ID | Revision | Neutral source | Neutral CodeQL DB |
| --- | --- | --- | --- | --- |
| Dev-A | P006 | `f04bbec461f2c2a6f1e2cf41770f42c64aae24a4` | `/workspace/msa-p0-devset/projects/P006` | `/workspace/msa-p0-devset/codeql-dbs/P006` |
| Dev-A | P007 | `8bebe1eb2ec1ac23e34111e9d06024d7dab7fa25` | `/workspace/msa-p0-devset/projects/P007` | `/workspace/msa-p0-devset/codeql-dbs/P007` |
| Dev-A | P010 | `97e39dde7e88aae802be98de084a382886ca4255` | `/workspace/msa-p0-devset/projects/P010` | `/workspace/msa-p0-devset/codeql-dbs/P010` |
| Dev-A | P012 | `34493c66edb490396202edad66c5f8cc5717d494` | `/workspace/msa-p0-devset/projects/P012` | `/workspace/msa-p0-devset/codeql-dbs/P012` |
| Dev-B | D001 | `ce57dfb949ed183405f75dee8cf3262b45c9b3b5` | `/workspace/w1-e1-dev8/projects/D001` | `/workspace/w1-e1-dev8/codeql-dbs/D001` |
| Dev-B | D002 | `5316c0d0f057daaf556c3907c20df975f7bf8a8a` | `/workspace/w1-e1-dev8/projects/D002` | `/workspace/w1-e1-dev8/codeql-dbs/D002` |
| Dev-B | D003 | `768c6e417a75e7732fc591bee844e5e81af56a7d` | `/workspace/w1-e1-dev8/projects/D003` | `/workspace/w1-e1-dev8/codeql-dbs/D003` |
| Dev-B | D004 | `d03f6987b793fac71ab89a31d7aa633c366c5289` | `/workspace/w1-e1-dev8/projects/D004` | `/workspace/w1-e1-dev8/codeql-dbs/D004` |

The neutral Dev-B paths are symlinks created in CloudStudio. Their targets
and the complete CodeQL database-resolution audit are preserved as
`/workspace/java-vuln-research/.dev8-links-audit` and
`/workspace/java-vuln-research/.dev8-db-resolve-audit`.

## Build and exclusion audit

| Candidate | Outcome | Audited reason or database |
| --- | --- | --- |
| ActiveMQ 5.15.8 | excluded | Cloud mirror lacked a legacy test dependency; Central then reached source compilation but a packaging module required a generated `activemq.xsd` that was absent. |
| JSPWiki 2.11.0.M3 | excluded | Central resolved the legacy dependency, but the `jspwiki-portable` packaging module attempted to unpack a reactor artifact before packaging. |
| DSpace 4.4 | excluded | JDK 8 fixed the original `tools.jar` problem, but the required Restlet 2.1.1 artifacts were absent from both the Cloud mirror and Maven Central. |
| AntiSamy 1.5.6 | excluded | The checked-out source/POM reported a mismatched snapshot lineage and failed deterministic dependency resolution. |
| Spark 2.5.1 | selected as D001 | CodeQL database `/workspace/w1-e1-dev-b-dbs/DB015-spark251-jdk8-central-compile`; `codeql resolve database` succeeded. |
| Spark 2.7.1 | selected as D002 | CodeQL database `/workspace/w1-e1-dev-b-dbs/DB017-spark271-jdk8-central-compile`; `codeql resolve database` succeeded. |
| XStream 1.4.6 | selected as D003 | CodeQL database `/workspace/w1-e1-dev-b-dbs/DB016-xstream146-jdk8-central-compile`; `codeql resolve database` succeeded. |
| XStream 1.4.14-java7 | selected as D004 | CodeQL database `/workspace/w1-e1-dev-b-dbs/DB008-xstream-1.4.14-java7`; `codeql resolve database` succeeded. |

The eight resolved databases occupy approximately 156 MiB, 106 MiB,
246 MiB, 99 MiB, 6.4 MiB, 6.9 MiB, 12 MiB, and 16 MiB respectively. The
CloudStudio integrity command exited with status 0 for all eight entries.

## Reproducibility constraints

- Do not alter the frozen manifest after expanded discovery starts.
- Write every rerun to a new immutable output directory.
- Keep detector input limited to project ID, revision, neutral source path,
  and CodeQL DB path.
- Run the independent evaluator only after detector output is persisted.
- Record all partial or failed projects; never replace them based on measured
  endpoints, paths, or coverage.
- `scientific_method_changed=NO`.
