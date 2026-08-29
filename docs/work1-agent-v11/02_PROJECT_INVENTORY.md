# Work1 V11：CloudStudio 项目资产 inventory

生成时间：2026-08-29（CloudStudio，`https://cloudstudio.net/a/37787922780340224/edit`）。本表由 CloudStudio 文件系统、Git remote、CodeQL `codeql-database.yml` 和实际最小查询共同生成；不以目录名推断数据库归属。

## 结论

- 当前可作为项目输入的源码根为 **33 个**：25 个规范 `V001`–`V025` 项目，加 manifest 中 8 个 P/D 项目。`/workspace/w1-e1-dev16/projects` 另有 `V010-wrong-backup`、`V011-wrong-backup` 两个非项目备份目录，因此按“所有 source 根目录存在”枚举为 **35 行 inventory**。其中 32 行至少含一个 Java 文件；V010 和两个 backup 的 `java_file_count=0`，但 V010 仍是 manifest 中的规范项目槽位。
- 仓库 frozen manifest 的历史 validation cohort 是 **18 个**：P006、P007、P010、P012；D001、D002、D003、D004；V001、V004、V005、V007、V009、V011、V021、V022、V023、V025。
- 当前实际存在的 CodeQL DB（manifest DB symlink 加 Dev16 DB 目录去重）为 **33 个**；其中用固定无依赖查询 `select 1, "inventory_probe"` 实际成功 **18 个**，失败 **15 个**。
- Dev16 是当前 CloudStudio 的 V 项目资产集合（V001–V025 加两个备份目录），不是 18-project cohort 本身；18-project cohort 只取其中 10 个成功验证的 V 项目，另外 8 个 P/D 项目来自历史 Dev-A/Dev-B 路径。

## 自动 inventory

`source_exists`、`codeql_db_exists` 来自 `Path.is_dir()`（跟随 symlink）；`java_file_count` 跟随 symlink 并跳过 `.git`、`target`、`build`、`out`、`node_modules`、`.gradle`；`codeql_db_ready=True` 仅表示实际 CodeQL query exit 0 且生成 BQRS。

| project_id | project_name | source_root | source_exists | java_file_count | codeql_db_path | codeql_db_exists | codeql_db_ready | historical_build_status |
|---|---|---|---:|---:|---|---:|---:|---|
| V001 | square/retrofit | `/workspace/w1-e1-dev16/projects/V001` | true | 220 | `/workspace/w1-e1-dev16/codeql-dbs/V001` | true | true | VALIDATED |
| V002 | dromara/hutool | `/workspace/w1-e1-dev16/projects/V002` | true | 889 | `/workspace/w1-e1-dev16/codeql-dbs/V002` | true | false | BUILD_FAILURE |
| V003 | apache/tika | `/workspace/w1-e1-dev16/projects/V003` | true | 1002 | `/workspace/w1-e1-dev16/codeql-dbs/V003` | true | false | BUILD_FAILURE |
| V004 | codehaus-plexus/plexus-archiver | `/workspace/w1-e1-dev16/projects/V004` | true | 135 | `/workspace/w1-e1-dev16/codeql-dbs/V004` | true | true | VALIDATED |
| V005 | iris-sast/zip4j | `/workspace/w1-e1-dev16/projects/V005` | true | 55 | `/workspace/w1-e1-dev16/codeql-dbs/V005` | true | true | VALIDATED |
| V006 | rhuss/jolokia | `/workspace/w1-e1-dev16/projects/V006` | true | 398 | `/workspace/w1-e1-dev16/codeql-dbs/V006` | true | false | BUILD_FAILURE |
| V007 | jstachio/jstachio | `/workspace/w1-e1-dev16/projects/V007` | true | 492 | `/workspace/w1-e1-dev16/codeql-dbs/V007` | true | true | VALIDATED |
| V008 | apache/struts | `/workspace/w1-e1-dev16/projects/V008` | true | 1984 | `/workspace/w1-e1-dev16/codeql-dbs/V008` | true | false | BUILD_FAILURE |
| V009 | apache/commons-io | `/workspace/w1-e1-dev16/projects/V009` | true | 232 | `/workspace/w1-e1-dev16/codeql-dbs/V009` | true | true | VALIDATED |
| V010 | apache/commons-text | `/workspace/w1-e1-dev16/projects/V010` | true | 0 | `/workspace/w1-e1-dev16/codeql-dbs/V010` | true | false | BUILD_FAILURE |
| V010-wrong-backup | cloud-studio-samples/clang-quickstart | `/workspace/w1-e1-dev16/projects/V010-wrong-backup` | true | 0 | — | false | false | NOT_IN_18_COHORT |
| V011 | OWASP/json-sanitizer | `/workspace/w1-e1-dev16/projects/V011` | true | 6 | `/workspace/w1-e1-dev16/codeql-dbs/V011` | true | true | VALIDATED |
| V011-wrong-backup | cloud-studio-samples/clang-quickstart | `/workspace/w1-e1-dev16/projects/V011-wrong-backup` | true | 0 | — | false | false | NOT_IN_18_COHORT |
| V012 | jenkinsci/docker-commons-plugin | `/workspace/w1-e1-dev16/projects/V012` | true | 44 | `/workspace/w1-e1-dev16/codeql-dbs/V012` | true | false | BUILD_FAILURE |
| V013 | codecentric/spring-boot-admin | `/workspace/w1-e1-dev16/projects/V013` | true | 333 | `/workspace/w1-e1-dev16/codeql-dbs/V013` | true | false | BUILD_FAILURE |
| V014 | cbeust/testng | `/workspace/w1-e1-dev16/projects/V014` | true | 2123 | `/workspace/w1-e1-dev16/codeql-dbs/V014` | true | false | BUILD_FAILURE |
| V015 | apache/jspwiki | `/workspace/w1-e1-dev16/projects/V015` | true | 522 | `/workspace/w1-e1-dev16/codeql-dbs/V015` | true | false | BUILD_FAILURE |
| V016 | kubernetes-client/java | `/workspace/w1-e1-dev16/projects/V016` | true | 1027 | `/workspace/w1-e1-dev16/codeql-dbs/V016` | true | false | BUILD_FAILURE (CodeQL tracer exit 137) |
| V017 | undertow-io/undertow | `/workspace/w1-e1-dev16/projects/V017` | true | 899 | `/workspace/w1-e1-dev16/codeql-dbs/V017` | true | false | BUILD_FAILURE |
| V018 | apache/karaf | `/workspace/w1-e1-dev16/projects/V018` | true | 1597 | `/workspace/w1-e1-dev16/codeql-dbs/V018` | true | false | BUILD_FAILURE |
| V019 | apache/james-project | `/workspace/w1-e1-dev16/projects/V019` | true | 5299 | `/workspace/w1-e1-dev16/codeql-dbs/V019` | true | false | BUILD_FAILURE |
| V020 | jlangch/venice | `/workspace/w1-e1-dev16/projects/V020` | true | 676 | `/workspace/w1-e1-dev16/codeql-dbs/V020` | true | false | BUILD_FAILURE (no root Maven POM) |
| V021 | whitesource/CureKit | `/workspace/w1-e1-dev16/projects/V021` | true | 9 | `/workspace/w1-e1-dev16/codeql-dbs/V021` | true | true | VALIDATED |
| V022 | ESAPI/esapi-java-legacy | `/workspace/w1-e1-dev16/projects/V022` | true | 351 | `/workspace/w1-e1-dev16/codeql-dbs/V022` | true | true | VALIDATED |
| V023 | vert-x3/vertx-web | `/workspace/w1-e1-dev16/projects/V023` | true | 427 | `/workspace/w1-e1-dev16/codeql-dbs/V023` | true | true | VALIDATED |
| V024 | apache/mina-sshd | `/workspace/w1-e1-dev16/projects/V024` | true | 1320 | `/workspace/w1-e1-dev16/codeql-dbs/V024` | true | false | BUILD_FAILURE |
| V025 | apache/shiro | `/workspace/w1-e1-dev16/projects/V025` | true | 728 | `/workspace/w1-e1-dev16/codeql-dbs/V025` | true | true | VALIDATED |
| P006 | manifest-only; repository name unavailable | `/workspace/msa-p0-devset/projects/P006` | true | 700 | `/workspace/msa-p0-devset/codeql-dbs/P006` | true | true | VALIDATED |
| P007 | manifest-only; repository name unavailable | `/workspace/msa-p0-devset/projects/P007` | true | 34 | `/workspace/msa-p0-devset/codeql-dbs/P007` | true | true | VALIDATED |
| P010 | manifest-only; repository name unavailable | `/workspace/msa-p0-devset/projects/P010` | true | 762 | `/workspace/msa-p0-devset/codeql-dbs/P010` | true | true | VALIDATED |
| P012 | manifest-only; repository name unavailable | `/workspace/msa-p0-devset/projects/P012` | true | 188 | `/workspace/msa-p0-devset/codeql-dbs/P012` | true | true | VALIDATED |
| D001 | Spark 2.5.1 | `/workspace/w1-e1-dev8/projects/D001` | true | 168 | `/workspace/w1-e1-dev8/codeql-dbs/D001` | true | true | VALIDATED |
| D002 | Spark 2.7.1 | `/workspace/w1-e1-dev8/projects/D002` | true | 179 | `/workspace/w1-e1-dev8/codeql-dbs/D002` | true | true | VALIDATED |
| D003 | XStream 1.4.6 | `/workspace/w1-e1-dev8/projects/D003` | true | 627 | `/workspace/w1-e1-dev8/codeql-dbs/D003` | true | true | VALIDATED |
| D004 | XStream 1.4.14-java7 | `/workspace/w1-e1-dev8/projects/D004` | true | 639 | `/workspace/w1-e1-dev8/codeql-dbs/D004` | true | true | VALIDATED |

## 历史 18-project validation cohort

来源：`experiments/frozen_configs/w1_e1_dev16_manifest.yaml`、`w1_e1_dev8_manifest.yaml`、`docs/experiments/W1_E1_DEV16_SELECTION.md` 与 `W1_E1_DEVSET_FREEZE.md`。

- Dev-A（4）：P006、P007、P010、P012。
- Dev-B（4）：D001 Spark 2.5.1、D002 Spark 2.7.1、D003 XStream 1.4.6、D004 XStream 1.4.14-java7。
- 成功验证的 Dev16 V（10）：V001 square/retrofit、V004 codehaus-plexus/plexus-archiver、V005 iris-sast/zip4j、V007 jstachio/jstachio、V009 apache/commons-io、V011 OWASP/json-sanitizer、V021 whitesource/CureKit、V022 ESAPI/esapi-java-legacy、V023 vert-x3/vertx-web、V025 apache/shiro。

V002、V003、V006、V008、V010、V012–V020、V024 是预声明候选但历史构建审计为 `BUILD_FAILURE`，不属于 18-project validation cohort；`*-wrong-backup` 也不属于 cohort。

## M2/M3 smoke 约束

- M2 的输入集合是 25 个规范 Dev16 项目（`V001`–`V025`）和 manifest 中 8 个 P/D 项目，共 33 个；不得再固定 Retrofit/Hutool。两个 `*-wrong-backup` 不属于项目集合。
- M3 的输入集合应是上表中 `codeql_db_ready=true` 的 18 个 DB；`codeql_db_exists=true` 但探针失败的 15 个 DB 不得作为 ready DB 使用。
- Cloud 证据目录：`/workspace/experiment-output/artifacts/work1-agent-v11/m1_repository_index/`，包含 `project_inventory.csv`、`inventory_summary.json`、`db_probe_results.json`、`simple_probe.ql`。

### M2 全量 smoke 结果

CloudStudio 最终结果为 **33/33 PASS**：

- 受限并行批次（4 并发、单项目 90 秒）通过 31 个；
- V016、V019 首轮分别以 exit 124 达到 90 秒上限，不属于功能失败；
- 两项目提高到 300 秒并行复跑，V016 与 V019 均 exit 0；
- 最终没有 repository indexer 功能失败。

证据：

- `/workspace/experiment-output/artifacts/work1-agent-v11/m2_smoke_results_retry2.csv`
- `/workspace/experiment-output/artifacts/work1-agent-v11/m2_smoke_retry2/`
- `/workspace/experiment-output/artifacts/work1-agent-v11/m2_smoke_results_retry3.csv`
- `/workspace/experiment-output/artifacts/work1-agent-v11/m2_smoke_retry3/`

M3 的 18 个 ready-DB 探针已完成并计入上述计数。仓库侧新增 `RepositoryTools` 与 `CodeQLTool` façade，并通过本地 fixture smoke（M2 entity/search、M3 DB_UNAVAILABLE 边界）验证。
