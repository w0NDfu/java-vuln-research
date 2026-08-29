# Work1 V11 M3：Agent-callable CodeQL analysis tools

## 1. M3 research role

M3 把已经验证可查询的 Java CodeQL 数据库封装为确定性、可审计、可限界的 agent 工具层。它接收 M1/M2 的 `ProgramEntity`，在严格实体映射后返回实体事实、调用边、局部数据流、数据流邻居与 CFG 邻居。M3 不提出漏洞假设，不执行安全语义搜索，也不启动 M4。

## 2. Why CodeQL is a tool, not the search boundary

CodeQL 在本阶段是事实提供者，不是漏洞搜索边界。模型只能调用固定 allow-list 工具，不能提交任意 QL；查询只回答“这个实体对应什么 CodeQL 元素”“相邻的调用/流/控制边是什么”。候选漏洞、sink/source 语义和 exploitability 判断仍属于后续阶段。

## 3. Entity mapping design

映射入口为 `ProgramEntity -> CodeQL entity`。候选由 repository-relative path、source range overlap 与 kind compatibility 共同约束，再以 qualified name、signature、declaring type、enclosing callable 提高确定性。映射器从不以 `simple_name` 单独匹配，也不会从多个候选中任取第一个。

映射结果固定为：

- `MAPPED_UNIQUE`：唯一候选，包含 `codeql_identity`、confidence、mapping evidence 与 provenance。
- `MAPPED_AMBIGUOUS`：存在多个合格候选，不替 agent 猜测。
- `NOT_MAPPED`：查询成功，但没有满足严格上下文的候选。
- `UNSUPPORTED_KIND`：该 `ProgramEntity.kind` 没有已实现映射语义。

同一 `(database, entity_id)` 的映射在一次工具会话中缓存；后续工具仍复制完整映射 provenance，并标注 `mapping_cache_hit=true`。唯一映射除 identity、kind、位置和签名外，还保留参数位置、返回信息、声明/接收者类型、annotation 以及 override/interface 事实，供后续工具复用而不再次按名称猜测。Cloud smoke 将一个项目的最多 11 个确定性样本合并为一次有界 `EntityFacts` 查询，再按严格 path/range/kind/context 规则分别映射；每个逻辑结果记录 batch parent call、batch size/index、完整 batch wall-clock 与摊分 latency。这只减少重复编译，不改变映射标准或逻辑调用数。

## 4. CodeQL tool list

| 工具 | 固定查询 | 返回事实 | 默认边界 |
|---|---|---|---|
| `codeql_entity_facts` | `EntityFacts.ql` | CodeQL identity、kind、位置、qualified identity、signature、enclosing context、参数/返回/类型/annotation/override-interface 事实 | 100 rows |
| `codeql_callers` | `CallGraph.ql` | 以精确 mapped CodeQL identity 为锚点的直接 caller 边 | 30 edges，depth 1 |
| `codeql_callees` | `CallGraph.ql` | 以精确 mapped CodeQL identity 为锚点的直接 callee 边 | 30 edges，depth 1 |
| `codeql_local_flow` | `LocalFlow.ql` | 一步 local flow，可选 target entity 与 scope entity | 30 edges，depth 1 |
| `codeql_dataflow_neighbors` | `DataFlowNeighbors.ql` | `FORWARD`/`BACKWARD`/`BOTH` 一步邻居 | 30 nodes、50 edges、depth 1 |
| `codeql_cfg_neighbors` | `CfgNeighbors.ql` | predecessor/successor | 30 nodes、50 edges、depth 1 |

## 5. Shared executor

`CodeQLExecutor` 是唯一进程边界。它检查 CodeQL binary、DB path、`codeql-database.yml` 与固定 query path；模板值只支持经过 QL literal escaping 的 path/line，不接受模型生成的 QL。每次调用生成独立 artifact 目录，记录 CodeQL version、DB path、query/template hash、参数、命令、exit code、bounded stdout/stderr、BQRS/CSV 路径、result hash 与 wall-clock latency。

模板化查询会把最近的 `qlpack.yml` 和 `codeql-pack.lock.yml` 复制到调用 artifact，保留 Java library pack 的精确解析上下文。此行为由真实 V001 probe 验证：修复前为 `could not resolve module java`，修复后同一实体达到 `MAPPED_UNIQUE/OK`。

失败分类包括 `CODEQL_UNAVAILABLE`、`DB_NOT_FOUND`、`DB_NOT_READY`、`QUERY_NOT_FOUND`、`QUERY_COMPILE_ERROR`、`QUERY_EXECUTION_ERROR`、`TIMEOUT`、`OOM`、`BQRS_DECODE_ERROR` 与 `OUTPUT_PARSE_ERROR`。

## 6. Evidence types

M2 lexical evidence 与 M3 CodeQL evidence 不可互换：

- M2：`LEXICAL_CALL`、`CALL_CANDIDATE`、`EXTENDS_TEXT`、`IMPLEMENTS_TEXT`、`OVERRIDE_CANDIDATE`。
- M3：`CODEQL_ENTITY_FACT`、`CODEQL_CALL`、`CODEQL_LOCAL_FLOW`、`CODEQL_DATAFLOW`、`CODEQL_CFG`、`CODEQL_RETURN`、`CODEQL_PARAMETER`。

每个结果使用统一 schema：`tool_call_id`、`tool_name`、`status`、`queried_entity_ids`、`mapped_codeql_entities`、`nodes`、`edges`、`truncated`、`warnings`、`failure`、`provenance`、`metrics`。

## 7. Uncertainty semantics

`OK` 表示工具成功且有事实；`EMPTY` 表示查询和解码成功但没有边/事实，不等价于失败；`ENTITY_NOT_MAPPED` 与 `UNSUPPORTED` 保留映射不确定性；`ERROR` 必须携带结构化 failure。所有边先按方向过滤，再同时应用 node、edge 与 depth 上限；达到上限时 `truncated=true`，不静默丢弃边界信息。M3 只实现 depth 1：调用方请求 `max_depth>1` 会得到明确参数错误，不会返回伪装成多跳的一步结果。

## 8. Local tests

本地覆盖 strict mapping、ambiguous/not-mapped/unsupported、实体 enrichment、精确 CodeQL identity 模板、可选 local-flow target/scope、depth 拒绝语义、模板 escaping、qlpack context、query/BQRS 执行与解析、timeout/OOM/compile classification、bounded output、call direction、node bounds、mapping cache、11-entity batch、配置化 query threads、smoke deterministic sampling、artifact binding 与 percentile。当前完整测试结果：`107 passed, 1 skipped`。

## 9. 18 DB CloudStudio test

CloudStudio 输入严格来自 `project_inventory.csv` 的 `codeql_db_ready=true` 集合，并由 runner 校验必须与 frozen cohort 完全相等：P006、P007、P010、P012、D001、D002、D003、D004、V001、V004、V005、V007、V009、V011、V021、V022、V023、V025。

每项目确定性采样计划为 TYPE×2、METHOD×3、CONSTRUCTOR×1、FIELD×2、CALL×3；缺少某 kind 时显式记录 `sample_missing`。随后执行 entity facts、3 个实体双向 call graph、local flow×3、dataflow forward×3/backward×3、CFG×3。最终 contract-complete 全量 runner 从首个项目起使用 2 workers、每个 query 1 thread、单查询 240 秒，并按项目写 checkpoint 支持恢复；checkpoint 只有 schema version、当前 V11 Git SHA、timeout 与 query-thread 配置同时匹配时才复用。18 个项目均在同一实现 SHA 下实际执行，没有重建 DB。

Cloud preflight 先在 P006 验证 enrichment、精确 CodeQL callable identity 和可选 local-flow target/scope，三类查询均成功编译执行。最终全量运行中 153 个唯一映射实体全部具有 `type_information`；其中 40 个具有参数位置、60 个具有返回信息、14 个具有 annotation facts、36 个具有 override/interface facts。空字段表示该实体种类没有对应事实，不用占位值伪造信息。

历史 pre-enrichment 运行曾在 4-worker 资源竞争下出现 5 个 OOM；该证据保存在 `pre_enrichment_717cd5f/`，不混入当前 required artifact。最终实现从头以 2 workers 重跑全部 18 个 ready DB，wall-clock 为 3882.606458 秒，没有 OOM 或 TIMEOUT，也不需要失败项目定向重试。D003 的 12 个 `QUERY_COMPILE_ERROR` 在新实现上稳定复现。

每个实际执行的查询绑定 V11 Git SHA、CodeQL version、DB path 与 materialized query hash；项目汇总同时绑定 frozen manifest 中的 source revision。源码副本没有 `.git` 时不伪造现场 HEAD，而是明确记录 `project_source_head_origin=frozen_manifest`。90 个下游调用因映射失败在 CodeQL 执行前短路，故没有伪造 query hash；其余 432 个调用均有实际 query hash 与 source revision。artifact 运行 SHA 为 `5c62e35075b13935885fda40ace55f6a36e4abd3`，CodeQL 为 `2.26.3`，并包含完整 EntityFacts enrichment、精确 call-graph identity、local-flow target/scope 与 depth 拒绝语义。

Cloud 命令在隔离 worktree `/workspace/work1-agent-v11-cloud` 上执行，不切换或清理 Route B 工作区。最终 artifact 目录：`/workspace/experiment-output/artifacts/work1-agent-v11/m3_codeql_tools/`。

五个 required artifact 均已生成并通过行数/JSON 审计：`project_summary.csv` 19 行（header + 18 projects）、`tool_calls.jsonl` 522 行、`entity_mapping.jsonl` 198 行、`failures.jsonl` 147 行、`aggregate.json` 1 个完整 JSON object。cohort 从 artifact 反查仍精确等于上述 18 个 project ID。

## 10. Per-project results

每项目请求 11 个实体样本和 29 个逻辑工具调用。`U/A/N` 分别是 `MAPPED_UNIQUE/MAPPED_AMBIGUOUS/NOT_MAPPED`；`ENM` 是工具级 `ENTITY_NOT_MAPPED`，包括 ambiguity/not-mapped 导致的下游短路。成功率为 `(OK + EMPTY) / 29`，因此 `EMPTY` 不按失败计。

| project | U | A | N | OK | EMPTY | ENM | ERROR | success rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P006 | 11 | 0 | 0 | 23 | 6 | 0 | 0 | 1.000000 |
| P007 | 9 | 0 | 2 | 15 | 6 | 8 | 0 | 0.724138 |
| P010 | 3 | 8 | 0 | 10 | 2 | 17 | 0 | 0.413793 |
| P012 | 11 | 0 | 0 | 26 | 3 | 0 | 0 | 1.000000 |
| D001 | 10 | 0 | 1 | 17 | 8 | 4 | 0 | 0.862069 |
| D002 | 11 | 0 | 0 | 23 | 6 | 0 | 0 | 1.000000 |
| D003 | 11 | 0 | 0 | 14 | 3 | 0 | 12 | 0.586207 |
| D004 | 0 | 0 | 11 | 0 | 0 | 29 | 0 | 0.000000 |
| V001 | 8 | 1 | 2 | 16 | 4 | 9 | 0 | 0.689655 |
| V004 | 10 | 0 | 1 | 17 | 8 | 4 | 0 | 0.862069 |
| V005 | 10 | 0 | 1 | 21 | 4 | 4 | 0 | 0.862069 |
| V007 | 9 | 0 | 2 | 12 | 9 | 8 | 0 | 0.724138 |
| V009 | 9 | 0 | 2 | 18 | 3 | 8 | 0 | 0.724138 |
| V011 | 10 | 0 | 1 | 22 | 3 | 4 | 0 | 0.862069 |
| V021 | 10 | 0 | 1 | 25 | 0 | 4 | 0 | 0.862069 |
| V022 | 1 | 0 | 10 | 1 | 0 | 28 | 0 | 0.034483 |
| V023 | 10 | 1 | 0 | 20 | 5 | 4 | 0 | 0.862069 |
| V025 | 10 | 0 | 1 | 21 | 4 | 4 | 0 | 0.862069 |

18 项目全部产生项目摘要；没有固定 Retrofit/Hutool，也没有使用 15 个 probe-fail DB。精确延迟、nodes/edges、truncated calls 和每次调用 provenance 以 `project_summary.csv`、`tool_calls.jsonl` 为准。

## 11. Per-tool results

最终共 522 个逻辑调用：301 `OK`、74 `EMPTY`、135 `ENTITY_NOT_MAPPED`、12 `ERROR`，总工具成功率为 0.718391。返回 1208 nodes、1515 edges；总 truncation rate 为 0.040230。全局 latency 为 avg 14.600897 秒、p50 5.445301 秒、p95 63.202608 秒、max 78.750911 秒。

| tool | calls | OK | EMPTY | ENM | ERROR | success | avg s | p50 s | p95 s | max s | nodes | edges | trunc. |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `codeql_callees` | 54 | 28 | 17 | 9 | 0 | 0.833333 | 10.823985 | 12.392351 | 15.237333 | 15.521912 | 133 | 146 | 0.055556 |
| `codeql_callers` | 54 | 28 | 17 | 9 | 0 | 0.833333 | 39.160167 | 46.888506 | 55.692888 | 56.398623 | 93 | 137 | 0.055556 |
| `codeql_cfg_neighbors` | 54 | 36 | 6 | 9 | 3 | 0.777778 | 11.661455 | 13.316253 | 17.809090 | 19.493560 | 653 | 1144 | 0.277778 |
| `codeql_dataflow_neighbors` | 108 | 40 | 20 | 42 | 6 | 0.555556 | 11.622362 | 16.666148 | 22.595638 | 25.756262 | 110 | 62 | 0.000000 |
| `codeql_entity_facts` | 198 | 153 | 0 | 45 | 0 | 0.772727 | 5.152247 | 5.027925 | 5.853443 | 5.853443 | 175 | 0 | 0.000000 |
| `codeql_local_flow` | 54 | 16 | 14 | 21 | 3 | 0.555556 | 37.360099 | 42.182055 | 75.903951 | 78.750911 | 44 | 26 | 0.000000 |

## 12. Mapping ambiguity analysis

198 个映射结果中：`MAPPED_UNIQUE=153`（77.2727%）、`MAPPED_AMBIGUOUS=10`（5.0505%）、`NOT_MAPPED=35`（17.6768%）、`UNSUPPORTED_KIND=0`。10 个 ambiguity 集中于 P010（8）、V001（1）、V023（1）；35 个 not-mapped 主要由 D004（11）与 V022（10）贡献，其余分散于 P007、D001、V001、V004、V005、V007、V009、V011、V021、V025。

45 个非唯一 entity-facts 结果进一步导致 90 个依赖工具调用在查询前确定性短路，最终形成 135 个工具级 `ENTITY_NOT_MAPPED`。这些调用保留 mapping evidence 和 batch-parent provenance，不被改写为 `EMPTY` 或 `ERROR`。

## 13. Timeout/OOM/error analysis

最终 artifact 中 `TIMEOUT=0`、`OOM=0`、`QUERY_EXECUTION_ERROR=0`、decode/parse/driver error 均为 0；唯一实际错误是 D003 的 12 个 `QUERY_COMPILE_ERROR`（exit 100）：CFG 3、dataflow 6、local-flow 3。stderr 的稳定共同栈位于 CodeQL `ExtensionalLoader`/`TuplePool` cache/load 路径；同一固定查询在其余 DB 可运行，因此证据支持“D003/CodeQL 运行时 compile-stage 兼容性问题”，而不是把它误报为无边、映射失败或通用 QL 语法错误。

历史 4-worker 结果中的 5 个 OOM 分布在 D001（2）、V007（1）、V009（1）、V011（1），证明高并发不适合该 4-core/8-GB CloudStudio 环境；它们不属于当前 artifact。最终 2-worker 全量重跑没有 OOM/TIMEOUT。D003 的 12 个错误仍完全复现，故停止重复重试。`failures.jsonl` 共 147 行：135 个显式 mapping failure/short-circuit，加 12 个结构化 CodeQL error；没有重建或使用 15 个非 ready DB。

## 14. Known CodeQL limitations

- 当前 call graph、flow 与 CFG 查询只提供一步邻居；API 对 `max_depth>1` 明确拒绝，本阶段 smoke 使用 depth 1。
- Java CodeQL database 只反映建库时成功提取的程序；缺失依赖、生成代码或未被构建覆盖的模块不会由工具补全。
- source range 可能对应多个 AST/flow 节点，因此 mapping 必须保留 ambiguity，而不能用名称猜测。
- `EMPTY` 只说明当前实体和固定查询没有事实，不能证明没有更长路径或安全问题。
- ready cohort 固定为 18；其余 15 个仅“目录存在”但实际 probe 失败的 DB 未被使用、未被重建。

## 15. M4 handoff

M4 只能消费 M3 的显式 evidence kind、mapping status、provenance、limits/truncation 与 failure semantics。M3 完成门槛是 18 个 ready DB 全部被执行、五个指定 artifact 完整生成、统计与本报告一致。当前门槛已达到，建议 **`PROCEED_M4`**；但 M4 必须把 D003 的 12 个结构化错误视为缺失证据，把 D004/V022 的低映射覆盖视为 uncertainty，不能解释成 negative evidence。本阶段在给出建议后停止，不启动 Security Proposal、Evidence Gate、Hybrid Evidence Graph、Agent、Prompt 或漏洞实验。
