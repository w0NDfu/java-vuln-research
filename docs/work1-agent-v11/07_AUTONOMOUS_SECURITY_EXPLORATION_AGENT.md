# Work1 V11 M7：Autonomous Security Exploration Agent

## Status

当前完成 `M7-0` 与 `M7-1`：Git/worktree 隔离、M1-M5 API inventory、Agent action/state/trace/budget 稳定契约及其回归。尚未接入真实 LLM、工具执行、proposal Gate 或 graph，也尚未运行 controlled Agent smoke 或真实 autonomous kill test。

## M7-0 Git and worktree isolation

M7 从已验证的 M6 分支 HEAD `d7cd7231429785b714e5ade69d578efec5207aef` 建立；其中 M6 实验代码基线为 `ec4e64ba0b9c3eb200705ae8d7239246c77bd5d4`。新分支为：

`work1/agent-active-security-v11-m7`

原本地 checkout 与 CloudStudio checkout 均为 dirty，因此没有 switch、reset、clean、force checkout 或覆盖任何已有修改。隔离位置：

- local implementation worktree：`C:/Users/戴超杰/AppData/Local/Temp/java-vuln-research-m7`
- CloudStudio authoritative test/experiment worktree：`/workspace/java-vuln-research-m7`

CloudStudio worktree 创建返回码为 0，创建后 `git status --short --branch` 仅显示 `## work1/agent-active-security-v11-m7`。云端原 checkout 的未跟踪 reports/临时文件保持不变。

## M1-M5 API inventory

### M1 ProgramEntity and RepositoryIndex

- `ProgramEntity` schema version 1，稳定 entity ID 基于 kind、repository-relative path、range、symbol identity 与 discriminator；拒绝绝对路径和 `..` traversal。
- `ProgramEntityKind` 已覆盖 FILE、PACKAGE、TYPE、METHOD、CONSTRUCTOR、PARAMETER、FIELD、CALL、ANNOTATION、RETURN、LOCAL、CALL_ARGUMENT、FIELD_READ、FIELD_WRITE。
- `RepositoryIndex` 保存 entities、diagnostics、Java 文件数、抽取耗时，并提供稳定排序、JSONL/summary 写出。
- `build_repository_index()` 使用 `JAVA_CONSERVATIVE_LEXICAL_V1`，排除 `.git`、build、target 等目录；不做安全 Source/Sink 分类。

### M2 repository primitives

已提交基线提供：

- `search_code(index, query, file_glob, max_hits, case_sensitive)`：默认 30、硬上限 100，query 上限 512，snippet 上限 500。
- `search_symbols(index, query, kind, max_hits, case_sensitive)`：同样有界，返回 entity/location/snippet/provenance。
- `read_file_range(root, path, start, end, max_lines, max_bytes)`：默认 250 行/64 KiB，硬上限 1000 行/1 MiB，路径 confinement 与 UTF-8 检查。
- `inspect_entity(root, entity, context_lines, ...)`：context 上限 100。

重要缺口：Git 基线中没有已提交的 `repository/tools.py` façade。原 dirty checkout 的未跟踪同名文件没有纳入 M7 基线，且其中 callers/callees/implementations/overrides/fields/annotations 只返回 `M1_RELATION_UNAVAILABLE`。M7 不复制该未跟踪用户文件；M7-4 将基于已提交 neutral primitives 建立通用、有界、可追踪的 runtime adapter，并对 unavailable relation 保留结构化不确定性。

### M3 CodeQL tools

`CodeQLAnalysisTools` 是固定 allow-list，不接受模型生成 QL：

- `codeql_entity_facts`
- `codeql_callers`
- `codeql_callees`
- `codeql_local_flow`
- `codeql_dataflow_neighbors`
- `codeql_cfg_neighbors`

工具先执行 strict ProgramEntity mapping；结果状态为 OK、EMPTY、ERROR、UNSUPPORTED 或 ENTITY_NOT_MAPPED。ERROR 保留 CODEQL_UNAVAILABLE、DB_NOT_FOUND、DB_NOT_READY、compile/execution/cache/timeout/OOM/decode/parse 等明确 failure reason。所有 graph/flow 查询保持 depth 1、node/edge hard ceiling，EMPTY/unavailable 不解释成关系不存在。

### M4 proposal and Evidence Gate

`SecurityProposal` schema version 1 已正式支持 EXTERNAL_INPUT、SECURITY_EFFECT、WRAPPER_FLOW、LIBRARY_FLOW、FIELD_STATE、FRAMEWORK_RELATION、CALLBACK_RELATION。proposal ID 对 type、subject/source/target、scope、semantic category 做稳定散列。

`EvidenceRef` 保留 source kind、entity IDs、source range、tool/artifact identity、hash、strength 与 provenance。`EvidenceGate.evaluate()` 返回 ADMISSIBLE、NEEDS_MORE_EVIDENCE、REJECTED、DUPLICATE、ALREADY_SUPPORTED 或 UNSUPPORTED；Gate 独立检查实体、role、scope、location、EvidenceRef resolution/locality 与 duplicate/native support。

M7 PROPOSE action 必须直接解析为这一正式 `SecurityProposal`，不会创建第二套 proposal IR。

### M5 graph and bounded path builder

`HybridEvidenceGraphBuilder` 接收 project-local entities、evidence catalog、M4 proposals/gate results、M3 tool artifact index 与 manifest。它只允许：

- CodeQL relation → `DETERMINISTIC_FACT`；
- repository relation → `STRUCTURAL_EVIDENCE`；
- ADMISSIBLE M4 proposal relation → `ADMISSIBLE_SEMANTIC_PROPOSAL`。

所有 edge 必须绑定可解析 EvidenceRef；CodeQL edge 还必须绑定 status=OK 的真实 tool call；proposal edge 必须保留精确 proposal EvidenceRef 集。`BoundedPathBuilder` 默认 depth 12、paths 20、expanded nodes 2000，硬上限分别为 20、20、10000，并原样保留 CandidatePath schema-v2 native paths。

## Reuse and required adapter work

| layer | directly reusable | M7 adapter/general work required |
|---|---|---|
| M1 | ProgramEntity、RepositoryIndex、stable serialization | project summary 与 runtime index loading |
| M2 | search/read/inspect primitives 与 hard ceilings | allow-listed action dispatcher、tool-call IDs、EvidenceRef catalog、通用 relation/unavailable adapter |
| M3 | fixed CodeQL allow-list、mapping、failure taxonomy | action argument validation、runtime DB/status binding、result-to-evidence conversion |
| M4 | formal proposal model、EvidenceRef、Gate | Agent provenance/round/tool-call binding、Gate feedback serialization |
| M5 | graph builder、native preservation、bounded path search | incremental rebuild、before/after path feedback、stop/progress accounting |

不得复用到 runtime 的内容包括 M6 diagnostic proposal、diagnostic analysis、mapped callable、root-cause label、proposal sequence、benchmark evaluator 输入及任何 CVE/CWE/patch/location 数据。

## M7-0 regression evidence

- local clean worktree：`148 passed, 3 skipped`，返回码 0。
- CloudStudio isolated worktree：`150 passed, 1 skipped, 1 warning`，返回码 0。

测试数量差异来自两端可用环境/可选集成依赖；两端均执行各自完整 `python -m pytest -q`，没有缩小到 M7-only tests。

## M7-0 acceptance decision

`PROCEED_M7_1`。

接受理由：两端 dirty worktree 已隔离；M7 分支/工作树干净；M1-M5 正式 API 与 schema 已盘点；M2 façade 缺口和 M3 identity/availability 语义已显式记录；本阶段未写 Agent 业务逻辑；local/cloud full regression 均通过。

下一 milestone 只实现 action/state/trace/budget schema、纯 Python contracts 与 deterministic mock tests。

## M7-1 Agent contracts

新增 `work1_agent.agent` 契约层与三份 JSON schema：

- `AgentAction`：固定 allow-list 覆盖 M2、M3、`PROPOSE` 与 `STOP`；action ID 由规范化 payload 稳定散列；`PROPOSE` 直接解析正式 M4 `SecurityProposal`；`STOP` 只接受冻结的 stop reason。
- `AgentBudgetLimits` / `BudgetTracker`：默认 15 rounds、每轮 4 次工具、总计 40 次工具、10 个 proposals、8 个 admissible、每轮 1 个 proposal；默认值同时是 hard ceiling，超限立即拒绝。
- `AgentState`：只保存单一 `project_id` 的 inspected/visited entity、工具调用、proposal、admissible proposal、path 和失败历史；序列化前强制规范化排序。
- `AgentTraceEvent` / `AgentTrace`：project-local、round-local、sequence 连续的 JSONL trace；trace ID 稳定且 replay 时重新验证，拒绝跨项目和序列断裂。
- schemas：`work1_agent_action.schema.json`、`work1_agent_state.schema.json`、`work1_agent_trace.schema.json`；action schema 通过正式 `security_proposal.schema.json` 引用 M4 proposal。

M7-1 没有引入 LLM SDK、benchmark selection、M6 diagnostic artifacts 或任何 CVE/CWE/patch/location 字段，也没有实现工具 dispatcher，因此该阶段仍是纯 deterministic contracts。

### M7-1 regression evidence

- targeted：`9 passed, 3 skipped`，返回码 0。
- local full regression：`157 passed, 6 skipped`，返回码 0。

### M7-1 acceptance decision

`PROCEED_M7_2`。

接受理由：action/state/trace/budget 的稳定 round-trip、schema validation、项目隔离、显式 STOP、冻结默认预算与 hard ceiling 均有定向测试；完整回归通过；尚未越过 M7-1 边界接入真实模型或执行工具。
