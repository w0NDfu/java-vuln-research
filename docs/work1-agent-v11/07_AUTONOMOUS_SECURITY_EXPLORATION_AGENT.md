# Work1 V11 M7：Autonomous Security Exploration Agent

## Status

当前完成 `M7-0` 至 `M7-3`：Git/worktree 隔离、M1-M5 API inventory、Agent action/state/trace/budget 稳定契约、fail-closed runtime security boundary/no-leakage audit，以及 provider-neutral LLM client、冻结 prompt 与严格 structured parser。尚未执行 repository/CodeQL tools、proposal Gate 或 graph，也尚未运行 controlled Agent smoke 或真实 autonomous kill test。

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

## M7-2 Runtime security boundary and no-leakage

新增 `work1_agent.agent.security_boundary` 作为 detector runtime 的唯一文件输入闸门。输入不是因为文件名“看起来安全”就被信任，而是必须同时满足：

- input kind 对应的显式 allowed root confinement；lexical path 与 symlink-resolved path 都接受检查；
- 目标存在且是 regular file，并满足 128 MiB 单文件 hard ceiling；
- 路径不命中 M6 diagnostic、benchmark answer/annotation/fix/patch、evaluator answer input、ground-truth 等 denylist；
- JSON、JSONL、YAML 与 CSV 结构化内容不含 benchmark CWE/CVE/patch/location、mapped callable、root cause、proposal sequence 或 diagnostic metadata；
- `benchmark_informed` 必须为 false，`allowed_for_agent_runtime` 必须为 true；嵌入在普通字段中的禁止 artifact path 同样拒绝；
- 每次成功读取都按 logical name、kind、resolved path、byte size 与 SHA-256 登记；同一 logical name 的身份或 hash 改变立即拒绝；
- detector 结束后 `seal()` 冻结 manifest，冻结后拒绝新增读取；`audit()` 复核每个已登记文件 hash。

Java source 与正式 trusted schema 仍记录路径、大小和 hash，但跳过 benchmark-metadata key 扫描：这避免把源码注释中的 CVE/CWE 字样误判为 evaluator 泄漏，也允许正式 M4 schema 声明 `benchmark_informed=false` 约束。它们不能绕过 root confinement 或 path denylist。

显式 denylist 至少覆盖：

- `m6_killtest/diagnostic_proposals/**`；
- 任意 basename 为 `diagnostic_analysis.json`；
- `benchmark_answers`、`benchmark_annotations`、`benchmark_fixes`、`benchmark_patches`、`evaluator_inputs`、`ground_truth` 等 answer 目录；
- evaluator/benchmark/dataset 上下文中的 annotation/fix/patch/CVE/CWE 目录和 patch/diff 文件；
- `project_info.csv` 等 evaluator annotation 输入。

拒绝事件带统一 `failure_class=SECURITY_BOUNDARY_VIOLATION`，并保留细分 code、rule ID、requested/resolved path、input kind 与 logical name，可直接写入既有 `SECURITY_BOUNDARY` trace event。新增 `work1_agent_runtime_input_manifest.schema.json`，冻结 manifest 明确记录 `detector_input_frozen`、`all_inputs_hashed`、`no_leakage_pass`、全部 entries、violations 与稳定 manifest ID。

静态 import boundary 也扩展到整个 M7 Agent package：禁止导入 `m6_killtest`、`evaluation` 或 `evaluator`，从 Python dependency graph 层面隔离 detector 与答案侧。

### M7-2 regression evidence

- targeted security boundary + import isolation：`18 passed, 1 skipped`，返回码 0。
- local full regression：`174 passed, 7 skipped`，返回码 0。
- CloudStudio full regression（commit `ee8e1c1`）：`180 passed, 1 skipped, 2 warnings`，返回码 0。

测试覆盖直接/改名/嵌入路径的 M6 diagnostic、JSON/JSONL/YAML/CSV 内容泄漏、benchmark flags、root escape、freeze 后读取、manifest schema、输入 hash、读取后篡改、Java source 非误报和 runtime/evaluator import separation。

### M7-2 acceptance decision

`PROCEED_M7_3`。

接受理由：runtime input 已具备统一 fail-closed entry point、显式 denylist、内容级反伪装检查、逐文件 hash ledger、冻结语义、审计输出与结构化 violation；定向和完整回归通过；M7 runtime 未导入 M6 diagnostic/evaluator，也未接入任何 benchmark artifact。

## M7-3 Provider-neutral reasoner boundary

M7-3 新增三层分离：

1. `LLMClient` protocol：controller 以后只依赖 `complete(LLMRequest) -> LLMResponse`，不依赖任何 provider SDK。
2. `OpenAICompatibleLLMClient`：当前唯一在线 transport 实现，API key、base URL、exact model ID、provider 与参数只能由 `LLMClientConfig` runtime config 或 `M7_LLM_*` 环境变量提供；manifest 只记录 key 的环境变量名与 presence，不序列化 secret。
3. `MockLLMClient`：按冻结 sequence 返回 canonical JSON，零网络、零随机性，并保留完整 request history。

`LLMRequest` 对 project、round、system prompt、observation 与 attempt 生成稳定 request ID；`LLMResponse` 记录 model-call ID、provider、exact model ID、raw structured output、tokens、finish reason、wall clock 与非 secret 配置 provenance。HTTP transport 请求 JSON-only response format；timeout 和 unavailable 分开分类。

### Prompt boundary

冻结 `M7_SECURITY_EXPLORATION_V1` system prompt 只描述 Work1 candidate-path exploration：先取证后 proposal；名字只能作为搜索线索；实体、role/index、EvidenceRef 和 tool-call ID 必须来自当前运行；unavailable/empty/truncated/unmapped 不等于关系不存在；不得 arbitrary query；不得 direct input-to-effect shortcut；Gate 反馈后需重新取证；路径形成后允许 STOP；证据不足时保守 STOP；明确禁止输出漏洞确认、最终 weakness class、可利用性或防护有效性。

Prompt 不含项目名、case ID、已知 API、恢复答案或 root-cause 表。tool catalog 作为 bounded data 以 canonical JSON 动态附加；prompt SHA-256 可直接冻结进后续 manifest。

### Structured parser

模型输出不是自然语言，而是只有五个字段的 `work1_agent_model_decision.schema.json` envelope。处理顺序为：

1. 拒绝 Markdown fence、前后 prose、非法 JSON 与非 object；
2. 拒绝 unknown action 和额外字段；
3. 用 JSON schema 校验 decision；
4. 按实际 M2/M3 ceiling 校验每个 tool 的 exact required/optional argument、relative path、entity ID、line/byte/result/depth bounds；
5. runtime 注入不可由模型覆盖的 project ID、round、provider/model-call provenance 与 `benchmark_informed=false`；
6. proposal draft 通过 `SecurityProposal.create()` 计算 canonical proposal ID，并重新验证为正式 M4 schema；
7. 可选 catalog check 拒绝不存在的 ProgramEntity 或 fabricated EvidenceRef；
8. 生成 canonical `AgentAction` 后再次用 action schema 校验；
9. 在不修改 budget tracker 的前提下预检 tool/proposal budget。

正式 action/proposal 仍完全兼容 M1/M4 contract；proposal draft 只是隔离在 untrusted model-output 边界的输入 envelope，模型不需要也不能猜测 SHA-based action/proposal ID。

运行时内置一个 fail-closed Draft 2020-12 vocabulary validator，覆盖当前 schemas 实际使用的 `$ref`、`oneOf`、`anyOf`、`allOf`、`if/then/else`、`not`、type、required、additionalProperties、pattern、enum、const 与 size/value bounds；未知 schema keyword 会拒绝，而不是静默忽略。安装 `jsonschema 4.26.0` 后又用标准实现交叉验证 model-decision/proposal schema，避免自有 validator 与 schema 文件发生漂移。

统一 model failure classes 全部已测试：`MODEL_UNAVAILABLE`、`MODEL_TIMEOUT`、`INVALID_JSON`、`INVALID_ACTION`、`SCHEMA_VIOLATION`、`TOOL_ARGUMENT_INVALID`、`BUDGET_EXCEEDED`。

### M7-3 regression evidence

- M7-3 targeted：`18 passed`，返回码 0。
- M7-1～M7-3 aggregate targeted：`49 passed`，返回码 0。
- local full regression：`198 passed, 1 skipped, 3 warnings`，返回码 0。
- CloudStudio full regression（commit `ed6fd24`）：`198 passed, 1 skipped, 3 warnings`，返回码 0。
- `compileall` 与 `git diff --check`：返回码 0。

唯一 skip 是既有环境相关测试；warnings 来自既有及交叉校验测试使用 `jsonschema.RefResolver` 的上游 deprecation，不影响 schema validation 结果。

### M7-3 acceptance decision

`PROCEED_M7_4`。

接受理由：在线/离线模型共享 provider-neutral protocol；secret 不进入 manifest；prompt 没有 benchmark/project-specific hint；模型输出经过 decision 与 canonical action 双重 schema 验证；所有越权/越界/非法/预算失败均结构化分类；mock 与 transport 均有 deterministic tests；完整回归通过。下一阶段才会把这些 action 接到 repository-first observation 与 M2/M3 deterministic adapter。
