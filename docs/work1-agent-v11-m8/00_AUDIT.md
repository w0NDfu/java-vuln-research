# Work1 V11 M8-0：多 Agent 实验前审计

## 1. 审计结论

M8 必须作为新的、与 M7 隔离的研究分支继续，不能在旧 M7 正式 cohort 或 artifacts 上调参。当前证据支持 M8 的核心假设：M7 的 transport、structured-output、source-root 和基础 schema 问题已经排除，剩余失败主要位于单一通用 Agent 同时承担 input、effect、bridge、tool choice、proposal construction 与反馈调度所造成的任务混杂。

本阶段不修改正式逻辑。审计确认四个待验证缺口均真实存在：

1. `AGENT_FAILED_TO_FIND_EFFECT=10/10`，没有 `SECURITY_EFFECT` proposal；
2. `AGENT_FAILED_TO_FIND_SEMANTIC_RELATION=9/10`，没有可准入的 bridge proposal；
3. 六个固定 CodeQL tools 已实现且 DB 能用，但正式 M7 为 `0` 次调用；
4. 进入 Gate 的 5 个 proposal 全部通过 entity/location/evidence 前置检查，却因 scope/role 构造错误被严格拒绝。

因此 M8 应新增结构化 Shared Evidence Board、三个专职 runtime、Coordinator 调度、CodeQL corroboration policy 和 deterministic scope/role helper；不得扩展 Route B、不得降低 M4 Gate、不得修改 Work2。

## 2. Git、worktree 与云端基线

### 2.1 本地

- 主 checkout：`F:/ForGithub/java-vuln-research`
- 主 checkout 分支：`work1/agent-active-security-v11`
- 主 checkout HEAD：`d7cd7231429785b714e5ade69d578efec5207aef`
- 主 checkout 已存在多项用户未提交修改和未跟踪文件；本轮不触碰、不 reset、不 clean。
- 已审计 M7 worktree：`C:/Users/戴超杰/.codex/visualizations/2026/08/29/01a04b8d-1779-78a0-8555-f98cec648fd5/m7-worktree`
- M7 最新 HEAD：`96a179fb2645e1092015f2b68809b886277d8bb8`
- 新 M8 worktree：`C:/Users/戴超杰/.codex/visualizations/2026/08/29/01a04b8d-1779-78a0-8555-f98cec648fd5/m8-worktree`
- 新分支：`work1/agent-active-security-v11-m8-multiagent`
- M8 起点：精确从 `96a179fb2645e1092015f2b68809b886277d8bb8` 创建，工作区干净。

M8 分支创建没有移动或改写 M7 分支。旧主 checkout 的既有改动也未被纳入 M8。

### 2.2 CloudStudio

CloudStudio `/workspace/java-vuln-research-m7` 的只读审计结果：

- 分支：`work1/agent-active-security-v11-m7`
- HEAD：`96a179fb2645e1092015f2b68809b886277d8bb8`
- 工作区：clean
- origin：`ssh://git@ssh.github.com:443/w0NDfu/java-vuln-research`
- 旧 M7 worktree 和 `/workspace/experiment-output/artifacts/work1-agent-v11/m7_agent/...` 均存在。

CloudStudio 当前尚无 `/workspace/java-vuln-research-m8`。它只能在 M8 commit 推送后，从远端 exact commit 创建；不得从云端旧 checkout 直接手改形成分叉实现。

## 3. M7 权威结果与边界

最新 M7 报告为 `docs/work1-agent-v11/07_AUTONOMOUS_AGENT.md`。需要区分两个 Git 身份：

- M7 正式 detector SHA：`07ec7767825bae72ba0d9b8591e058f558b1ffa9`；
- 包含最终报告的 M7 分支 HEAD：`96a179fb2645e1092015f2b68809b886277d8bb8`。

正式结果：10/10 setup-ready，10/10 进入模型循环，77 rounds，79 model calls，62 repository calls，0 CodeQL calls，496 EvidenceRefs，5 proposals，0 ADMISSIBLE，0 candidate paths，0/10 autonomous recovery。140 个 detector files 的 post-freeze no-leakage audit 通过，native preservation 通过。

旧 M7 负结果必须原样保留。M8 不把旧 10-case cohort 作为新的完全未见 formal holdout；只允许作为 historical comparison，不能用 evaluator 信息调 prompt、budget、scope helper 或 specialist policy。

## 4. M1-M7 API inventory

| Milestone | 已有主要 API / contract | M8 复用边界 |
|---|---|---|
| M1 | `ProgramEntity`, `ProgramEntityKind`, `RepositoryIndex`, `build_repository_index`, `search_code`, `search_symbols`, `read_file_range`, `inspect_entity` | 继续作为唯一实体身份和 repository confinement 基础；不得按项目添加 parser 特例。 |
| M2 | `RepositoryCodeQLToolAdapter` 的 11 个 repository actions；`AgentToolResult`、EvidenceRef 转换 | 保留 bounds/project isolation；只补通用结构解析能力和 specialist allow-list。 |
| M3 | `CodeQLAnalysisTools`, `CodeQLExecutor`, `map_program_entity`, `CodeQLToolResult`；六个固定 tools | 六个 tool 名和 fixed-query 边界保持不变；新增调度 policy，不允许模型写 QL。 |
| M4 | `SecurityProposal`, `EvidenceRef`, `EntityRoleRef`, `ProposalScope`, `EvidenceGate`, `validate_role`, `validate_proposal_shape`, `validate_scope` | Gate 顺序、准入语义和 `ADMISSIBLE != vulnerability` 不变；helper 只做结构合法性预览/修复。 |
| M5 | `HybridEvidenceGraphBuilder`, `AgentGraphPathAdapter`, `BoundedPathBuilder`, `NativePathAdapter`, `SearchLimits` | 仅在新 ADMISSIBLE 后 rebuild；原生 CandidatePath byte-semantically preserved。 |
| M6 | frozen kill-test inventory、detector/evaluator separation、artifact audit、diagnostic-only lineage | 只复用隔离与审计机制；M6 hints/annotations 不进入 M8 detector。 |
| M7 | `AgentController`, `AgentState`, `BudgetTracker`, strict parser/normalizer, provider-neutral LLM clients, runtime boundary, trace/artifact writer, formal detector/evaluator | M7 single Agent 保留为 E0 baseline；M8 新建独立 controller/runtime，不在原类中塞角色分支。 |

### 4.1 当前 ProgramEntity 能力

`ProgramEntityKind` 已定义 `FILE/PACKAGE/TYPE/METHOD/CONSTRUCTOR/PARAMETER/FIELD/CALL/ANNOTATION/RETURN/LOCAL/CALL_ARGUMENT/FIELD_READ/FIELD_WRITE`。但“枚举类型存在”不等于 M1 对所有 Java 结构都能高置信抽取；M8 helper 和工具必须基于实际 index/provenance 检查，不得假定每个 kind 都齐全。

### 4.2 当前 M3 固定工具

固定并继续冻结：

- `codeql_entity_facts`
- `codeql_callers`
- `codeql_callees`
- `codeql_local_flow`
- `codeql_dataflow_neighbors`
- `codeql_cfg_neighbors`

`RepositoryCodeQLToolAdapter._codeql()` 已正确区分 `UNAVAILABLE`，并明确记录 unavailable 不能解释为关系不存在。实体映射支持 `ENTITY_NOT_MAPPED`，固定查询执行器也已有 failure taxonomy。因此正式 0 调用不能归因于没有实现 M3。

## 5. 当前 single-Agent controller 审计

`AgentController.run()` 每轮只调用一个通用模型，动作来自同一个 `ActionType` 集合：repository tool、CodeQL tool、`PROPOSE` 或 `STOP`。首轮被限定为 `SEARCH_CODE/SEARCH_SYMBOLS`；后续 tool、proposal、Gate、graph/path 和 stop 全由同一个模型决定。

已有正确约束：

- 每轮一个结构化 action；
- tool/result/evidence/project isolation；
- anchor proposal 需要先 inspect callable；
- bridge evidence 必须覆盖 source/target；
- Gate feedback 可回到下一轮；
- 仅新 ADMISSIBLE 才 rebuild graph/path；
- budget/stagnation 有界；
- invalid structured output 只做 bounded repair。

主要结构缺口：

- 没有 Input/Effect/Bridge 的独立任务状态、prompt、allow-list 或 budget；
- 没有 Coordinator dispatch action；
- finding 只存在于自然语言 reasoning 或直接 proposal，没有中间 typed finding contract；
- 没有 Shared Evidence Board，也没有 finding provenance/replay；
- Gate feedback 回到同一个通用 Agent，不能定向交还原 specialist；
- 没有 scope/role preview/repair action；
- 没有 deterministic CodeQL corroboration trigger；
- controller observation 始终是同一种 repository-first payload，而不是按角色最小披露。

## 6. CodeQL 0 调用的代码路径根因

这是调度缺失，不是 executor 缺失：

1. `bounded_tool_catalog()` 确实把六个 CodeQL actions 与 repository actions 一起展示给模型；
2. prompt 只说“static analysis available”，没有 anchor-before-submit、bridge-gap 或 evidence-conflict 的强制 policy；
3. controller 对所有 `TOOL_ACTIONS` 一视同仁，仅执行模型选择的 action；
4. `codeql_status` observation 只提供 availability/ready/status/reason/database identity，不维护“此 entity 已映射但尚未 corroborate”的任务；
5. proposal 进入 Gate 前只有 evidence、callable inspection 和 bridge endpoint coverage 约束，没有 CodeQL-attempt 检查；
6. `ENTITY_NOT_MAPPED` 没有 project-level dedup state，现有 controller 也不会主动避免重复尝试。

M8 需要独立 `CodeQLCorroborationPolicy`。policy 只决定是否尝试一个既有固定工具、如何记账和何时停止重试，不决定安全语义，也不把 EMPTY/UNAVAILABLE/ERROR 当负证据。

## 7. Repository tool limitation 审计

| Tool | 当前实现 | 研究限制 |
|---|---|---|
| `SEARCH_CODE` | 单个大小写无关 literal substring | 只给 lexical lead；无法表达结构查询。 |
| `SEARCH_SYMBOLS` | indexed symbol literal match | 依赖 M1 已抽取实体。 |
| `READ_FILE_RANGE` | confined bounded source read | 无调用点/值角色结构化结果。 |
| `INSPECT_METHOD/TYPE` | bounded entity source + context | 能给部分 parameter/return role refs，但没有专用 callsite/constructor/return-flow 视图。 |
| `GET_CALLERS` | 所有同 `simple_name` 的 `CALL` | 返回 `CALLS_CANDIDATE`；未按 declaring type/overload/dispatch 验证。 |
| `GET_CALLEES` | 当前 enclosing callable 中的 lexical CALL | 是 `LEXICAL_CALL`，不是 resolved runtime call graph。 |
| `GET_IMPLEMENTATIONS` | simple-name 搜索并检查文本含 `implements/extends` | 文本候选，容易漏掉/误配复杂类型。 |
| `GET_OVERRIDES` | 同 simple name + signature | 未验证继承/接口关系，仅 `OVERRIDE_CANDIDATE`。 |
| `GET_FIELDS` | 按 enclosing type 枚举 FIELD | 结构上较可靠，但不等于 field write/read flow。 |
| `GET_ANNOTATIONS` | 同文件且范围内/前三行邻近 | 只是附着候选，不是完整 Java annotation ownership。 |

现有 adapter 已对 lexical relations添加 `M1_RELATION_IS_STRUCTURAL_CANDIDATE_NOT_SEMANTIC_FACT` 警告，边界是正确的。M8 应优先补通用 `find_entity_by_location`、`inspect_callsite`、`inspect_constructor`、`inspect_field_accesses`、`inspect_return_flow`、`get_enclosing_callable/type`、`get_call_argument_entities`、`get_return_entities`；如 M3 能提供更强结构事实，优先合并 M3 evidence，而不是把 lexical candidate 升格为语义事实。

## 8. 5 个 Gate reject 的 contract 审计

M4 Gate 的执行顺序是 schema → entity/no-fabrication → location → role/shape → evidence resolution → locality → scope → duplicate/native → sufficiency。正式 5 个 proposal 均在后段失败，说明前置实体和 evidence 不是伪造。

### 8.1 Scope

P007、P010（两次）、V005 的四个 `EXTERNAL_INPUT` proposal 因 `SCOPE_DOES_NOT_BOUND_ALL_ANCHORS` 被拒绝。`validate_scope()` 要求 subject/source/target 的全部 entity IDs 都属于 `scope.entity_ids`，并继续禁止 wildcard、`..` 和超过 12 个 explicit entities。

修复方向：`build_valid_scope()` 从 owner callable/type/file 和 anchors 确定最小 bounded scope，返回 preview 与 covered anchors。不得自动扩大到 PROJECT，不得修改 `validate_scope()`。

### 8.2 Role/shape

V004 的 `FIELD_STATE` 因 `FIELD_STATE_ANCHORS_REQUIRED` 被拒绝。当前 shape contract 要求：

- source 与 target 均存在；
- source role 为 `FIELD_WRITE/ARGUMENT/PARAMETER`；
- subject role 为 `FIELD`，且 subject entity kind 为 `FIELD`；
- target role 为 `FIELD_READ/RETURN`。

修复方向：role helper 根据 ProgramEntity kind、relation type 和已观察源码结构返回合法 roles/index/schema example；不能凭安全语义自动生成 relation。

## 9. Observation 与 token duplication 审计

M7 已把 observation 限制为 BOOTSTRAP 16 KiB、TOOL_GROUNDED 24 KiB，但每一轮仍重复构造：repository identity、Java/entity counts、top packages、完整 17-tool 名称与 purpose、CodeQL/native 摘要、budget 和 runtime rules。所有角色不存在，因此同一通用 payload 同时承担导航、input/effect/bridge 和 proposal 构造。

正式 M7 共 79 model calls，provider 记账 input tokens `7,140,650`、output tokens `16,941`，约 `90,388` input tokens/model call。不能仅由当前 trace 精确分解这些 token 的来源：`write_controller_artifacts()` 没有写逐轮 `observations.jsonl` 或完整 model request，只写 trace/model-call 摘要；trace 的 `INITIAL_OBSERVATION` 只保留第一轮 observation。因此 exact duplicated bytes 无法从已冻结 M7 artifacts 事后重算，这是一个可审计性缺口，不能用估算值冒充实测值。

M8 必须为每个角色、每次调用记录：canonical observation SHA、serialized bytes、system prompt SHA、tool schema/catalog SHA、input/output token、cache information（provider 有则记录）、与上一调用重复的 observation bytes，以及 project-level duplicated bytes 汇总。role observation 只包含完成当前 TaskSpec 所需的局部状态。

## 10. M8 模型合同

用户指定的角色模型是 M8 的显式实验合同：

| 角色 | exact model ID | 用途 |
|---|---|---|
| Coordinator / 主 Agent | `claude-opus-5` | 任务分解、specialist 调度、整合、CodeQL 请求、Gate/path 反馈决策、STOP。 |
| Input specialist | `claude-sonnet-5` | 外部影响证据与 InputFinding。 |
| Effect specialist | `claude-sonnet-5` | 安全相关行为证据与 EffectFinding。 |
| Bridge specialist | `claude-sonnet-5` | 最小局部缺失语义关系与 BridgeFinding。 |

模型名称与 ID 同名。实现必须使用两个独立冻结配置，而不是在 prompt 中声明角色却仍共用一个 `LLMClientConfig`：建议环境前缀 `M8_COORDINATOR_LLM_` 与 `M8_SPECIALIST_LLM_`，manifest 分别记录 provider、exact model、endpoint protocol、temperature、seed、max output、timeout 和 key-presence boolean。API key 不进入 Git、trace、artifact 或 exception text。

现有 `LLMClientConfig` 是单模型配置；现有 M7 manifest 也只有一个 `model` 字段。M8 manifest 必须改为 `models.coordinator` 与 `models.specialists`，并在每条 model-call trace 记录 `agent_role` 和 exact model ID。

E0/E1 开发比较将遵守同一 Claude 5 model family、同一 provider、相同 M4/M5、相同 repository/CodeQL tools 和可比较总 token/tool budget。由于 E1 使用显式的 Opus/Sonnet 角色分工，报告必须把模型混合标为处理的一部分，不能把全部差异无条件归因于“多 Agent”三个字。

## 11. M8-1～M8-10 文件级实施计划

### M8-1 SharedEvidenceBoard + contracts

新增：

- `schemas/m8_specialist_task_spec.schema.json`
- `schemas/m8_specialist_finding.schema.json`
- `schemas/m8_specialist_result.schema.json`
- `schemas/m8_shared_evidence_board.schema.json`
- `src/java_vuln_research/work1_agent/m8_multiagent/contracts.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/board.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/serialization.py`
- `tests/unit/test_m8_contracts.py`
- `tests/unit/test_m8_evidence_board.py`
- `docs/work1-agent-v11-m8/01_MULTI_AGENT_ARCHITECTURE.md`

要求：project isolation、stable identity、provenance、collision detection、round/budget state、failed hypotheses、deterministic replay；不接真实 LLM。

### M8-2 Scope/Role helper

新增：

- `src/java_vuln_research/work1_agent/m8_multiagent/scope_helper.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/role_helper.py`
- `tests/unit/test_m8_scope_helper.py`
- `tests/unit/test_m8_role_helper.py`
- `docs/work1-agent-v11-m8/02_SCOPE_ROLE_HELPERS.md`

直接回归四个 M7 scope failure 形态与一个 FIELD_STATE shape failure。测试必须证明 helper 产物仍由原 `EvidenceGate` 判定，不修改 `gate.py/validator.py/roles.py` 的准入标准。

### M8-3 三个 specialist runtime

新增：

- `src/java_vuln_research/work1_agent/m8_multiagent/prompts/common.py`
- `.../prompts/input_agent.py`
- `.../prompts/effect_agent.py`
- `.../prompts/bridge_agent.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/observation.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/specialists.py`
- `tests/unit/test_m8_specialist_prompts.py`
- `tests/unit/test_m8_specialist_runtime.py`
- `docs/work1-agent-v11-m8/03_SPECIALIST_AGENTS.md`

先使用 `MockLLMClient`。验证角色特化 prompt、最小 observation、独立 tool allow-list、每次 dispatch 4 rounds/6 tools/1 batch、有界 STOP、不能跨项目或越权。

### M8-4 Coordinator、CodeQL policy 与反馈闭环

新增：

- `src/java_vuln_research/work1_agent/m8_multiagent/prompts/coordinator.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/actions.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/codeql_policy.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/coordinator.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/runtime.py`
- `tests/unit/test_m8_codeql_policy.py`
- `tests/unit/test_m8_coordinator.py`
- `tests/unit/test_m8_feedback_loop.py`
- `tests/unit/test_m8_replay.py`
- `docs/work1-agent-v11-m8/04_COORDINATOR.md`

覆盖 A-E controlled fixtures：完整 input/effect/bridge→Gate→path；scope repair；role repair；repository insufficient→CodeQL；CodeQL unavailable→非负证据并继续 repository-only。Coordinator 每轮一个调度动作，specialists 不直接互聊。

### M8-5 controlled real-LLM smoke

新增：

- `src/java_vuln_research/work1_agent/m8_multiagent/controlled_smoke.py`
- `tests/fixtures/m8_controlled_java/`（非 benchmark、同时含可审计 positive/benign 结构）
- `tests/unit/test_m8_controlled_smoke.py`
- `docs/work1-agent-v11-m8/05_CONTROLLED_SMOKE.md`

冻结四个 prompt：`M8_COORDINATOR_V1`、`M8_INPUT_AGENT_V1`、`M8_EFFECT_AGENT_V1`、`M8_BRIDGE_AGENT_V1`。Coordinator 使用 `claude-opus-5`，所有 specialists 使用 `claude-sonnet-5`。必须至少形成 1 条经 M4/M5 的 Candidate Path 且 no-leakage 通过，否则停止，不进 development projects。

### M8-6 development cohort

新增：

- `src/java_vuln_research/work1_agent/m8_multiagent/development.py`
- `experiments/frozen_configs/m8_development_cohort.csv`
- `tests/unit/test_m8_development_manifest.py`
- `docs/work1-agent-v11-m8/06_DEVELOPMENT_COHORT.md`

至少 8 个不同的 `DEVELOPMENT_ONLY` 项目；不得包含新的 formal holdout benchmark answers。记录 Input/Effect/Bridge finding、CodeQL/repository use、scope/role repair、Gate/path、per-role token 和 wall-clock。

### M8-7 single vs multi

新增：

- `src/java_vuln_research/work1_agent/m8_multiagent/comparison.py`
- `tests/unit/test_m8_budget_comparability.py`
- `docs/work1-agent-v11-m8/07_SINGLE_VS_MULTI.md`

E0 复用 M7-style single Agent，E1 使用 M8 full multi-agent；同一 development cohort、同一 M4/M5、同一 tools、同一 Claude 5 family、可比较 token/tool ceiling。报告预算差、实际 token、dispatch、wall-clock，并明确模型混合这一实验因素。

### M8-8 freeze gate

新增：

- `schemas/m8_detector_manifest.schema.json`
- `src/java_vuln_research/work1_agent/m8_multiagent/freeze.py`
- `src/java_vuln_research/work1_agent/m8_multiagent/audit.py`
- `tests/unit/test_m8_freeze.py`
- `tests/unit/test_m8_no_leakage.py`
- `docs/work1-agent-v11-m8/08_FORMAL_FREEZE.md`

只有 development 同时满足 Effect≥50%、Bridge≥30%、CodeQL>0、至少 3 projects with path、至少 2 relation types、scope/role 不再主导 reject、no leakage、无 case-specific code 才 freeze；否则封存负结果并停止 M8-9。

### M8-9 new-holdout formal detector/evaluator

仅在 M8-8 通过后新增：

- `src/java_vuln_research/work1_agent/m8_killtest/detector.py`
- `src/java_vuln_research/work1_agent/m8_killtest/evaluator.py`
- `tests/unit/test_m8_killtest_detector.py`
- `tests/unit/test_m8_killtest_evaluator.py`
- `docs/work1-agent-v11-m8/09_FORMAL_RESULTS.md`

新的 holdout cohort 与旧 M7 10 cases 隔离。detector 只读 project-side frozen inputs，先完成 outputs/hash/seal，evaluator 后读 annotation。旧 cohort 只能 historical comparison。

### M8-10 decision、conditional ablation 与总报告

新增：

- `src/java_vuln_research/work1_agent/m8_multiagent/reporting.py`
- `tests/unit/test_m8_failure_taxonomy.py`
- `tests/unit/test_m8_artifact_audit.py`
- `docs/work1-agent-v11-m8/10_FAILURE_ANALYSIS.md`
- `WORK1_V11_M8_MULTI_AGENT_REPORT.md`

autonomous recovery=0 时报告失败且不进 Work2；≥1 才运行 A0-A3 ablation；≥3 recoveries、≥2 projects、≥2 semantic relation types 才报告较强可行性证据。最终逐项回答任务中的 25 个问题。

## 12. 初始预算与 failure taxonomy

Development 初始冻结：Coordinator 12 rounds；每 specialist dispatch 4 internal rounds、6 tool calls、1 finding batch；每项目 Input 4/Effect 4/Bridge 5 dispatch；proposal 10、admissible 8；CodeQL 12 calls/project。调整只能依据 controlled/development 的通用成本证据，不能依据 formal answer。

M8 至少记录：`INPUT_NOT_FOUND`、`EFFECT_NOT_FOUND`、`SEMANTIC_BRIDGE_NOT_FOUND`、`SPECIALIST_STALLED`、`COORDINATOR_STALLED`、`REPOSITORY_TOOL_LIMITATION`、`CODEQL_UNAVAILABLE`、`CODEQL_ENTITY_NOT_MAPPED`、`CODEQL_TOOL_ERROR`、`SCOPE_CONSTRUCTION_FAILED`、`ROLE_CONSTRUCTION_FAILED`、`GATE_NEEDS_MORE_EVIDENCE`、`GATE_REJECTED`、`GATE_DUPLICATE`、`PATH_NOT_CONNECTED`、`PATH_SEARCH_TRUNCATED`、`BUDGET_EXHAUSTED`、`MODEL_OUTPUT_INVALID`、`MODEL_TIMEOUT`、`MODEL_UNAVAILABLE`、`SECURITY_BOUNDARY_VIOLATION`、`INSUFFICIENT_PROGRAM_EVIDENCE`、`OTHER`。

## 13. M8-0 验证门

- targeted baseline：`96 passed`；覆盖 M7 controller/tool adapter/observation、M3 tools、M4 Gate、M5 graph/path、M7 detector。
- full regression：`261 passed, 2 skipped, 3 warnings`；warnings 均为既有 `jsonschema.RefResolver` deprecation。
- `python -m compileall -q src tests`：通过。
- `git diff --check`：通过。

只有上述门全部通过、M8-0 commit/push 后在 CloudStudio exact commit full regression 通过，才开始 M8-1。
