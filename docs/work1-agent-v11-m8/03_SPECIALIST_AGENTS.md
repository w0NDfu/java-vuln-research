# Work1 V11 M8-3：三个 Specialist Agent Runtime

## 结论

M8-3 已实现 `InputAgentRuntime`、`EffectAgentRuntime` 和 `BridgeAgentRuntime`。本阶段只使用 deterministic `MockLLMClient` 验证 runtime contract，没有调用真实模型、没有运行 benchmark、没有产生实验 finding，也没有向 M4 Gate 提交 proposal。真实 Claude smoke 属于 M8-5，不能把本阶段 fixture 的 finding 当成检测结果。

每次调用仍是受限的单向交换：

```text
Coordinator TaskSpec
  -> one specialist runtime
  -> at most 4 internal rounds / 6 tool calls / 1 finding batch
  <- SpecialistResult
  -> Coordinator / SharedEvidenceBoard
```

三个 specialist 没有互相发送消息的 API。Bridge 只能从 Coordinator 放入 `known_findings` 的已存在 Input/Effect finding 摘要读取跨角色状态。

## Agent 身份与模型

`agent_registry.py` 冻结四个 agent 的 `id`、`name` 和 exact model ID：

| id = name | exact model ID | runtime |
|---|---|---|
| `coordinator_agent` | `claude-opus-5` | M8-4 实现 |
| `input_agent` | `claude-sonnet-5` | `InputAgentRuntime` |
| `effect_agent` | `claude-sonnet-5` | `EffectAgentRuntime` |
| `semantic_bridge_agent` | `claude-sonnet-5` | `BridgeAgentRuntime` |

非 Mock client 暴露 `config.model_id` 时，specialist 构造器要求它与注册表精确相同，否则 fail-closed。每条 finding/result provenance 同时记录 agent ID、冻结配置 model ID，以及实际 response provider/model ID，防止 manifest 只保留一个模糊的全局 model 字段。

## 冻结 prompt

| role | version | SHA-256 |
|---|---|---|
| Input | `M8_INPUT_AGENT_V1` | `5c16fc6b5337f2277ade342ba4c0b015e96e2a765cafe77f8411bbf26759320d` |
| Effect | `M8_EFFECT_AGENT_V1` | `648f968268af323618c6cb8918415fe2da7dc79516139651f22a7b7839873384` |
| Bridge | `M8_BRIDGE_AGENT_V1` | `753396bfd91d9e377de253f3c0a5ca2304436f6e06e704541bded0c5971f33f6` |

共同 prompt 明确：finding 不是 proposal，ADMISSIBLE 不是漏洞，Candidate Path 不是已确认漏洞；不读 benchmark/evaluator/CVE/patch/M6 diagnostic；不生成 arbitrary QL；CodeQL `EMPTY/UNAVAILABLE/ERROR/ENTITY_NOT_MAPPED` 不是否定证据。

角色 prompt 互不相同：

- Input 只判断 value role 是否有外部影响证据，不找 effect 或完整路径；
- Effect 只判断当前程序行为是否有安全相关副作用或敏感解释，不推断 input；
- Bridge 只在已有 input/effect finding 之间检查最小局部缺失关系，不做 repository-wide free search。

## 严格 action protocol

模型每轮只能返回一个 closed-key JSON object，`action_type` 只能是：

- `TOOL`：一个 TaskSpec 与 role 双重 allow-list 内的 M2/M3 工具；
- `SUBMIT_FINDINGS`：一个 grounded finding batch；
- `STOP`：一个非 `FINDINGS` 的终止状态。

运行时复用 M7 的 `StructuredOutputNormalizer`、`validate_tool_arguments()`、`AgentAction`、`RepositoryCodeQLToolAdapter` 和 `evidence_from_tool_result()`。因此 source access、project boundary、参数范围、固定六个 CodeQL tools 和 EvidenceRef 转换没有另起一套宽松实现。

模型不能提供 finding ID、role identity、round 或 provenance。runtime 只接受当前 dispatch 已执行的 tool-call ID 和已生成的 EvidenceRef ID，要求 finding entity 被所引用 evidence 覆盖，然后生成 canonical `m8finding-*` ID。伪造 entity/tool/evidence、跨角色 finding、错误 relation vocabulary 或缺少 role-specific details 均 fail-closed 为 `MODEL_OUTPUT_INVALID`。

不同 dispatch 可能在相同 internal round 调用相同工具。M8 使用 coordinator round、dispatch index 和 internal round 的一一复合映射进入既有 M7 `AgentAction.round` 命名空间，避免 action/tool-call ID 在不同 specialist dispatch 间碰撞。

## Tool isolation

Input 与 Effect 可由 Coordinator 从现有 11 个 repository tools 和固定 6 个 CodeQL tools 中进一步缩小 TaskSpec allow-list。Bridge 的 role allow-list不含 `SEARCH_CODE` 和 `SEARCH_SYMBOLS`，只允许局部 read/inspect、结构关系工具以及固定 CodeQL tools。

真正执行前同时检查：

1. 工具属于既有 `TOOL_ACTIONS`；
2. 工具属于 specialist role allow-list；
3. 工具属于当前 TaskSpec allow-list；
4. 参数通过既有 M7 strict validator；
5. project、RepositoryIndex 与 tool adapter 身份一致；
6. dispatch 不超过 4 rounds、6 tool calls、1 finding batch。

Bridge TaskSpec 还必须同时含已有 `INPUT_FINDING` 和 `EFFECT_FINDING`，否则 Coordinator 尚未提供桥接前提，runtime 拒绝启动。

## Role-minimal observation

每轮 observation 硬上限为 16 KiB，并记录：

- canonical observation ID；
- exact UTF-8 serialized bytes；
- `ceil(bytes/4)` token estimate；
- 与上一 observation 完全相同的 top-level section bytes；
- 剩余 dispatch budget。

Input、Effect、Bridge 分别只看到 `external_input_context`、`security_effect_context`、`semantic_bridge_context`。每轮最多携带最近 3 个 tool summary、12 个 EvidenceRef 和 8 个已知 finding 摘要，不重复完整 repository summary。Bridge observation 将 input/effect findings 放入两个独立数组。

## CodeQL 边界

六个固定 CodeQL tools 保持不变，不允许模型编写 QL。M8-3 已验证 specialist 能调用固定工具，且 `UNAVAILABLE` 会保留 tool result、warnings 和 failure，但不产生 EvidenceRef，也不会自动转成“关系不存在”。Anchor/bridge 的强制 corroboration 调度 policy 属于 M8-4 Coordinator，不在 M8-3 提前伪造。

## 验证

`tests/unit/test_m8_specialists.py` 覆盖：

- 四个 agent 的 `id == name` 与 exact model assignment；
- 三个 frozen prompt 与 role-minimal observation；
- Input/Effect/Bridge 分别产生自己的 typed finding；
- TaskSpec/role tool 双重 restriction；
- Bridge 禁止自由搜索和缺失两侧 finding；
- project/RepositoryIndex/adapter isolation；
- 4/6/1 dispatch budget；
- 不同 dispatch 的 tool-call ID 唯一性；
- fabricated entity/tool/evidence fail-closed；
- 真实 client model mismatch fail-closed；
- CodeQL unavailable 非负证据语义；
- 16 KiB observation ceiling 与 byte/token/duplication metrics。

本地验证：

- specialist targeted：`16 passed`；
- M8-1～M8-3 targeted：`40 passed, 2 warnings`；
- full regression：`301 passed, 2 skipped, 5 warnings`；
- `python -m compileall -q src tests`：通过；
- `git diff --check`：通过；
- CloudStudio exact-commit：必须在 push 后执行，当前尚未宣称通过。

5 个 warnings 均为现有 schema 测试使用 `jsonschema.RefResolver` 的 deprecation warning，不改变测试判定。

## 未改变的边界

M8-3 没有修改 M4 Evidence Gate、M5 graph/path builder、Route B、Work2、旧 M7 branch 或旧 M7 artifacts。它没有根据旧 formal evaluator 位置、CWE/CVE、patch 或项目名添加规则，也没有把 lexical call 当成 runtime dataflow。
