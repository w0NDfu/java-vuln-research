# Work1 V11 M8-1：Multi-Agent Architecture 与 Shared Evidence Board

## 结论

M8-1 已建立 deterministic、project-local、可回放的多 Agent 交换层。本阶段没有接真实 LLM，没有创建 proposal，没有调用 Evidence Gate，也没有运行 benchmark。它只解决 M7 中“各类发现直接混在同一个通用 Agent trace 中”的状态与契约问题。

架构不是自由群聊：

```text
Coordinator
  -> SpecialistTaskSpec
  -> Input / Effect / Bridge Specialist（一次 bounded dispatch）
  <- SpecialistResult（一个 finding batch）
  -> SharedEvidenceBoard.merge
  -> Coordinator 再决策
```

specialist 之间没有直连消息、共享聊天历史或自动轮询。跨角色信息只能先写入 SharedEvidenceBoard，再由 Coordinator 选择性放进后续 TaskSpec。

## 角色与模型合同

| 角色 | exact model ID | M8 责任 |
|---|---|---|
| Coordinator / 主 Agent | `claude-opus-5` | 调度、整合、CodeQL 请求、proposal/Gate/path/stop 决策。 |
| Input Agent | `claude-sonnet-5` | 只产生外部影响相关 finding。 |
| Effect Agent | `claude-sonnet-5` | 只产生安全相关行为 finding。 |
| Bridge Agent | `claude-sonnet-5` | 只产生最小局部语义桥 finding。 |

模型名称与 ID 同名。M8-1 尚未实例化任何模型 client；这里只把该分工固定为后续 M8-3/M8-5 的 runtime contract。后续 manifest 必须分别记录 `models.coordinator` 与 `models.specialists`，不能只写一个全局 model。

## 新增 contracts

### SpecialistTaskSpec

Coordinator 对一次 specialist dispatch 的唯一输入：

- `project_id`
- `specialist_agent`
- `coordinator_round`
- `dispatch_index`
- `objective`
- `seed_entity_ids`
- `known_findings`
- `unresolved_question`
- `allowed_tools`
- `remaining_specialist_budget`
- `prohibited_actions`
- `provenance`

预算键固定为 `max_internal_rounds`、`max_tool_calls`、`max_finding_batches`。默认 prohibited actions 明确禁止 benchmark answer/evaluator、arbitrary QL、绕过 Gate 和最终漏洞结论。allowed tools 与 prohibited actions 必须不相交。

`task_id` 由全部语义输入 canonical JSON 计算，不包含非语义 producer metadata。内容被改写而 ID 不变时 fail-closed。

### SpecialistFinding

三种 typed finding：

- `INPUT_FINDING`
- `EFFECT_FINDING`
- `BRIDGE_FINDING`

每条 finding 必须有：project、specialist role、round、entity IDs、tool-call IDs、EvidenceRef IDs、结构化 details、uncertainties 和 provenance。finding 必须至少引用一个 tool call 和一个 EvidenceRef。

role/type 是硬约束：Input Agent 不能产生 EffectFinding，Effect Agent 不能产生 BridgeFinding，Bridge Agent 不能产生 InputFinding。这只是职责隔离，不代表 finding 已成为 M4 proposal。

### SpecialistResult

一次 bounded dispatch 的唯一输出：

- `status`
- `findings[]`
- `evidence_refs[]`
- `tool_calls[]`
- `next_suggested_evidence[]`
- `uncertainty[]`
- `stop_reason`
- `rounds_used`
- `tool_calls_used`
- `provenance`

`FINDINGS` 必须携带非空 finding batch；其他 status 不允许夹带 finding。一个 batch 可以包含多个独立 grounded findings，但在 Board 中只计一次 finding batch，符合“每 dispatch 最多一个 finding batch”而不是错误地限制为一条 finding。

## SharedEvidenceBoard

Board 至少保存任务要求的全部项目级状态：

- project/repository/CodeQL status
- input/effect/bridge findings
- inspected entities
- tool calls 与 EvidenceRefs
- pending proposals
- Gate results
- active admissible proposals
- candidate paths
- unresolved questions
- failed hypotheses
- budget state 与 round state
- 三个 specialist 的 per-role state
- replay event log

M8-1 只填充 specialist 侧字段；proposal、Gate、path 字段为 M8-4 预留，不在本阶段伪造结果。

### Merge invariants

`merge_specialist_result(task, result)` 执行：

1. Board、TaskSpec、Result、Finding 和带 project ID 的 artifact 必须同项目；
2. Result 的 task ID 与 specialist role 必须匹配 TaskSpec；
3. 实际 rounds/tool calls/finding batch 不能超过 TaskSpec 剩余预算；
4. tool-call ID、evidence ID、finding ID 内容碰撞时 fail-closed；
5. finding 引用的 tool-call/EvidenceRef 必须已经存在于 Board 或同一 Result；
6. finding 按类型写入独立数组；
7. inspected entities、unresolved questions、failed hypotheses 和 per-role counters 结构化更新；
8. 最后追加 canonical `SPECIALIST_RESULT_MERGED` event。

这保证自然语言 summary 不能成为唯一 memory。Coordinator 后续只能从 Board 的 typed state 构造 observation。

## Per-agent state

每个 specialist 独立记录：

- dispatch count
- internal rounds
- tool calls
- finding batches
- finding count
- last task/result ID
- last result status

因此后续 budget 和停滞判断可以按角色做，不会把 Input Agent 的探索成本误记给 Effect Agent。

## Provenance 与 replay

Board event 只有两个 M8-1 类型：

- `BOARD_INITIALIZED`
- `SPECIALIST_RESULT_MERGED`

每个 event 有 contiguous sequence、project、Coordinator round、specialist role、完整 TaskSpec/Result payload、producer 和 `benchmark_informed=false`。`event_id` 是 canonical content hash。

Replay 从 `BOARD_INITIALIZED` 开始，逐条重新执行 merge，并比较重新生成 event 与 frozen event 是否逐字段相同。缺首事件、sequence 不连续、未知 event type、ID 内容不一致、snapshot 与 replay state 不一致均 fail-closed。

Artifacts 可写为：

- `shared_evidence_board.json`
- `board_events.jsonl`

读取 snapshot 时不会直接信任最终 JSON；它必须由 event log 重放得到同一状态。

## JSON schemas

- `m8_specialist_task_spec.schema.json`
- `m8_specialist_finding.schema.json`
- `m8_specialist_result.schema.json`
- `m8_shared_evidence_board.schema.json`

Python dataclass validation 与 JSON schema 都要求 closed top-level fields、canonical IDs、role enums、budget bounds 和结构化 provenance。运行时校验比 schema 更强的部分包括 project isolation、role/finding compatibility、artifact collision、reference resolution 和 replay equivalence。

## 学术边界

- Finding 不是 SecurityProposal。
- SecurityProposal 不是 confirmed relation。
- Gate ADMISSIBLE 不是漏洞确认。
- Candidate Path 不是漏洞、CWE 或 exploitability 结论。
- SharedEvidenceBoard 不允许 benchmark answer 或 evaluator annotation。
- M8-1 没有修改 Route B、M4 Gate、M5 path builder 或 Work2。

## 验证

新增 deterministic tests 覆盖：

- task/finding/result canonical identity 与 schema；
- role-specific finding restriction；
- finding batch 语义；
- project isolation；
- tool/evidence/finding collision；
- unknown artifact reference；
- specialist budget；
- structured per-role counters；
- failed hypothesis；
- snapshot/event serialization；
- event replay 等价。

本地验证：

- targeted contracts/Board/import-boundary：`16 passed`；
- full regression：`275 passed, 2 skipped, 5 warnings`；
- `python -m compileall -q src tests`：通过；
- `git diff --check`：通过。

warnings 均为既有或新增 schema 测试使用旧 `jsonschema.RefResolver` 产生的 deprecation，不影响契约判定。CloudStudio exact-commit 结果将在 push 后补充到下一里程碑审计链，不改写本次代码身份。
