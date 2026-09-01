# Work1 V11 M8-4: Coordinator 多 Agent 控制器

## 结论

M8-4 已实现有界的 `CoordinatorRuntime`，串联三个 specialist、`SharedEvidenceBoard`、未修改的 M4 Evidence Gate 和未修改的 M5 graph/path builder。本阶段只使用 deterministic `MockLLMClient` 和 controlled Java fixture；没有调用真实 Claude、没有运行 benchmark，也没有把 fixture 结果当成实际检测收益。真实模型 smoke 属于 M8-5。

Coordinator 的冻结身份为：

| id = name | exact model ID | prompt version | prompt SHA-256 |
|---|---|---|---|
| `coordinator_agent` | `claude-opus-5` | `M8_COORDINATOR_V2` | `b56af0f0b4f666db8b9ec1e67e64fc3ca151da88a075103a7f9a17aae3583484` |

三个 specialist 继续使用 `claude-sonnet-5`，且每个 agent 的 `id == name`。非 Mock client 暴露 `config.model_id` 时，runtime 会精确校验模型 ID；Coordinator 使用 specialist 模型或 specialist 使用 Coordinator 模型都会 fail closed。

M8-5 real-model readiness 复核发现，V1 要求模型填写 canonical `proposal_id`，但该 ID 是 runtime 内部稳定哈希，模型不能可靠计算。V2 冻结了完整 proposal draft 字段和 role/scope 结构；模型必须省略 `proposal_id`，runtime 校验严格 key set、project scope 和非 benchmark provenance 后生成 canonical ID。已有带合法 canonical ID 的 deterministic proposal 仍兼容，Gate schema 与判定标准未改变。

Coordinator repository overview 现在携带最多 16 个有界 top-level entity 摘要，使首轮可以基于真实 `entity_id` dispatch，而不是猜测内部哈希。tool call 与 Gate observation 去除已由 EvidenceRef 独立表达的重复大字段；最终 controlled round 保持在 32 KiB frozen hard ceiling 内。

## 一轮一个动作

Coordinator 每轮接收一个紧凑的项目级 Evidence Board observation，并且只能选择一个动作：

- `DISPATCH_INPUT_AGENT`
- `DISPATCH_EFFECT_AGENT`
- `DISPATCH_BRIDGE_AGENT`
- `REQUEST_CODEQL_CORROBORATION`
- `SUBMIT_PROPOSAL`
- `REQUEST_SCOPE_REPAIR`
- `REQUEST_ROLE_REPAIR`
- `REBUILD_PATH`
- `STOP`

每次 specialist 调用仍是 `TaskSpec -> SpecialistResult -> SharedEvidenceBoard`。specialist 之间没有直接通信 API；Coordinator 也没有 repository search/read 工具，因此不能替代 specialist 自由漫游项目。每轮 action、feedback、budget、proposal、Gate、repair、path 和 stop 都作为结构化 board event 记录并可 replay。

## Evidence 与 proposal 边界

Coordinator 只能引用当前 board 中已存在的 specialist finding ID。proposal 的每个 anchor 必须被相应 finding 覆盖；每个 `EvidenceRef` 必须来自相应 finding 或 Coordinator 实际执行的固定 CodeQL 调用。runtime 会在提交 M4 Gate 前拒绝未知 finding、跨项目 evidence、伪造 evidence 或无 specialist 支持的 proposal。

`EXTERNAL_INPUT` 只能由 Input finding 支持，`SECURITY_EFFECT` 只能由 Effect finding 支持，中间五类 relation 只能由 Bridge finding 支持。Bridge proposal 不能直接把 Input finding 的 anchor 跳接到 Effect finding 的 anchor。这个限制不修改 Gate，只在 Coordinator 整合层阻止 direct input-to-effect semantic shortcut。

## 固定 CodeQL policy

六个 M3 固定工具保持不变，模型不能生成 arbitrary QL。若 proposal anchor 有 `codeql_identity`、CodeQL DB ready 且没有已有同类尝试或 evidence，Coordinator 必须先调用最相关的固定 CodeQL tool，然后才能提交 proposal。

CodeQL 的 `EMPTY`、`UNAVAILABLE`、`ERROR` 和 `ENTITY_NOT_MAPPED` 会进入 tool result、board event 和 failure taxonomy，但不被解释为“关系不存在”。当 CodeQL 不可用时，repository-only finding 仍可继续进入原 M4 Gate。成功的 CodeQL `EvidenceRef` 作为独立的 Coordinator corroboration 与 specialist evidence 共同进入 proposal、Gate 和 M5 path evidence，不回写或篡改原 specialist finding。

## Gate feedback 与修复

Scope/role helper 只在对应的真实 Gate rejection 之后启用：

- scope repair 重新计算覆盖全部 anchors 的最小 bounded scope；
- role repair 从 specialist 已声明的 role 与原 M4 validator 的合法候选中做确定性修复；
- 多个合法角色但没有 specialist 语义证据时 fail closed，不猜测；
- 修复后的 proposal 保留 `repair_of`、`repair_kind` 和 `security_semantics_changed=false` provenance。

每个新 `ADMISSIBLE` proposal 自动触发 M5 graph/path rebuild。`ADMISSIBLE` 仍只表示 proposal 通过证据准入，Candidate Path 仍只表示值得 Work2 验证的候选链，不代表漏洞、CWE、可利用性或 sanitizer 结论。

## 预算

默认冻结 development 预算与执行指令一致：Coordinator 最多 12 rounds；Input/Effect/Bridge 每项目最多 4/4/5 次 dispatch；proposal 最多 10；admissible proposal 最多 8；CodeQL 最多 12 calls。specialist 单次 dispatch 的 4 rounds、6 tool calls、1 finding batch 上限继续由 M8-3 runtime 执行。预算使用和剩余量逐轮写入 board。

## Controlled fixtures

`tests/unit/test_m8_coordinator.py` 覆盖要求中的五类 fixture 和模型身份冻结：

| fixture | 验证结果 |
|---|---|
| A | Input、Effect、Bridge 依次 dispatch；三个 proposal 经原 Gate 准入；新 proposal 自动回建并形成 Candidate Path |
| B | 错误 scope 先被 Gate 拒绝；scope helper 修复后 `ADMISSIBLE` |
| C | 错误 `FIELD_STATE` role 先被 Gate 拒绝；role helper 修复后 `ADMISSIBLE` |
| D | mapped anchor 先调用固定 `codeql_entity_facts`；CodeQL evidence 进入 board、proposal、Gate 和 path |
| E | CodeQL unavailable 不产生否定 evidence；repository-only proposal 仍可准入并继续探索 |

Fixture 中的 source/effect/relation、CodeQL 结果和结构边均为受控测试数据，只证明控制器协议和数据流正确，不证明真实项目 discovery 或 autonomous recovery。

## 验证

当前本地 targeted 结果：

- Coordinator controlled fixtures: `6 passed`；
- Evidence Board + Coordinator: `13 passed, 1 warning`；
- full regression: `307 passed, 2 skipped, 5 warnings`；
- `python -m compileall -q src tests`: 通过；
- `git diff --check`: 通过。

5 个 warnings 都是已有 schema 测试使用 `jsonschema.RefResolver` 的 deprecation warning，不改变测试判定。

CloudStudio 在 clean detached worktree `/workspace/m8v` 对 exact commit `a4f1b805461c8906b01fc58d7134ec9d1cab7c3d` 的复验结果：

- full regression: `308 passed, 1 skipped, 5 warnings`；
- Coordinator controlled smoke: `6 passed`；
- `python3 -m compileall -q src tests`: exit 0；
- `git --no-pager diff --check`: exit 0；
- 最终 `git --no-pager status --short`: clean；
- 最终 HEAD 仍为 exact commit。

本地与云端 skipped 数不同来自环境依赖可用性差异；两边均无 failed test。云端 targeted smoke 另显示现有 `pylama` 导入 `pkg_resources` 的一条 UserWarning，不改变测试判定。CloudStudio 页面同时显示 CAPTCHA，但本次复验未与其交互。

## 未改变的边界

M8-4 没有修改 M4 Gate 判定标准、M5 path builder、M3 fixed CodeQL tools、Route B、Work2、旧 M7 branch 或旧 M7 artifacts。实现不含项目名/CVE/CWE/patch/benchmark location 规则，也没有读取 evaluator annotation。
