# Work1 V11 M8-5: Controlled Multi-Agent Smoke

## 范围与结论

M8-5 增加一个非 benchmark Java fixture 和可审计的四 Agent smoke runner。它只验证真实模型调用前所需的 prompt、dispatch、evidence、proposal、Gate、graph/path、artifact 与 no-leakage 链路，不代表真实项目 detection、autonomous recovery 或漏洞确认。

冻结 Agent 分配如下：

| id = name | exact model ID |
|---|---|
| `coordinator_agent` | `claude-opus-5` |
| `input_agent` | `claude-sonnet-5` |
| `effect_agent` | `claude-sonnet-5` |
| `semantic_bridge_agent` | `claude-sonnet-5` |

runtime 使用两个独立环境前缀：`M8_COORDINATOR_LLM_` 与 `M8_SPECIALIST_LLM_`。real smoke 要求 exact endpoint、temperature 0、seed omitted、`JSON_OBJECT` structured output，并对两个 exact model ID fail closed。API key 只从环境读取；manifest 仅记录 key presence 和变量名。

## Controlled repository

fixture 为 `tests/fixtures/work1_agent_m8`。`receive(String requestPath)` 是显式受控输入边界，`carry(String value)` 返回参数，`persist(String path)` 使用该值执行文件写入。fixture-only graph 提供以下两条结构关系：

- `receive PARAMETER[0] -> carry PARAMETER[0]`
- `carry RETURN -> persist PARAMETER[0]`

这些关系带 `controlled_fixture_only` provenance，只存在于 smoke runtime，不进入 development/formal detector，也不是 Route B rule。

deterministic 四 Agent run 依次产出一个 Input finding、一个 Effect finding、一个 WRAPPER_FLOW Bridge finding；三个 proposal 均通过未修改的 M4 Gate，并经未修改的 M5 builder 形成一条 Candidate Path。该路径只表示值得 Work2 验证的候选链。

## Artifact 与安全边界

每次 run 拒绝覆盖非空目录，并写出 txt 约定的 coordinator/specialist traces、tool/evidence/findings、proposal/Gate、graph/path、board replay、failure taxonomy、summary、manifest、artifact audit 与 no-leakage audit。

manifest 记录 Git SHA、branch、UTC timestamp、project identity/revision、CodeQL 状态、四 Agent exact model、provider/endpoint/protocol、四 prompt version/hash、全部 schema hash、tool catalog hash、M4/M5 和 scope/role helper version/source hash、budget、path limits、token/tool/runtime、全部 detector input hash 与 output hash。RuntimeSecurityBoundary 在 seal 后重新审计输入哈希；API secret 扫描结果共同决定 no-leakage 状态。

Evidence Board snapshot 可以由 `board_events.jsonl` 完整 replay。artifact hash 测试逐项复算 `manifest.output_hashes`，并验证 secret marker 不出现在任何 artifact。

## 本地验证

- M8 controlled/coordinator/specialist targeted: `31 passed`；
- full regression: `317 passed, 2 skipped, 5 warnings`；
- `python -m compileall -q src tests`: 通过；
- `git diff --check`: 通过。

5 个 warnings 是既有 `jsonschema.RefResolver` deprecation warning，不改变测试判定。

## Real-LLM gate

CloudStudio real smoke 必须在 clean worktree checkout 本 milestone exact commit，使用唯一且非覆盖的 artifact attempt 目录。进入 M8-6 的硬条件是至少形成一条 Candidate Path 且 no-leakage audit 为 PASS。真实 Claude 结果和 exact commit/attempt identity 在云端复验完成后追加记录；失败 attempt 也必须保留，且不得通过覆盖目录或在同一 attempt 上调 prompt 规避负结果。
