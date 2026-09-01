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

## CloudStudio real-LLM attempt 1

2026-09-01 在 CloudStudio clean worktree `/workspace/m8v` 对以下冻结身份执行了一次真实模型 smoke：

- Git SHA：`db87f201bfcc6b4d786b695d56c344e834ec1ed1`；
- branch：`work1/agent-active-security-v11-m8-multiagent`；
- artifact root：`/workspace/experiment-output/artifacts/work1-agent-v11/m8_multiagent/controlled_real_llm/db87f201-20260901-attempt1`；
- project：非 benchmark 的 `CONTROLLED_M8` fixture；
- coordinator：`coordinator_agent`，`id == name`，`claude-opus-5`；
- specialists：`input_agent`、`effect_agent`、`semantic_bridge_agent`，均为 `id == name` 和 `claude-sonnet-5`；
- provider/protocol：`openlux` / `OPENAI`，exact endpoint `https://api.openlux.ai/v1/chat/completions`；
- structured output：`JSON_OBJECT`，temperature `0`，seed omitted，timeout `60s`，max output tokens `2048`。

manifest 只记录 API key 对应环境变量名和 `api_key_present=true`；运行输出、artifact 和 Git 均未记录 secret。运行前后的 CloudStudio 验证为：targeted `32 passed`、full regression `318 passed, 1 skipped, 5 warnings`、`compileall` 通过、`git diff --check` 通过，worktree 保持 clean，远端 branch 与上述 SHA 一致。

真实运行结果：

| metric | value |
|---|---:|
| coordinator rounds | 5 |
| model calls | 5 |
| input / output tokens | 18,256 / 6,292 |
| attempted Input dispatches | 4 |
| successful specialist dispatches | 0 |
| Input / Effect / Bridge findings | 0 / 0 / 0 |
| proposals / admissible proposals | 0 / 0 |
| Gate admission rate | 0.0 |
| CodeQL calls | 0 |
| Candidate Paths | 0 |
| stop reason | `BUDGET_EXHAUSTED` |

`failure_taxonomy.json` 记录 4 个 `SPECIALIST_TOOL_RESTRICTION`。四次 Input dispatch authorization attempt 都试图授予超出 Input specialist allow-list 的工具，runtime 在创建 TaskSpec 前按安全边界 fail closed；因此没有成功进入 specialist 执行，也没有继续调度 Effect 或 Bridge。失败首先位于 Coordinator 到 specialist 的 TaskSpec/tool-policy 边界，而不是 M4 Gate、M5 path builder 或 no-leakage evaluator。

独立落盘核验结果：

- `candidate_paths.jsonl` 为 0 行；
- `no_leakage_audit.json` 为 `status=PASS`、`no_leakage_pass=true`、`runtime_boundary_pass=true`、`model_secret_scan_pass=true`、`violation_count=0`；
- `artifact_audit.json` 为 `required_files_present=true`、`no_leakage_pass=true`。

M8-5 gate 结论为 **FAIL**：no-leakage 条件通过，但 Candidate Paths 至少 1 条的硬条件未通过。本 attempt 作为不可覆盖的负结果保留，不在同一目录重跑，也不进入 M8-6 development cohort。

## Attempt1 后的通用修复冻结

用户在 attempt1 封存后明确要求修复。审计确认这不是项目语义、Gate 或 specialist 权限问题，而是模型输入契约缺失：Coordinator 必须生成 `allowed_tools`，但 V2 prompt/observation 没有提供 canonical 名称；失败 action 又在 role-policy 校验前消耗 specialist dispatch budget。

新冻结只修复该通用协调协议：

- `M8_COORDINATOR_RUNTIME_V2` 在每轮 observation 中公开从实际 specialist runtime 派生的完整 `dispatch_tool_policy`；
- `M8_COORDINATOR_V3` 要求 `allowed_tools` 是对应 action policy 的非空、大小写精确子集，prompt SHA-256 为 `ca5c7792dbce8ac544912d9a5a04d6053985a3f60ea2e0f9786ef22eeae9916c`；
- 未知和跨角色工具仍 fail closed，不做 alias 猜测、静默取交集或权限扩张；
- restriction feedback 记录 specialist、requested、invalid 和 canonical allowed tools；
- 只有通过 preflight 并真正创建 TaskSpec 的 dispatch 扣 specialist quota，非法 action 仍扣 Coordinator round/model-call budget；
- observation 的 policy 使用独立精确序列化，避免通用 evidence 压缩器把 17 项工具数组截断为 12 项。

该修复不读取 benchmark/evaluator，不包含 fixture entity、项目名、CVE/CWE、危险 API 或 case-specific rule，不修改 M4 Gate、M5 path builder、specialist tool allow-list、CodeQL tool catalog 或预算上限。attempt2 必须使用新 Git SHA 和新的非覆盖 artifact root；只有 attempt2 同时满足 Candidate Paths 至少 1 条和 no-leakage PASS，才重新评估 M8-6 gate。

本地冻结验证为：M8 targeted `48 passed, 2 warnings`，full regression `319 passed, 2 skipped, 5 warnings`，`compileall` 和 `git diff --check` 均通过。

## CloudStudio real-LLM attempt 2

2026-09-01 在 CloudStudio clean worktree `/workspace/m8v` checkout 通用 Coordinator 修复后，使用新的不可覆盖目录执行 attempt2：

- Git SHA：`0e23d2c97cf8b89018c195f9a4b841eb45c8d591`；
- branch：`work1/agent-active-security-v11-m8-multiagent`；
- artifact root：`/workspace/experiment-output/artifacts/work1-agent-v11/m8_multiagent/controlled_real_llm/0e23d2c-20260901-attempt2`；
- project：非 benchmark 的 `CONTROLLED_M8` fixture；
- coordinator：`coordinator_agent`，`id == name`，`claude-opus-5`；
- specialists：`input_agent`、`effect_agent`、`semantic_bridge_agent`，均为 `id == name` 和 `claude-sonnet-5`。

运行前 CloudStudio 验证为 targeted `48 passed, 2 warnings`、full regression `320 passed, 1 skipped, 5 warnings`、`compileall` 通过、`git diff --check` 通过。HEAD 与上述 SHA 一致；一次终端误操作产生的 0 字节未跟踪文件 `tatus --short` 经确认后删除，随后 `git status --short` 为空。attempt1 目录保持原样。

真实运行结果：

| metric | value |
|---|---:|
| coordinator rounds | 6 |
| model calls | 6 |
| input / output tokens | 26,062 / 7,451 |
| Input / Effect / Bridge dispatches | 4 / 1 / 0 |
| successful specialist dispatches | 5 |
| Input / Effect / Bridge findings | 0 / 0 / 0 |
| proposals / admissible proposals | 0 / 0 |
| Gate admission rate | 0.0 |
| CodeQL calls | 0 |
| Candidate Paths | 0 |
| stop reason | `INSUFFICIENT_EVIDENCE` |

attempt1 的 `SPECIALIST_TOOL_RESTRICTION` 已消失：Coordinator 发出的 5 个 TaskSpec 均通过 preflight，specialist dispatch quota 实际记为 Input 4、Effect 1、Bridge 0。五个 specialist 模型响应也都选择了 canonical TOOL 动作，依次为 Input 的 `READ_FILE_RANGE`、`GET_ANNOTATIONS`、`INSPECT_METHOD`、`READ_FILE_RANGE`，以及 Effect 的 `READ_FILE_RANGE`。

新的失败发生在 specialist 输出合同。V1 shared prompt 只列出 `next_suggested_evidence` 和 `uncertainty` 字段名，没有声明它们必须始终为 JSON string array。五个 TOOL 响应中四个把 `next_suggested_evidence` 写成空字符串或单个字符串，一个在前者为数组时把 `uncertainty` 写成字符串。strict parser 在任何工具执行前正确 fail closed，因此 `failure_taxonomy.json` 记录 `failure_count=10`，labels 为 `ERROR: 5` 和 `MODEL_OUTPUT_INVALID: 5`；底层五个 parser failure 中四个为 `next_suggested_evidence must be an array of strings`，一个为 `uncertainty must be an array of strings`。

独立落盘核验结果：

- `candidate_paths.jsonl` 为 0 行，且 `summary.json`、`evidence_board.json` 均记录 0 条 Candidate Path；
- `no_leakage_audit.json` 为 `status=PASS`、`no_leakage_pass=true`、`runtime_boundary_pass=true`、`model_secret_scan_pass=true`、`benchmark_informed=false`、`violation_count=0`，`hash_mismatches` 和 `secret_hit_files` 均为空；
- 对最终完整 artifact 目录再次按两个 API-key 环境变量值扫描，均无命中文件；扫描不输出 secret；
- `artifact_audit.json` 为 `required_files_present=true`、`artifact_count=23`、22 个受审计 artifact 条目、`no_leakage_pass=true`；
- `manifest.output_hashes` 和 `artifact_audit.artifacts` 两组 SHA-256 均逐项复算通过；
- manifest 的 Git/project/prompt identity、四 Agent `id == name`、`claude-opus-5` / `claude-sonnet-5` 分配和仅记录 key presence 的合同检查通过。

M8-5 gate 结论仍为 **FAIL**：no-leakage 条件通过，但 Candidate Paths 至少 1 条的硬条件未通过。attempt2 作为第二个不可覆盖负结果保留，不进入 M8-6。后续修复只应补全通用 specialist JSON 类型合同，保持 parser fail closed；不得把字符串静默包装为数组，也不得修改 specialist allow-list、预算、M4 Gate 或 M5 path builder。修复后必须使用新 Git SHA 和新的 attempt3 artifact root。

## Attempt2 后的 specialist 合同修复冻结

attempt2 负结果单独记录于 Git 提交 `47c02ca`。后续修复以 shared specialist prompt 及其冻结身份为核心，并仅额外将 specialist runtime 收紧为拒绝 TOOL 非空 advisory array；不改 normalizer、observation/result schema、工具权限、预算、M4 Gate、M5 path builder 或 controlled fixture：

- `M8_INPUT_AGENT_V2`：`8c3eb00150e5c22abb8ecc2ee465ab88d5affb2c4fc77aa4c844f0b520d992fc`；
- `M8_EFFECT_AGENT_V2`：`1939aa9aecf6be39ffab25c41da3bb8a1f6dc5692606cd1cba7e47df6f84845e`；
- `M8_BRIDGE_AGENT_V2`：`e1bd0ff9012178ef0d287b32469888af87065da31f2594ffeff5cac2da6e1600`。

V2 对八个 closed top-level 字段逐一声明 JSON 类型；所有 array 字段禁止使用 `""`、单个字符串、`null` 或 object 表示，无值必须写 `[]`。TOOL 明确使用 `findings=[]`、`status=null`，两个 advisory 字段必须为 `[]`。`M8_SPECIALIST_RUNTIME_V2` 同步拒绝 TOOL 非空 advisory array，避免接受后静默丢失；新增测试证明标量和 TOOL 非空 advisory array 都 fail closed 且不会执行工具，空数组 TOOL 正例不受影响。

本地冻结验证结果为：specialist targeted `23 passed`，M8 targeted `65 passed, 2 warnings`，full regression `326 passed, 2 skipped, 5 warnings`，`compileall` 与 `git diff --check` 均通过。attempt3 必须 checkout 本修复的最终 exact commit，使用新的非覆盖 artifact root；attempt1 与 attempt2 均不得复用或删除。
