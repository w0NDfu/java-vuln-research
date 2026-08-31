# M7 Failure and Fix Analysis

本文档记录 M7 历史正式运行的失败根因以及在同一 M7 方法内部完成的工程修复。历史 0-recovery 结果继续保留在 `07_AUTONOMOUS_SECURITY_EXPLORATION_AGENT.md`，不得覆盖或改写为成功实验。新的 detector freeze、正式运行和 evaluator 只有在 M7-F1 至 M7-F6 全部通过后才会产生。

## 历史失败基线

CloudStudio 上的历史正式运行基于 detector commit `82200a5`，10 个 frozen baseline-miss 项目中 0 个形成 autonomous recovery：

- 8 个项目进入模型循环，但首轮响应和同轮 bounded repair 都未满足当时的 bare-JSON framing，最终以 `INVALID_JSON` fail-closed；这 8 个项目均为 2 次 model call、0 次 tool call、0 proposal、0 path。
- D003 与 P006 在模型调用前被 security boundary 拒绝。它们的合法 source root 是 symlink，解析路径包含 `datasets`，源码目录名包含 `annotations`；旧的 token denylist 将合法项目源码误判为 evaluator/answer 输入。
- 16 次 model call 共消耗 1,003,268 input tokens、2,337 output tokens。旧 observation 将过多 repository inventory、工具描述和历史反馈重复发送，虽未突破轮次预算，却造成约 1M input-token 的明显成本失控。
- 正式 detector artifacts、第一次 evaluator attempt 和修正后的 evaluator 结果均保留；本次修复不读取 benchmark answer，也不把 M6 diagnostic proposal、项目方法名或已知漏洞位置带入 runtime。

因此，旧运行不能证明真实模型缺乏安全推理能力。它首先证明的是三个可复现的工程阻塞：provider framing 与 parser 契约错位、source-path boundary 假阳性、observation 体积过大。只有消除这些阻塞后，新的正式运行才可以把剩余失败归因到 discovery、entity alignment、evidence、proposal、Gate、path connectivity 或 reasoning。

## M7-F1 Structured output normalization

状态：完成。commit `72793ed` 已推送，并在 CloudStudio `/workspace/java-vuln-research-m7` 同 commit 全量回归通过。

在 provider client 与 `StrictActionParser` 之间新增 `StructuredOutputNormalizer`，版本为 `M7_STRUCTURED_OUTPUT_NORMALIZER_V1`。它只解除唯一、无歧义的传输封装，不修补 action、字段、实体、EvidenceRef、proposal 语义或预算：

- 接受一个 bare JSON object；
- 接受外围只有空白的一个完整 JSON code fence；
- 接受恰好一个名为 `submit_agent_decision` 的 OpenAI tool call；
- 接受恰好一个名为 `submit_agent_decision` 的 Anthropic `tool_use`；
- 接受 content array 中恰好一个结构化 object；
- 拒绝 prose 与 JSON 混合、多 fence、多 tool call、多 content block、未知 tool 名和 provider/text 双对象不一致；
- normalization 后继续执行原有 decision/action/proposal schema、entity、EvidenceRef、scope 和 budget 校验，不能绕过 Evidence Gate。

每次成功 normalization 记录 mode、normalizer version、原始响应 SHA-256、provider payload shape、ambiguity flag 和 warnings；provider 原始结构只驻留在内存，不由 `LLMResponse.to_dict()` 写入 trace。新增失败类别 `STRUCTURED_OUTPUT_AMBIGUOUS` 与 `STRUCTURED_OUTPUT_UNSUPPORTED`，两者仅允许同轮一次 bounded repair，之后仍 fail-closed。

本地验证（2026-08-31）：

- `compileall`：通过；
- targeted pytest：39 passed；
- full pytest：242 passed、1 skipped；
- CloudStudio full pytest：242 passed、1 skipped、3 个既有 deprecation warnings；
- `git diff --check`：通过；
- 新增覆盖：bare/fenced JSON、OpenAI/Anthropic envelope、单 object content、多调用/多块歧义、prose 混合、未知 action，以及 normalization 后伪造 EvidenceRef 仍被 strict parser 拒绝。

安全判断：F1 修复的是 transport framing，不放宽正式决策语义。完整 fence 中的 `{}` 现在被成功解封装，但仍以 `SCHEMA_VIOLATION` 拒绝；纯自然语言现在明确分类为 `STRUCTURED_OUTPUT_UNSUPPORTED`，不会被猜测性转换成 action。

## 后续阶段状态

### M7-F2 Security boundary false-positive fix

状态：本地实现与回归通过，等待 CloudStudio 同 commit 全量回归和真实 symlink 用例。

边界策略升级为 `M7_RUNTIME_BOUNDARY_V2`。每个输入先由 `RuntimeInputKind` 映射到不可由调用者自由伪造的 `artifact_role`，再在该 kind 的显式 trusted root 内做 lexical/resolved containment：

- `JAVA_SOURCE -> PROJECT_SOURCE`：只允许已登记 source root；允许合法 source root 或解析后的路径包含 `dataset`、`datasets`、`annotation`、`annotations`，并允许 source root 本身是 symlink；
- `TRUSTED_SCHEMA -> TRUSTED_DETECTOR_ASSET`：只允许冻结的 schema/query roots；
- 其余 kinds -> `DETECTOR_RUNTIME_ARTIFACT`：继续执行 answer-artifact path denylist 与 JSON/JSONL/YAML/CSV content scan；
- 同一个物理文件不能通过声明错误 kind 借用其他 role 的 trusted root，仍以 `ROOT_ESCAPE` fail-closed。

manifest schema 升级到 version 2。每个输入除 SHA-256 外新增 `artifact_role`、`requested_path`、`resolved_path` 和实际命中的 `trusted_root`；violation trace 同样记录 role。这样 freeze 和审计能明确区分“项目源码位于名字敏感的目录中”与“detector 读取了禁止的答案 artifact”。

本地验证（2026-08-31）：targeted 33 passed、1 skipped；full 244 passed、2 skipped；`diff --check` 通过。新增 symlink 回归在本地 Windows 因创建 symlink 权限不足而 skip，必须由 CloudStudio/Linux 实际通过后才能把 F2 标记完成。

后续 deterministic 闭环还发现：同一已信任 Java 文件可先以相对路径登记、再由工具以绝对路径读取。V2 因审计字段 `requested_path` 不同而错误触发 `INPUT_CHANGED`。现已将逻辑输入身份限定为 kind、role、resolved path、trusted root、size 和 hash；requested lexical path 只保留作审计。同一文件的合法 lexical alias 回归通过，resolved identity、root containment 或内容任一变化仍 fail-closed。

### Remaining stages

### M7-F3 Compact bootstrap and tool-grounded observation

状态：本地实现与回归通过，等待 GitHub 网络恢复后执行 CloudStudio 同 commit 全量回归。

observation schema 升级到 version 2，并拆为两个确定性层级：

- `BOOTSTRAP`：只发送 Java 文件数、ProgramEntity 总数与 kind counts、最多 10 个 top packages、紧凑 CodeQL/native 状态、当前预算，以及 17 个工具的 exact name 与一行 purpose；不再预先发送最多 30 types、30 methods 和完整工具 bounds；
- `TOOL_GROUNDED`：保留同一轻量 bootstrap，并附最近 3 条压缩反馈、最后一次工具的状态/数量摘要、最多 5 个最近实体和最多 5 个最近 EvidenceRef。大源码只保留一次 bounded preview，不在 last-tool summary 中重复；EvidenceRef 去重时优先保留带 entity grounding 的完整版本。

硬上限分别为 16 KiB 和 24 KiB。每个 observation 通过稳定迭代记录 exact `serialized_chars`、`ceil(chars/4)` token estimate、估算方法与适用 ceiling；若实际 canonical serialization 超限则在 model call 前 fail-closed。通用 mapping/sequence/text、工具 items、源码 content/snippet 和 Gate feedback 均有独立确定性上限。

本地验证（2026-08-31）：targeted 25 passed；full 246 passed、2 skipped；compileall、未定义引用检查和 `diff --check` 通过。极端测试使用 12 个实体、12 个 EvidenceRef 和每项 20,000 字符源码，验证反馈为 3、实体为 5、EvidenceRef 为 5 且最终 observation 不超过 24 KiB。deterministic controlled smoke 为 6 rounds、2 tools、3 proposals、3 ADMISSIBLE、1 path、`PATH_FORMED`，artifact audit 与 no-leakage 均通过。

### M7-F4 Phased controller constraints

状态：本地实现与回归通过，等待 GitHub 网络恢复后执行 CloudStudio 同 commit 全量回归。

controller 升级为 `M7_CONTROLLER_V2`，显式维护 `DISCOVERY`、`INSPECTION`、`HYPOTHESIS`、`PATH_SEARCH`。phase 写入每个 trace event，并进入 model-visible observation。非空项目第 1 轮只接受 `SEARCH_CODE` 或 `SEARCH_SYMBOLS`；越界 action 返回 `ROUND1_DISCOVERY_ACTION_REQUIRED` structured controller feedback。无 EvidenceRef 的 proposal 在 Gate 前返回 `PROPOSAL_BEFORE_EVIDENCE`；input/effect anchor 必须位于已执行 `INSPECT_METHOD` 的 method/constructor 中；传播 proposal 的 EvidenceRef grounding 必须同时覆盖 source 与 target，否则返回 `PROPOSAL_EVIDENCE_COVERAGE_INCOMPLETE`。这些反馈不扣 proposal budget、不进入 Gate/graph，并受 stagnation ceiling 约束。

本地验证（2026-08-31）：targeted 20 passed；full 248 passed、2 skipped；compileall 与 `diff --check` 通过。deterministic phased smoke 仍为 6 rounds、2 tools、3 ADMISSIBLE proposals、1 path、`PATH_FORMED`，artifact/no-leakage audit 通过。

### M7-F5 Enriched bounded tool summaries

状态：本地实现与全量回归通过；本阶段以独立 Git commit 推送，随后由 CloudStudio 拉取同一 commit 执行云端回归。

每个 M2/M3 tool result 现在包含确定性的 `summary`，供下一轮 observation 使用，而不是把完整原始 items 再次发送给模型。摘要只保留 tool status、bounded result count、最多 5 个 linked entity IDs、最多 5 个 source locations、relation/evidence-kind 计数、truncation、warning count、结构化 failure reason，以及最多 2,000 字符的首个源码/文本 preview。事实与 preview 的递归扫描各有 2,000-node hard ceiling，防止异常嵌套结果造成无界压缩成本。

controller 另附 Gate 前证据摘要：evidence count、最多 5 个 EvidenceRef IDs、最多 5 个 covered entity IDs、source-kind counts 和 truncation。`TOOL_GROUNDED` observation 允许这两个摘要字段进入最近反馈，但仍受 M7-F3 的 24 KiB 整体硬上限约束。原始 tool items、EvidenceRef 和 trace artifact 保持完整审计语义；摘要不被当作新证据，也不绕过 Gate。

本地验证（2026-08-31）：targeted 21 passed；controlled smoke integration 2 passed；full 248 passed、2 skipped；compileall 与 `diff --check` 通过。deterministic smoke 的 tool/proposal/Gate/path 行为保持不变。

### M7-F6 Controlled real-model preflight

状态：两项目 preflight runner、冻结配置与自动门槛审计已实现并通过机制回归；CloudStudio 已执行两次保留产物的真实启动诊断，但尚无通过的 `claude-opus-5` preflight，因此 `freeze_allowed` 仍未成立，禁止进入 F7/F8。

preflight 不再只使用合成 fixture。冻结配置按 `FROZEN_PROJECT_INVENTORY_JAVA_FILE_COUNT` 选择两个不属于正式 10-project kill-test 的真实开源项目：SMALL 为 V011 OWASP/json-sanitizer（6 个 Java 文件），MEDIUM 为 V022 ESAPI/esapi-java-legacy（351 个 Java 文件）。配置只含公共项目身份、source root、精确 revision、Java 文件数与模型传输契约；`benchmark_informed=false`，不含 CVE、CWE、patch、known location、M6 proposal 或 evaluator 输入。运行前会校验 project ID 安全性、40-hex revision、Git HEAD、RepositoryIndex 规范 Java 文件数以及 small/medium 唯一性。

模型契约冻结为 provider `openlux`、exact model ID `claude-opus-5`、OpenAI protocol、`TOOL_CALL` structured output、temperature 0、max output 2048、seed omitted。`base_url` 是 `https://api.openlux.ai/v1`，exact `endpoint_url` 是服务声明的 OpenAI POST endpoint `https://api.openlux.ai/v1/chat/completions`。runner 要求 `endpoint_mode=EXACT` 且逐字段匹配冻结配置，client 直接使用完整 URL，不在运行时拼接路径。

每项目自动检查：round 1 是否实际完成 `SEARCH_CODE`/`SEARCH_SYMBOLS`；tool calls 是否至少 2 次；是否至少产生 1 条经 schema/parser 接受的 proposal；是否至少进入 Gate 1 次；每个 `NEEDS_MORE_EVIDENCE` 后是否存在实际 tool result；detector input manifest、artifact contract 与 secret/no-leakage 是否通过；每个 model call 是否被带显式 StructuredOutputNormalizer provenance 的 action 或明确 retry/failure 完整记账。只有两个项目全部通过才写 `freeze_allowed=true`；不要求形成 candidate path，也不运行 benchmark evaluator。

本地验证（2026-08-31）：机制测试构造 1-file SMALL 与 100-file MEDIUM 项目，分别完成 2 个 repository tools、1 个 schema-valid proposal、1 次 Gate，并验证 API key 不进入任何 artifact。修复 seed 缺省语义、HTTP 状态审计和 V022 revision 后，targeted 14 passed；full 252 passed、2 skipped；compileall 与 `diff --check` 通过。真实 Cloud run 结果必须单独记录，不能用 mock 结果替代。

CloudStudio 诊断尝试（均未读取 benchmark answer，也未进入 F7）：

- attempt 1，detector commit `3902ee8`：在模型调用前因环境缺省 seed 被客户端静默解释为 `0`、与冻结 `null` 不一致而 fail-closed。提交 `66ec477` 将未配置 seed 确定性保留为 `None`，并补回归测试。
- attempt 2，detector commit `66ec477`：V011 首轮 exact-base POST 返回 transport failure，0 tool call、0 proposal；独立最小探针确认 `POST https://api.openlux.ai/v1` 返回 HTTP 400。V022 在模型调用前发现冻结 revision 两字符转置；真实 Git HEAD 为 `2e8694c6beb3bdbb2645b882eba72ce41bc63242`。提交 `c8e00ad` 修正该身份并让 HTTP 状态以不含响应体/凭据的形式进入失败 artifact。
- 根据服务公开的接口契约，后续尝试使用 exact OpenAI endpoint `/v1/chat/completions`；这只是冻结完整 URL，不允许 client 在运行时猜测或拼接路径。attempt 1/2 的目录和日志继续保留，不覆盖。

- M7-F7 至 M7-F10：待前置阶段通过后执行。
