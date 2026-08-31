# Work1 V11 M7：Autonomous Security Exploration Agent

## 结论

M7-F1 至 M7-F10 已完成。新的正式 M7 运行在 CloudStudio 上对原冻结的 10 个 baseline-miss 项目执行了真实模型 detector；10/10 项目 setup-ready，10/10 进入模型与工具循环，detector 全部结束并完成 hash freeze 后才运行 evaluator。正式结果为 0/10 autonomous recovery，因此按预注册条件不执行 E1/E2/E3 ablation、不启动 Work2。

这个 0-recovery 结果不再由旧运行的 transport/parser/setup 工程故障主导：全部项目均进入模型循环；79 次 model calls 中 77 次形成严格 schema action，另外 2 次歧义输出被明确拒绝并有界修复；合法 symlink source roots 全部通过 runtime boundary；140 个 detector 文件的 post-freeze no-leakage audit 通过。剩余失败集中在安全 effect/语义关系发现、repository relation 能力、Gate scope/role 约束和后续 path connectivity。

旧的正式 0-recovery 运行及其工程失败产物继续保留在 `07_AUTONOMOUS_SECURITY_EXPLORATION_AGENT.md`，没有删除或改写。本文件只报告修复后的新运行。

## 正式运行身份

| 项目 | 冻结值 |
|---|---|
| detector Git SHA | `07ec7767825bae72ba0d9b8591e058f558b1ffa9` |
| detector input manifest | `m7detector-9e40adaad7b93a8796c23298` |
| provider / exact model | `openlux` / `claude-opus-5` |
| base URL | `https://api.openlux.ai/v1` |
| exact endpoint / protocol | `https://api.openlux.ai/v1/chat/completions` / `OPENAI` |
| structured output | `TOOL_CALL`, temperature `0`, max output `2048`, seed `null` |
| normalizer | `M7_STRUCTURED_OUTPUT_NORMALIZER_V1` |
| prompt | `M7_SECURITY_EXPLORATION_V9`, SHA-256 `1fcb84f7b658026d9db3959d7a8e8c527b14b089eb5fcb5bd31797291b7af8ad` |
| controller | `M7_CONTROLLER_V3`, stagnant rounds `3`, output repairs `2` |
| observation | schema `2`; bootstrap `16384` chars; tool-grounded `24576` chars |
| tool catalog SHA-256 | `b8e2921b283f51f3ef75050a3f19f1e5802d4a297121ac6d9829acd8bb3f2aa4` |
| path bounds | depth `12`, paths `20`, expanded nodes `2000` |

每项目预算冻结为 15 rounds、每轮最多 4 个 tool calls、总计最多 40 个 tool calls、每轮最多 1 个 proposal、每项目最多 10 个 proposals 和 8 个 admissible proposals。11 个 schema 的 SHA-256、M1--M5 artifact tree、CodeQL `2.26.3` baseline lineage、lexical source root 与 `M7_RESOLVED_SOURCE_ROOT_SHA256_V1` resolved-root identity 均写入 manifest。detector 启动时逐项 fail-closed 校验 Git SHA、模型、prompt、normalizer、observation、controller、tool catalog、schemas 和 source identities。

F7 共保留三个不作为 detector 输入的审计尝试：第一次缺显式 normalizer/observation 字段；第二次缺 resolved-root identity；第三次使用 plaintext resolved root 时因路径包含 selection case 标识而被 no-leakage 审计拒绝。正式第四次 freeze 使用不可逆 resolved-root identity，并在 detector 启动时从 lexical root 重算比对。没有覆盖旧目录，也没有为通过审计而关闭规则。

## 冻结 cohort 与逐项目结果

| project | case | rounds | model | repo tools | proposals | Gate | input / output tokens | wall-clock (s) | stop | failure taxonomy |
|---|---|---:|---:|---:|---:|---|---:|---:|---|---|
| D003 | xstream CVE-2013-7285 | 4 | 5 | 3 | 0 | -- | 305337 / 1174 | 53.712 | INSUFFICIENT_EVIDENCE | input, effect, semantic relation, repository tool |
| P006 | xstream CVE-2021-21345 | 4 | 5 | 3 | 0 | -- | 198069 / 1243 | 55.686 | INSUFFICIENT_EVIDENCE | input, effect, semantic relation, repository tool |
| P007 | AntiSamy CVE-2016-10006 | 11 | 11 | 9 | 1 | REJECTED 1 | 1108820 / 2339 | 105.201 | INSUFFICIENT_EVIDENCE | effect, semantic relation, repository tool, Gate, path |
| P010 | spring-security-oauth CVE-2018-1260 | 8 | 8 | 5 | 2 | REJECTED 2 | 522113 / 2084 | 111.899 | INSUFFICIENT_EVIDENCE | effect, semantic relation, repository tool, Gate, path |
| P012 | cron-utils CVE-2021-41269 | 8 | 8 | 7 | 0 | -- | 531074 / 1299 | 76.194 | INSUFFICIENT_EVIDENCE | input, effect, semantic relation, repository tool |
| V001 | Retrofit CVE-2018-1000850 | 3 | 3 | 2 | 0 | -- | 228115 / 643 | 31.227 | INSUFFICIENT_EVIDENCE | input, effect, semantic relation |
| V004 | plexus-archiver CVE-2018-1002200 | 14 | 14 | 12 | 1 | REJECTED 1 | 1779194 / 3022 | 137.429 | BUDGET_EXHAUSTED | input, effect, repository tool, Gate, path, budget |
| V005 | zip4j CVE-2018-1002202 | 9 | 9 | 7 | 1 | REJECTED 1 | 1144283 / 1986 | 91.259 | INSUFFICIENT_EVIDENCE | effect, semantic relation, repository tool, Gate, path |
| V009 | commons-io CVE-2021-29425 | 4 | 4 | 3 | 0 | -- | 379849 / 742 | 42.110 | INSUFFICIENT_EVIDENCE | input, effect, semantic relation |
| V023 | vertx-web CVE-2019-17640 | 12 | 12 | 11 | 0 | -- | 943796 / 2409 | 123.933 | BUDGET_EXHAUSTED | input, effect, semantic relation, repository tool, budget |

所有 10 个 case 均为 frozen baseline miss，`benchmark_informed=false`；每个项目 candidate paths、matched paths 和 autonomous recovery 均为 0，matching granularity 为 `NONE`。表中的 case 信息只由 post-freeze evaluator 加入，没有进入 detector manifest、prompt、observation 或 trace。

## Aggregate metrics

| metric | result |
|---|---:|
| frozen baseline-miss projects | 10 |
| setup-ready / model-loop-entered | 10 / 10 |
| rounds | 77 |
| model calls | 79 |
| successful normalized actions | 77 |
| normalization modes | `FENCED_JSON: 77` |
| invalid/ambiguous structured outputs | 2（均为 `STRUCTURED_OUTPUT_AMBIGUOUS`，有界重试） |
| repository / CodeQL tool calls | 62 / 0 |
| inspect calls / unique inspected entities | 37 / 31 |
| EvidenceRefs | 496 |
| proposals | 5（`EXTERNAL_INPUT: 4`, `FIELD_STATE: 1`） |
| Gate ADMISSIBLE / NEEDS_MORE_EVIDENCE / REJECTED | 0 / 0 / 5 |
| Gate DUPLICATE / ALREADY_SUPPORTED | 0 / 0 |
| candidate / matched paths | 0 / 0 |
| autonomous recovery | 0 / 10 = 0.0% |
| average input / output tokens per project | 714065 / 1694.1 |
| total wall-clock / average per project | 828.650 s / 82.865 s |

Repository tool distribution 为 `SEARCH_SYMBOLS 13`、`SEARCH_CODE 1`、`INSPECT_METHOD 32`、`INSPECT_TYPE 5`、`GET_CALLERS 6`、`GET_IMPLEMENTATIONS 2`、`GET_OVERRIDES 2`、`GET_FIELDS 1`。没有发起 CodeQL action，因此不存在 CodeQL-assisted recovered path；repository-only recovered path 同样为 0。不得把这个结果报告为完整 benchmark Detection Rate、Avg FDR 或 Avg F1。

## Proposal、Gate 与 path 解释

5 个 proposal 全部经过正式 M4 `EvidenceGate`，没有绕过：

- P007、P010 的两次和 V005 共 4 个 `EXTERNAL_INPUT` proposals，schema、entity、location、role、EvidenceRef resolution/locality 全部通过，但 `SCOPE_BOUND` 以 `SCOPE_DOES_NOT_BOUND_ALL_ANCHORS` 拒绝；
- V004 的 `FIELD_STATE` proposal 在 `ROLE_COMPATIBILITY` 以 `FIELD_STATE_ANCHORS_REQUIRED` 拒绝；
- 因此 proposal acceptance rate 为 0%，rejection rate 为 100%；没有 ADMISSIBLE proposal edge，graph/path builder 没有形成 candidate path；
- recovered path 为 0，counterfactual attribution 状态为 not applicable；recovered proposal-type contribution 和 recovered path support composition 均为空。

`ADMISSIBLE` 从未被当作 confirmed relation，candidate path 也从未被解释成漏洞。没有 direct input-to-effect shortcut，没有把 lexical call 当 runtime dataflow，也没有生成任意 QL。

## Failure taxonomy 与 root cause

| failure class | projects |
|---|---:|
| AGENT_FAILED_TO_FIND_EFFECT | 10 |
| AGENT_FAILED_TO_FIND_SEMANTIC_RELATION | 9 |
| REPOSITORY_TOOL_LIMITATION | 8 |
| AGENT_FAILED_TO_FIND_INPUT | 7 |
| GATE_BLOCKED | 4 |
| PATH_NOT_CONNECTED | 4 |
| BUDGET_EXHAUSTED | 2 |
| protocol/model-output fatal、CodeQL unavailable/alignment、OTHER | 0 |

分层判断如下：

- protocol failure：已修复。79 个 model calls 全部由 77 个规范 action 或 2 个明确 ambiguous retry 记账；没有首轮 parser/setup 崩溃，taxonomy 中 `MODEL_OUTPUT_INVALID=0`。
- tool discovery：repository discovery 确实发生（62 calls、37 inspections、496 EvidenceRefs），但模型从未选择 6 个固定 CodeQL tools，且 8 个项目出现 repository relation limitation。这是剩余能力缺口，不是工具循环未启动。
- entity alignment：正式 taxonomy 中 CodeQL entity-alignment failure 为 0；进入 Gate 的 proposals 均通过 entity existence/no-fabrication/location checks。当前阻塞不再是早期的 fabricated/wrong-role entity。
- evidence/proposal：模型只提出 input anchor 与一个 field-state relation，10/10 没有找到 security effect，9/10 没有形成所需语义关系；这是最主要的 reasoning/evidence discovery 失败。
- Gate：5 个 proposals 均因正式 scope/role 约束被拒绝。不能降低 Gate 标准来制造 recovery。
- path connectivity：没有 ADMISSIBLE anchors/relations，因而 0 path；4 个已提出 proposal 的项目被归类为 `PATH_NOT_CONNECTED`，这是上游 proposal/Gate 失败的结果。
- model reasoning stalled：taxonomy 中显式 `MODEL_REASONING_STALLED=0`，但两个项目耗尽预算，其余在证据不足时保守停止。更精确的结论是 effect/semantic discovery 不足，而不是 transport 故障或未进入循环。

## No-leakage、native preservation 与 artifact audit

post-freeze evaluator 扫描 140 个 detector files：forbidden selected-value hits、secret hits、runtime boundary violations、fail-closed denied inputs 和 unverified inputs 均为空，`no_leakage_pass=true`。10 个项目的 runtime input audit 和 artifact contract 全部通过；合法 symlink source roots 没有再因 `annotations`/`datasets` 路径词被误伤。`native_preservation_pass=true`。

关键冻结 hash：

| artifact | SHA-256 |
|---|---|
| frozen detector input | `66056b12ee4a51fc43916080635ba0fcfb83338d5c7eb0288c4654810c7138dd` |
| detector summary | `f3c4b6021dcc7a3a428bd8bd19950245acb32c2c46ada0e6e00c608f31431f6c` |
| detector output manifest | `0a16123f9f03fe7b080356dc1574b10370c606bfcea79ee2cd51d1d00410287d` |
| selection manifest | `4e7df3e955b77f6c575e6eec59109302244d518516863ccbe34755c110c4a6b7` |
| aggregate summary | `db44658e5f261cc76f0f4634f33c2171dfed8c959f46be73098bbab8a13d843f` |
| selected cases CSV | `4781f33ac69b879848427edff4e8476fbae0ac548758623de02cafadb151ccf6` |
| failure taxonomy | `bfa8f8d9195da1a23d9ec683b4a8111432df31335fc0dabcb0dcf127e33fa8d0` |
| evaluator no-leakage audit | `5def7569cf6b3610ac52086f60834e6a4aacd1b5ac82c926eb6ec312b33c1dee` |
| evaluator artifact audit | `31f319703d8dc8334a836f483ef3f4c594d32c00a19610db31a1a2c778599e4d` |

CloudStudio authoritative roots：

- freeze：`/workspace/experiment-output/artifacts/work1-agent-v11/m7_agent/runs/07ec7767825bae72ba0d9b8591e058f558b1ffa9/killtest_freeze`
- detector + evaluator：`/workspace/experiment-output/artifacts/work1-agent-v11/m7_agent/runs/07ec7767825bae72ba0d9b8591e058f558b1ffa9/killtest`

`artifact_audit.json` 记录 `required_files_present=true`、`project_contract_pass=true`、`detector_freeze_validated=true`、project count 10。evaluator manifest 记录 `m7_11_required=false`，与 0 recovery 的 ablation 门槛一致。

## Ablation 和后续阶段决定

E1/E2/E3 ablation 的前置条件是正式 M7 至少出现 1 个 autonomous recovery。本次为 0，因此没有运行、也没有伪造 counterfactual/ablation 结果。Work2 不启动。

下一轮研究若继续，必须作为新的预注册实验解决通用能力问题：提高 effect/semantic relation discovery、让模型实际利用固定 CodeQL tools、改善 scope 构造反馈或提供不改变 Gate 标准的可执行 scope guidance。不得基于这 10 个 benchmark answer 修改当前冻结配置，也不得覆写本次 artifacts。
