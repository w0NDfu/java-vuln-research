# Work1 V11 M4：Security Proposal IR 与 Evidence Gate

## 1. M4 在 Work1 中的位置

M1–M3 只建立可追溯的 program facts：`ProgramEntity`、repository relations/tools 与有界 CodeQL facts。M4 在这些事实之上增加第一层安全语义，但只允许提出和准入 **security semantic hypothesis**。M4 不实现 Agent、LLM 自动找漏洞、sanitizer/protection 最终判定、Hybrid Vulnerability Path、正式漏洞检测或 benchmark 评价。

本阶段的边界是：统一表达 proposal，并判断它是否有足够真实、局部、可解析的程序证据进入 M5。`Proposal != confirmed fact`，`ADMISSIBLE != vulnerability confirmed`，CodeQL `EMPTY`/不可用不等于 proposal 为假，`model_confidence` 也不等于 evidence。

## 2. Proposal IR 与稳定身份

`SecurityProposal` 固定包含 `proposal_id`、`proposal_type`、`subject`、可选 `source/target`、`scope`、可选 `semantic_category`、`evidence_refs`、`reason`、可选 `model_confidence` 与 `provenance`。Schema 位于：

- `schemas/security_proposal.schema.json`
- `schemas/evidence_ref.schema.json`
- `schemas/evidence_gate_result.schema.json`

proposal/evidence ID 都由 canonical JSON 的 SHA-256 前 24 个十六进制字符生成；确定性输入中没有 timestamp。序列化对 key 排序并使用稳定 JSONL，因此同一结构跨运行得到相同 ID 和字节表示。`reason` 与 `model_confidence` 被保留用于审计，但不参与 admission 决策。

V1 proposal type 严格只有七种：

| 类型 | 表达内容 |
|---|---|
| `EXTERNAL_INPUT` | 一个值可能受项目外部环境影响 |
| `SECURITY_EFFECT` | 一个行为可能产生安全相关副作用 |
| `WRAPPER_FLOW` | 项目 wrapper 内显式、局部的角色间传播 |
| `LIBRARY_FLOW` | 某个 library/member scope 内的局部传播假设 |
| `FIELD_STATE` | write anchor → 唯一 field → read anchor 的状态关系 |
| `FRAMEWORK_RELATION` | binding、DI、lifecycle 等框架中介关系 |
| `CALLBACK_RELATION` | registration、callback entity 与相关数据角色关系 |

无法由这七种表达的场景返回 `UNSUPPORTED`/`UNSUPPORTED_PROPOSAL_TYPE`，不临时增加项目专用类型。`EXTERNAL_INPUT` 与 `SECURITY_EFFECT` 的 category 是 proposal 描述，不是 API 识别规则；`UNKNOWN` 和 `OTHER` 合法。

## 3. Role system

Role 固定为 `ENTITY`、`PARAMETER`、`ARGUMENT`、`RETURN`、`CALL_RESULT`、`RECEIVER`、`FIELD`、`FIELD_READ`、`FIELD_WRITE`、`CALL`、`METHOD`、`CONSTRUCTOR`。每个 anchor 使用 `entity_id + role + optional index`，不能退化为仅写两个方法名。

Validator 会依据 `ProgramEntity.kind`、callable parameter count 和 call argument count 检查 role：`ARGUMENT/PARAMETER` 必须有存在的 index，`RETURN` 只适用于 callable，`CALL_RESULT` 只适用于 call，field roles 只适用于 field/相应访问锚点。`FIELD_STATE` 要求 write、field、read 三个明确 anchor；字段不能唯一定位时为 `NEEDS_MORE_EVIDENCE`，不会按同名字段猜测。

## 4. EvidenceRef

M4 evidence source kind 固定支持：`SOURCE_SNIPPET`、`PROGRAM_ENTITY`、`REPOSITORY_RELATION`、`REPOSITORY_TOOL_RESULT`、`CODEQL_ENTITY_FACT`、`CODEQL_CALL`、`CODEQL_LOCAL_FLOW`、`CODEQL_DATAFLOW`、`CODEQL_CFG`、`TYPE_DECLARATION`、`ANNOTATION_TEXT`。网络和外部 library/framework documentation 不在本阶段。

每条 `EvidenceRef` 保存稳定 `evidence_id`、source kind、关联 entity IDs、repository-relative path、可用时的行范围、tool call ID、artifact/result reference、content/result hash、confidence、strength 与 provenance。strength 为 `DIRECT`、`STRONG_STRUCTURAL`、`SUPPORTING`、`WEAK`；只有直接源码定义、明确结构事实或 CodeQL-confirmed fact 可成为 `DIRECT`。自然语言 reason 不是 evidence。

## 5. Proposal Admission Gate

`EvidenceGate` 依次产生可审计 checks：schema validity、entity existence/no fabricated entity、location validity、role compatibility、evidence resolution、evidence locality、scope bound、duplicate/native support、evidence sufficiency。结果只使用：`ADMISSIBLE`、`NEEDS_MORE_EVIDENCE`、`REJECTED`、`DUPLICATE`、`ALREADY_SUPPORTED`、`UNSUPPORTED`。

- 不存在的 entity/file/tool call/evidence ID、非法 role/index、完全不相关证据和无边界 wildcard 被拒绝。
- 只有自然语言理由或字段锚定仍有歧义时要求更多证据。
- 同批重复关系为 `DUPLICATE`；已有确定性 CodeQL native relation 为 `ALREADY_SUPPORTED`，不会重复加入 overlay。
- 所有 check、resolved/missing evidence、warning、rejection reason 和 provenance 都写入 `gate_results.jsonl`。

Gate 验证 proposal 是否 grounded，不生成 proposal。实现和测试明确禁止 `KNOWN_SOURCE_APIS`、`KNOWN_SINK_APIS`、`HTTP_REQUEST_TYPES`、`DANGEROUS_METHOD_NAMES`、`SPRING_SOURCE_RULES`、`CWE22_RULES` 等 Route B 固定规则，也没有 `methodName == exec` 一类方法名推断。因此 M4 没有把 admission gate 变成另一套 source/sink detector。

## 6. CodeQL 是可选证据，不是准入前提

Repository/source facts 与 CodeQL facts 分开解析。足够的源码定义、M1 entity、M2 repository relation/tool result 可以形成 `REPOSITORY_ONLY` admission；有成功、可绑定的 M3 tool call 时形成 `CODEQL_ASSISTED` admission，并保留较强 evidence。没有 CodeQL evidence、CodeQL `EMPTY` 或稳定工具错误都不自动拒绝 proposal；只有“没有任何 program evidence”才不能 admission。

## 7. Controlled security fixture 与人工 proposal

fixture 为 `tests/fixtures/work1_agent_m4/src/main/java/com/example/ControlledSecurityCases.java`，覆盖 custom external-input/security-effect wrapper、`ARG0 -> RETURN`、setter → field → getter、interface/callback 和 annotation/framework-like binding。它只验证 IR/Gate 机制，不衡量漏洞检测率。

人工输入共 45 条，其中 29 条预期有效，严格满足：5 `EXTERNAL_INPUT`、5 `SECURITY_EFFECT`、5 `WRAPPER_FLOW`、3 `LIBRARY_FLOW`、5 `FIELD_STATE`、3 `FRAMEWORK_RELATION`、3 `CALLBACK_RELATION`。另外 16 条覆盖 fabricated method、wrong argument index、invalid return/field role、unrelated/missing/fabricated evidence、wildcard scope、duplicate、native support、ambiguous field 和只有自然语言 reason。

controlled 结果：

| status | count |
|---|---:|
| `ADMISSIBLE` | 29 |
| `REJECTED` | 10 |
| `NEEDS_MORE_EVIDENCE` | 4 |
| `DUPLICATE` | 1 |
| `ALREADY_SUPPORTED` | 1 |

29 条有效 proposal 全部 admission；16 条故意错误/不足 proposal 全部未 admission，non-admission rate 为 1.0。controlled evidence resolution success rate 为 0.95；该比例包含故意构造的 missing/fabricated evidence，因此不是工具可靠性或检测率。controlled 的 29 个 admission 全部为 repository-only。

按类型的 controlled 结果为：

| type | outcomes |
|---|---|
| `CALLBACK_RELATION` | ADMISSIBLE 3 |
| `EXTERNAL_INPUT` | ADMISSIBLE 5；REJECTED 6；NEEDS_MORE_EVIDENCE 3；DUPLICATE 1；ALREADY_SUPPORTED 1 |
| `FIELD_STATE` | ADMISSIBLE 5；REJECTED 1；NEEDS_MORE_EVIDENCE 1 |
| `FRAMEWORK_RELATION` | ADMISSIBLE 3 |
| `LIBRARY_FLOW` | ADMISSIBLE 3 |
| `SECURITY_EFFECT` | ADMISSIBLE 5；REJECTED 1 |
| `WRAPPER_FLOW` | ADMISSIBLE 5；REJECTED 2 |

## 8. 8-project real grounding smoke

选择规则固定为按 `project_id` 排序后的前 2 个 P、前 2 个 D、前 4 个 V：`P006`、`P007`、`D001`、`D002`、`V001`、`V002`、`V003`、`V004`。输入只来自冻结 inventory、M2 index/tool artifacts、M3 `tool_calls.jsonl` 与源码；没有读取 CVE、CWE、patch 或 benchmark vulnerability location。每项目至多 2 条 proposal，远低于 10 条上限。

| project | CodeQL ready | proposals | repository-only admitted | CodeQL-assisted admitted | outcome |
|---|---:|---:|---:|---:|---|
| P006 | yes | 2 | 1 | 1 | 2 ADMISSIBLE |
| P007 | yes | 2 | 1 | 1 | 2 ADMISSIBLE |
| D001 | yes | 2 | 1 | 1 | 2 ADMISSIBLE |
| D002 | yes | 2 | 1 | 1 | 2 ADMISSIBLE |
| V001 | yes | 2 | 1 | 1 | 2 ADMISSIBLE |
| V002 | no | 1 | 1 | 0 | 1 ADMISSIBLE |
| V003 | no | 1 | 1 | 0 | 1 ADMISSIBLE |
| V004 | yes | 2 | 1 | 1 | 2 ADMISSIBLE |

真实 smoke 共 14 条 proposal，14 条 `ADMISSIBLE`：8 个 repository-only、6 个 CodeQL-assisted。这只证明真实代码上的 entity/evidence/tool binding 能工作，不表示这些 proposal 是真实漏洞或已确认安全语义。

## 9. 合并机制指标

CloudStudio 使用实现 SHA `cd512b21bb4657ade298ea0ec9759a30257179ef` 从头运行 controlled 与 real smoke，退出码为 0。顶层 artifact 位于 `/workspace/experiment-output/artifacts/work1-agent-v11/m4_proposals/`：

- `proposals.jsonl`：59 行
- `gate_results.jsonl`：59 行
- `evidence_index.jsonl`：48 行
- `failures.jsonl`：16 行
- `summary.json`
- `controlled_fixture/`、`real_project_smoke/`、`d003_resolution/`

合并 status：`ADMISSIBLE=43`（0.728814）、`REJECTED=10`（0.169492）、`NEEDS_MORE_EVIDENCE=4`（0.067797）、`DUPLICATE=1`（0.016949）、`ALREADY_SUPPORTED=1`（0.016949）。admission basis 为 repository-only 37、CodeQL-assisted 6。

合并 proposal type count：`EXTERNAL_INPUT=30`、`SECURITY_EFFECT=6`、`WRAPPER_FLOW=7`、`LIBRARY_FLOW=3`、`FIELD_STATE=7`、`FRAMEWORK_RELATION=3`、`CALLBACK_RELATION=3`。这里不报告 Detection Rate；`summary.json` 将其保留为 `null` 并明确说明没有执行漏洞评价。

## 10. D003 resolution

M3 的 12 个 D003/XStream 1.4.6 exit-100 错误历史上记录为 `QUERY_COMPILE_ERROR`。M4 检查实际完整 query log 后发现：QL 已编译完成并进入 evaluation，随后 `ExtensionalLoader`/`TuplePool` 在读取 `db-java/default/cache/cached-strings/tuple-pool` 时报告 invalid checksum。因此根因分类为：

- corrected failure reason：`DB_CACHE_CORRUPTION`
- resolution category：`DB/LANGUAGE_VERSION_LIMITATION`
- 分布：`codeql_cfg_neighbors=3`、`codeql_dataflow_neighbors=6`、`codeql_local_flow=3`
- `GENERIC_QUERY_BUG=false`，不触发“修 query 后对另外 2 DB 回归”的条件分支
- 无 `if project == "D003"`，无项目专用补丁

通用 classifier 现在先识别 invalid-checksum/pool-file corruption，再判断 compile failure，并移除了把正常 `Compiling query plan` 进度文本当错误的逻辑。12 条保存诊断重放结果均为 `DB_CACHE_CORRUPTION`。`d003_resolution/` 保存 `failure_index.jsonl`、`summary.json`、`classification_replay.json`、12 份逐调用 failure log 及 SHA-256 清单；另保留完整 D003 call artifact 副本用于追溯。

D003 仍能在真实 smoke 中以 repository evidence admission，同时成功的 CodeQL entity fact 也可单独成为辅助 evidence。flow/CFG cache error 只代表该证据来源缺失，不会把其他 program evidence 变成反证。

## 11. Tests 与回归

测试覆盖稳定 ID、七类有效 proposal、entity/role/index/location/locality/scope 错误、missing/fabricated evidence、duplicate/native support、CodeQL unavailable + repository evidence、confidence 不绕过 gate、稳定序列化、provenance、controlled exact outcomes、8-project deterministic smoke、禁止固定 Route B 规则，以及 D003 classifier regression。完整测试结果为 `127 passed, 2 skipped`；M1/M2/M3 无回归。

## 12. Known limitations

- M4 只判断可追溯性、局部一致性和证据充分性；不证明 proposal 正确，更不证明 vulnerable/safe。
- 实际 real smoke proposal 由确定性脚本构造，尚未评价未来 Agent proposal 的质量、召回或分布漂移。
- CodeQL-assisted smoke 使用已有 M3 entity facts；没有为 M4 运行无界查询或重建 DB。
- V1 relation 必须绑定 entity/local callable/explicit field/framework relation；跨模块长路径和 package/repository wildcard 明确不支持。
- framework/callback semantics 目前只接受可定位 annotation、signature、type/repository relation，不使用外部文档。
- evidence resolution success rate 会被测试集中的故意坏证据影响，不能跨数据集解释为准确率。
- D003 的损坏/不兼容 cache 没有重建；M4 只修正分类与语义隔离。

## 13. M5 handoff contract

M5 可以只消费 `ADMISSIBLE` proposal，并必须保留 proposal ID、每个 role anchor、resolved evidence IDs、strength、gate checks、artifact hashes、admission basis 和 provenance。`DUPLICATE`/`ALREADY_SUPPORTED` 不应重复创建 semantic overlay；`NEEDS_MORE_EVIDENCE`/`REJECTED`/`UNSUPPORTED` 不进入 graph。M5 不得把 admission status 改写为 truth、vulnerability 或 safety 标签，也不得把 CodeQL absence 当作 negative edge。

M4 成功标准均已满足：七类假设统一表达；M1/M2/M3 evidence 可解析；repository-only admission 已在无 CodeQL 的 V002/V003 和 D003 行为中验证；CodeQL evidence strength/provenance 被保留；非法实体/role/范围/证据不能通过；Gate 没有固定 source/sink 规则；所有结果可审计。建议 **`PROCEED_M5`**，但本提交在 M4 完成后停止，不启动 M5。
