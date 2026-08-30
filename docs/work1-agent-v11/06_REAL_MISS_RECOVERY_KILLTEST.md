# Work1 V11 M6：Real Baseline-Miss Semantic Recovery Kill Test

## 1. M6 scientific purpose

M6 是 Work1 V11 第一次面向真实 benchmark 漏检实例的机制能力测试。它回答的唯一核心问题是：当冻结 CodeQL baseline 没有检出真实漏洞时，如果由诊断侧提供最小、可定位、能通过 M4 Evidence Gate 的缺失安全语义，M1-M5 是否能构造一条 baseline 中不存在且与 benchmark 标注一致的 input-to-effect Candidate Path。

本轮 canonical 云端产物根为：

`/workspace/experiment-output/artifacts/work1-agent-v11/m6_killtest/`

实验在 CloudStudio `/workspace/java-vuln-research` 上执行，实验代码 Git SHA 为 `ec4e64ba0b9c3eb200705ae8d7239246c77bd5d4`。最终 artifact audit 为 `PASS`：10 个 selected case 全部审计，9 个恢复，`violations=[]`。

## 2. Why M6 is not autonomous detection

M6 没有实现 Agent，没有 runtime LLM、prompt、memory、planning 或 tool-selection policy。proposal 由可读取 benchmark 修复信息的诊断侧离线生成，因此结果只能称为 `Mechanism Recovery Count/Rate`，不能计入 `#Detected`、Detection Rate、Avg FDR 或 Avg F1。

M6 的结论是“若正确的缺失语义假设已经可用，当前机制能否表达并因果性地恢复路径”，不是“系统能否自主发现该语义”。自主发现能力属于 M7，本轮没有启动 M7。

## 3. Information separation

信息域按文件系统和模块同时隔离：

- diagnostic side：读取 benchmark/修复函数压缩输入，只写 `diagnostic_proposals/` 和每 case 的 `diagnostic_analysis.json`；所有 proposal 均标记 `proposal_origin=BENCHMARK_INFORMED_DIAGNOSTIC`、`benchmark_informed=true`、`allowed_for_agent_runtime=false`、`eligible_for_detection_metric=false`。
- detector side：只消费源码、M1 ProgramEntity、M2 repository evidence、已有 M3 artifacts 和显式 proposal JSON；`detector.py` 不导入 diagnostic 或 evaluator 模块，不读取 CVE、CWE、patch 或 benchmark location。
- evaluator side：只在 detector manifest、输出和 hashes 冻结后读取 benchmark annotation；`evaluation_started_after_detector_freeze=true`。

`diagnostic_proposals/manifest.json` 绑定诊断输入路径、SHA-256、hint 数量和禁止 runtime 使用的标志；每个 case 另有独立 proposal 副本，避免把 benchmark-informed 数据混入后续 Agent 输入。

## 4. Eligible case inventory

自动 inventory 由冻结 baseline coverage、M1 project inventory、filesystem、CodeQL DB 状态和 benchmark annotation 联合生成，不根据目录名猜测。共发现 12 个可审计 benchmark case；D001、D002 已被 baseline 检出而排除，余下 10 个全部满足 `source_ready=true`、`db_ready=true`、`baseline_detected=false`、`annotation_available=true`。

| project | case | revision | CWE | match granularity | baseline | M6 eligible | exclusion |
|---|---|---|---|---|---|---:|---|
| D001 | Spark 2.5.1 / CVE-2016-9177 | `UNKNOWN` | CWE-022 | METHOD | detected | false | `BASELINE_DETECTED` |
| D002 | Spark 2.7.1 / CVE-2018-9159 | `UNKNOWN` | CWE-022 | METHOD | detected | false | `BASELINE_DETECTED` |
| D003 | XStream 1.4.6 / CVE-2013-7285 | `768c6e417a75e7732fc591bee844e5e81af56a7d` | CWE-078 | METHOD | miss | true | — |
| P006 | XStream 1.4.15 / CVE-2021-21345 | `f04bbec461f2c2a6f1e2cf41770f42c64aae24a4` | CWE-078 | METHOD | miss | true | — |
| P007 | AntiSamy 1.5.3 / CVE-2016-10006 | `8bebe1eb2ec1ac23e34111e9d06024d7dab7fa25` | CWE-079 | METHOD | miss | true | — |
| P010 | spring-security-oauth 2.3.2.RELEASE / CVE-2018-1260 | `97e39dde7e88aae802be98de084a382886ca4255` | CWE-094 | METHOD | miss | true | — |
| P012 | cron-utils 9.1.5 / CVE-2021-41269 | `34493c66edb490396202edad66c5f8cc5717d494` | CWE-094 | METHOD | miss | true | — |
| V001 | square/retrofit 2.4.0 / CVE-2018-1000850 | `7158698314daa138e993fac6a590ed19d78a8599` | CWE-022 | METHOD | miss | true | — |
| V004 | plexus-archiver 3.5 / CVE-2018-1002200 | `b9f9a425865eb47fb3665b3144ee4ca11f402704` | CWE-022 | METHOD | miss | true | — |
| V005 | zip4j 1.3.2 / CVE-2018-1002202 | `d87ffa2d64ffb3a0a1cf0c7a69c7b19d7015bfde` | CWE-022 | METHOD | miss | true | — |
| V009 | commons-io 2.6 / CVE-2021-29425 | `2ae025fe5c4a7d2046c53072b0898e37a079fe62` | CWE-022 | METHOD | miss | true | — |
| V023 | vertx-web 3.9.3 / CVE-2019-17640 | `2146b7240096e25b40bb1acc083fa7ec79330989` | CWE-022 | METHOD | miss | true | — |

详细字段保存在 `case_inventory.csv`，包括 source root、DB path、ready 状态、baseline 状态、annotation 状态、eligibility 和 exclusion reason。

## 5. Deterministic selection

eligible 数量为 10，小于 12 的硬上限，因此全部入选。选择在 proposal 构造前冻结，并严格按 `project_id`、`case_id` 排序：

`D003, P006, P007, P010, P012, V001, V004, V005, V009, V023`

10 个 case 来自 10 个不同 project；没有因为某个 case 看起来容易恢复而进行人工筛选。选择结果和顺序保存在 `selected_cases.csv`。

## 6. Frozen E0

E0 使用既有 Route B 冻结 run：

`/workspace/experiment-output/artifacts/work1/p0_b_route_b/W1-P0-B-ROUTE-B-20260827-002/`

CodeQL CLI 为 2.26.3。每个 `baseline.json` 绑定 command template、query paths/hashes、output paths/hashes、run manifest hash、coverage record hash、DB identity/path、source revision 和 CodeQL version。所有 10 个 selected case 均满足：

- `baseline_detected=false`；
- `baseline_alert_or_path_ids=[]`；
- `native_candidate_covered=false`；
- `unified_candidate_covered=false`；
- `baseline_query_unchanged=true`。

因此本轮 10 个 case 均属于 `NO_USEFUL_BASELINE_PARTIAL_PATH`；没有通过修改 native/Route B query 制造恢复。

## 7. Diagnostic root-cause method

诊断侧只用 benchmark 信息定位最小缺失语义，再映射回真实 M1 ProgramEntity 和源码 EvidenceRef。映射采用通用实体索引与稳定 entity ID，核心实现中不存在 project/case 条件分支。

| project | diagnostic cause | mapped callable |
|---|---|---|
| D003 | `WRAPPER_OR_LIBRARY_FLOW_MISSING` | `com.thoughtworks.xstream.XStream.buildMapperDynamically` |
| P006 | `WRAPPER_OR_LIBRARY_FLOW_MISSING` | `com.thoughtworks.xstream.XStream.alias` |
| P007 | `FRAMEWORK_OR_CALLBACK_RELATION_MISSING` | `MagicSAXFilter.startElement` |
| P010 | `FRAMEWORK_OR_CALLBACK_RELATION_MISSING` | `DefaultOAuth2RequestAuthenticator.authenticate` |
| P012 | `FRAMEWORK_OR_CALLBACK_RELATION_MISSING` | `CronParser.parse` |
| V001 | `WRAPPER_OR_LIBRARY_FLOW_MISSING` | `RequestBuilder` constructor |
| V004 | `WRAPPER_OR_LIBRARY_FLOW_MISSING` | `AbstractUnArchiver.extractFile` |
| V005 | `WRAPPER_OR_LIBRARY_FLOW_MISSING` | `Unzip.initExtractFile` |
| V009 | `UNCERTAIN` | no grounded callable mapping |
| V023 | `FRAMEWORK_OR_CALLBACK_RELATION_MISSING` | `StaticHandlerImpl.handle` |

V009 的诊断输入没有可用修复函数投影，系统没有把 benchmark target 强行映射成 proposal，而是停止于 `INSUFFICIENT_PROGRAM_EVIDENCE`。

## 8. Minimal proposals

replay 从一个 proposal 开始，只有前一步不能形成 benchmark-consistent path 时才加入下一条。本轮 9 个可恢复 case 的最终序列均为 3 条：

- D003、P006、V001、V004、V005：`EXTERNAL_INPUT + LIBRARY_FLOW + SECURITY_EFFECT`；
- P007、P010、V023：`EXTERNAL_INPUT + CALLBACK_RELATION + SECURITY_EFFECT`；
- P012：`EXTERNAL_INPUT + FRAMEWORK_RELATION + SECURITY_EFFECT`；
- V009：0 条 proposal，因程序证据不足停止。

每 case 实际 proposal 上限为 3，低于任务硬上限 5。没有逐 native dataflow step 编码 proposal，没有 repository-wide wildcard，没有 direct line-to-line benchmark shortcut。

## 9. Evidence Gate

9 个恢复 case 的 27 条 proposal 全部经过正常 M4 Gate，状态均为 `ADMISSIBLE`。Gate 校验真实实体、value role、EvidenceRef、scope 和结构真实性；benchmark-informed 身份不绕过 Gate。V009 没有足够证据形成 proposal，因此 Gate input 为空，不通过放宽 Gate 获取路径。

汇总结果：`gate_blocked_count=0`。逐 proposal 的稳定 ID 和 Gate status 保存在每 case 的 `gate_results.jsonl` 与 aggregate `proposal_results.jsonl`。

## 10. Incremental replay

每个 case 执行同一 replay：E0 → P1 → P1+P2 → P1+P2+P3。9 个 case 均在 step 3 首次恢复；step 1 和 step 2 不满足完整 input-to-effect 与 benchmark method-level match。V009 在 proposal 构造前因证据不足终止。

detector 依次构建 graph nodes、graph edges 和 bounded candidate paths；输出冻结后 evaluator 才运行。每 case 的 `summary.json`、`evaluation.json` 和 manifest 记录 recovered step、matched path 及 freeze 状态。

## 11. Recovery criterion

本轮只有同时满足以下条件才计为 mechanism recovery：

1. 冻结 E0 是 miss；
2. M6 新生成完整 input-to-effect path；
3. detector output 先冻结并通过 hash 校验；
4. 独立 evaluator 在明确的 METHOD granularity 上与 benchmark annotation 一致；
5. path 可归因到 M6 proposal；
6. 每条 proposal/edge/entity/EvidenceRef 均可审计；
7. path 至少含一条非 anchor 的真实程序关系；
8. 移除 causal proposal 后相同 benchmark-consistent path 消失。

仅“项目中存在某条路径”或 input/effect 直接跳接不计为恢复。

## 12. Per-case results

support composition 采用 `CodeQL deterministic / repository structural / semantic proposal` 计数。

| project | E0 | proposal sequence | Gate | recovered | granularity | support | counterfactual | minimal | wall-clock | failure |
|---|---|---|---|---:|---|---|---|---|---:|---|
| D003 | miss, 0 paths | INPUT + LIBRARY + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 13.848866s | — |
| P006 | miss, 0 paths | INPUT + LIBRARY + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 15.488172s | — |
| P007 | miss, 0 paths | INPUT + CALLBACK + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 1.521172s | — |
| P010 | miss, 0 paths | INPUT + CALLBACK + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 17.675949s | — |
| P012 | miss, 0 paths | INPUT + FRAMEWORK + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 4.682590s | — |
| V001 | miss, 0 paths | INPUT + LIBRARY + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 7.132732s | — |
| V004 | miss, 0 paths | INPUT + LIBRARY + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 3.364919s | — |
| V005 | miss, 0 paths | INPUT + LIBRARY + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 2.019031s | — |
| V009 | miss, 0 paths | none | n/a | false | METHOD | 0 / 0 / 0 | n/a | n/a | 2.078865s | `INSUFFICIENT_PROGRAM_EVIDENCE` |
| V023 | miss, 0 paths | INPUT + CALLBACK + EFFECT | 3/3 admissible | true | METHOD | 0 / 1 / 3 | removed | 3/3 necessary | 20.402029s | — |

## 13. Before/after paths

所有 selected case 的 BEFORE 均为 `NO_USEFUL_BASELINE_PARTIAL_PATH`：E0 没有 alert/path ID，native 和 unified coverage 都为 false。

AFTER 的 9 条恢复路径不是 input 直接跳到 effect；每条都包含真实 M2 repository `LEXICAL_CALL` 结构边：

| projects | AFTER ordered relations |
|---|---|
| D003, P006, V001, V004, V005 | `EXTERNAL_INPUT -> LIBRARY_FLOW -> LEXICAL_CALL -> SECURITY_EFFECT` |
| P007, P010, V023 | `EXTERNAL_INPUT -> CALLBACK_RELATION -> LEXICAL_CALL -> SECURITY_EFFECT` |
| P012 | `EXTERNAL_INPUT -> FRAMEWORK_RELATION -> LEXICAL_CALL -> SECURITY_EFFECT` |
| V009 | no path; evidence不足，没有构造 shortcut |

其中 anchor 与语义关系保持 `ADMISSIBLE_SEMANTIC_PROPOSAL`，`LEXICAL_CALL` 保持 `STRUCTURAL_EVIDENCE`；实现没有把 proposal edge 伪装成 `CODEQL_*`。

## 14. Counterfactual results

对 9 个恢复 case 移除所有 recovery proposal，再用完全相同的 graph/path 配置运行。9/9 的 benchmark-consistent path 均消失：

`counterfactual_without_proposal = NO_RECOVERY`

因此 `counterfactual_causal_success_count=9`，`counterfactual_causal_for_all_recoveries=true`。没有把本来就存在的路径错误归因给 proposal。

## 15. Proposal minimality

对每个 3-proposal recovery 执行 leave-one-out：移除 input、middle semantic relation 或 effect 中任意一条，完整 benchmark-consistent path 都不再成立。9 个恢复 case 均为 `MINIMAL_SET`，每个最小 proposal 数为 3；没有 `REDUNDANT_PROPOSAL_PRESENT`。

这个结果也解释了为什么 replay 都在 step 3 首次成功：两个 anchor 和中间缺失语义缺一不可。

## 16. Failure analysis

唯一未恢复 case 是 V009 commons-io / CVE-2021-29425。诊断侧 compact fix projection 为空，无法定位一个可通过 Gate 的真实 callable/role/EvidenceRef 组合。系统将其分类为 `INSUFFICIENT_PROGRAM_EVIDENCE`，没有降级成猜测、项目特例或 direct benchmark target edge。

failure taxonomy：

- `INSUFFICIENT_PROGRAM_EVIDENCE`: 1；
- `GATE_BLOCKED`: 0；
- `NOT_EXPRESSIBLE_BY_CURRENT_PROPOSAL_TYPES`: 0；
- 其他失败类别：0。

## 17. Aggregate mechanism recovery

| metric | value |
|---|---:|
| Eligible Miss Cases | 10 |
| Selected Cases | 10 |
| Selected projects | 10 |
| Mechanism Recovery Count | 9 |
| Mechanism Recovery Rate | 90% |
| Recovered projects | 9 |
| `LIBRARY_FLOW` recoveries | 5 |
| `CALLBACK_RELATION` recoveries | 3 |
| `FRAMEWORK_RELATION` recoveries | 1 |
| `WRAPPER_OR_LIBRARY_FLOW_MISSING` recovered causes | 5 |
| `FRAMEWORK_OR_CALLBACK_RELATION_MISSING` recovered causes | 4 |
| Proposals per recovered case | 3 |
| Minimal proposals per recovered case | 3 |
| Recovered paths with CodeQL deterministic evidence | 0 |
| Recovered repository-only paths | 9 |
| Counterfactual causal successes | 9/9 |
| Gate blocked | 0 |
| Not expressible | 0 |
| Average M6 CodeQL calls | 0.0 |
| Average wall-clock | 8.821432s |

本轮真实路径的 support composition 全部为 `0 CodeQL deterministic + 1 repository structural + 3 semantic proposal`。M6 没有为了提高 CodeQL edge 数而制造连接。M5 controlled fixture 已验证 CodeQL-assisted graph composition，但这些 M6 mapped entities 的 `codeql_identity=null`，当前 replay 没有获得可合法拼入恢复路径的 M3 deterministic relation。

云端 full test 返回码为 0：`150 passed, 1 skipped, 1 warning`。artifact auditor 同时验证 required case files、Git/revision/CodeQL/DB/schema binding、hashes、baseline miss、diagnostic flags、proposal budget、freeze ordering、counterfactual、minimality、非 trivial program relation、failure taxonomy、diagnostic manifest 和逐 case proposal 副本；结果 `PASS`、0 violations。

## 18. No-leakage boundary for M7

M6 diagnostic proposals 永久保存在独立的 `m6_killtest/diagnostic_proposals/`，manifest 明确：

- `benchmark_informed=true`；
- `allowed_for_agent_runtime=false`；
- `eligible_for_detection_metric=false`。

这些文件不得进入 M7 prompt、few-shot example、retrieval memory、tool hint、训练数据或正式评测输入。detector 包没有 diagnostic/evaluator import；实现扫描确认不存在 `if project == ...`、`if case_id == ...`、`if repository == ...` 的特例行为，aggregate 记录 `case_specific_implementation_conditionals=false`。

## 19. Limitations

- 结果是 benchmark-informed upper bound，不是自主检测性能。
- 10 个 case 的可用 benchmark matching granularity 全部是 METHOD；不能把结果宣传为 line-level recovery。
- 9 条恢复路径均为 repository-only hybrid，M6 本身没有执行 CodeQL tool call，也没有真实 CodeQL deterministic edge；“语义 proposal 桥接真实 CodeQL facts”仍需后续专门样本验证。
- repository `LEXICAL_CALL` 是真实结构证据，但不等价于 runtime dataflow。
- mapped callable 的 `codeql_identity` 均为空，暴露了 RepositoryIndex 与 M3 entity identity 对齐仍需加强。
- 当前 inventory 由已有 18 个 CodeQL-ready 资产及冻结 baseline case 交集生成；本轮不重建失败 DB，不能外推到全部 benchmark。
- V009 表明 benchmark 修复信息也不必然足以形成可审计的 M4 proposal；证据不足时机制会保守停止。
- 平均 wall-clock 只反映本轮云端缓存、硬件和 10-case replay，不是最终 Agent 成本。

## 20. Decision

决定：`PROCEED_M7`，但本轮在此停止，不启动 M7。

理由：

- 9 个真实 baseline miss 恢复，超过至少 3 个的门槛；
- 覆盖 9 个不同项目，超过至少 2 个项目的门槛；
- `LIBRARY_FLOW`、`CALLBACK_RELATION`、`FRAMEWORK_RELATION` 三类中间语义因果参与，超过至少 2 类的门槛；
- 9/9 counterfactual 均确认 proposal contribution；
- 9/9 leave-one-out 均得到最小 proposal 集；
- 没有 project-specific implementation rule；
- artifact audit PASS，云端 full regression PASS。

`PROCEED_M7` 只表示 M1-M5 机制具备接受最小 grounded hypothesis 并恢复真实漏检路径的能力，不表示 M7 的自主 proposal discovery 必然成功，也不表示 Work1 已获得正式 Detection Rate/FDR/F1。
