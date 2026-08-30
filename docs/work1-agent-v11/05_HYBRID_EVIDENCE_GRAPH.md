# Work1 V11 M5：Hybrid Evidence Graph 与 Candidate Path Builder

## 1. M5 研究目的

M5 将 M1 `ProgramEntity`、M2 repository structural evidence、M3 CodeQL deterministic facts 与 M4 `ADMISSIBLE` security proposals 放入同一套可审计的证据图，并从 External Input anchor 到 Security Effect anchor 构造有界 Candidate Path。它回答的是“是否存在一条有程序证据支撑、值得 Work2 继续验证的安全相关候选链”，而不是漏洞裁决。

图构造不以 CodeQL native/partial-flow 成功为前置条件；CodeQL 是高可信的确定性证据来源之一。已有 `CODEQL_NATIVE` Candidate Path 通过 adapter 原样保留，hybrid augmentation 只做加法。

## 2. Graph node model

`EvidenceNode` 同时表达实体与 value role，避免把 `Foo.bar ARGUMENT[0]`、`Foo.bar RETURN`、`Foo.bar RECEIVER` 混成一个节点。实体节点记录 `entity_id`、`role`、可选 `role_index`、repository-relative file、行范围、program kind 和 provenance；概念 anchor 使用 `SECURITY_INPUT_ROOT` 与 `SECURITY_EFFECT_ROOT`。

`node_id` 由 project identity、node kind、entity identity、role/index 或 anchor proposal identity 的 canonical payload 生成，稳定且可复查。绝对文件系统路径不进入 identity，因此同一 revision 在不同 checkout 下不会产生不同 node ID。role/index 在节点进入 active graph 前由 M4 role validator 校验。

## 3. Graph edge model

`HybridEdge` 统一记录 `source_node_id`、`target_node_id`、`relation_kind`、`support_class`、`evidence_refs`、可选 `proposal_id`、`tool_call_ids`、`repository_relation_ids`、描述性 confidence 与 provenance。`edge_id` 对 project、两端 node、relation、support class、EvidenceRef、proposal/tool/repository relation identity 的 canonical payload 做确定性散列。

支持的确定性关系为 `CODEQL_CALL`、`CODEQL_LOCAL_FLOW`、`CODEQL_DATAFLOW`、`CODEQL_CFG`；repository structural relation 为 `LEXICAL_CALL`、`DECLARES`、`EXTENDS_TEXT`、`IMPLEMENTS_TEXT`、`OVERRIDE_CANDIDATE`；proposal-derived relation 保留 M4 原始语义：`EXTERNAL_INPUT`、`SECURITY_EFFECT`、`WRAPPER_FLOW`、`LIBRARY_FLOW`、`FIELD_STATE`、`FRAMEWORK_RELATION`、`CALLBACK_RELATION`。proposal edge 不会伪装或重命名成 `CODEQL_*`。

## 4. Support classes

M5 使用三个互不混淆的 support class：

- `DETERMINISTIC_FACT`：已成功执行并有精确 EvidenceRef/tool-call 绑定的 CodeQL relation。
- `STRUCTURAL_EVIDENCE`：M1/M2 repository/source/type/call structure 支持的局部关系。
- `ADMISSIBLE_SEMANTIC_PROPOSAL`：M4 Evidence Gate 已准入但仍需后续语义验证的 hypothesis。

排序仅用于确定性搜索：deterministic fact 在 structural evidence 之前，structural evidence 在 admissible proposal 之前。这个顺序不是概率、风险分数或漏洞置信度。

## 5. `ADMISSIBLE` 不等于 deterministic fact

只有 M4 Gate status 为 `ADMISSIBLE` 的 proposal 可以形成 active proposal edge，而且 Gate 的 `resolved_evidence` 必须覆盖 proposal 的完整 EvidenceRef 集。`REJECTED`、`NEEDS_MORE_EVIDENCE`、`DUPLICATE` 都只留下 diagnostic，不进入 active graph；`ALREADY_SUPPORTED` 不复制边，只在已存在、端点相符的 stronger edge 上附加 proposal provenance。

`ADMISSIBLE_SEMANTIC_PROPOSAL` 始终保留 proposal ID、EvidenceRef 与“grounded but not confirmed”告警。它不升级为 `DETERMINISTIC_FACT`，也不表示 relation、候选路径或漏洞已经成立。

## 6. HybridEvidenceGraphBuilder

Builder 接收 project-scoped ProgramEntity index、EvidenceRef catalog、M2 repository artifacts、M3 CodeQL tool results、M4 proposals 与 Gate results。active edge 必须满足：两端节点存在且同属一个 project；entity/role/index 可解析；每个 EvidenceRef 存在且其中引用的 entity 可解析；support class 与 relation source 一致；没有匿名 edge 或 wildcard semantic edge。

CodeQL edge 还要求 relation 对应精确 EvidenceSourceKind、每个 `tool_call_id` 指向 status `OK` 的实际工具结果，并被同类型 EvidenceRef 的 `tool_call_id` 精确绑定。repository edge 要求 source/repository/type evidence。非法 edge 被排除并写入带 `project_id` 的 graph diagnostic；除非图完整性本身无法确定，否则不会让整个 build 崩溃。

`build_subgraph(seed_node_ids, max_nodes, max_edges, max_depth)` 只展开任务相关局部证据。M5 不把整个 CodeQL DB 导入大图。若同一端点已有 deterministic `CODEQL_CALL`，等价 `LEXICAL_CALL` 会作为 dominated structural edge 被抑制；语义不同的 proposal edge不会因此消失。

## 7. Security anchors

External Input proposal 建立 `SECURITY_INPUT_ROOT -> ProgramValueNode`；Security Effect proposal 建立 `ProgramValueNode -> SECURITY_EFFECT_ROOT`。两类概念节点以 proposal identity 区分，序列化的 candidate path 同时记录 `input_anchor`、`effect_anchor` 及各自 proposal ID。M5 不要求这些 anchor 属于 CodeQL Source/Sink taxonomy。

`FIELD_STATE` 可形成 source-to-field 与 field-to-target 两段 proposal edge；wrapper/library/framework/callback proposal 按其 source/target role 形成一段关系。因此路径端点和每个中间 value role 均可回溯到真实 ProgramEntity。

## 8. Candidate Path 定义与 schema

Candidate Path 是从 External Input anchor 到 Security Effect anchor 的一条有界、按序证据链。`hybrid_candidate_path.schema.json` v1 记录 `input_anchor`、`effect_anchor`、`ordered_nodes`、`ordered_edges`、`support_summary`、`proposal_ids`、`unresolved_semantics`、`evidence_refs` 与 provenance；`m5_candidate_path.schema.json` 是显式版本化 union，接受 legacy/native schema-v2 path 或 hybrid schema-v1 path。

每条 ordered edge 保留 relation、support class、两端 node、EvidenceRef、proposal/tool/repository relation ID 和 provenance。support summary 只报告 path length、三类 edge 数量、CodeQL/repository contribution、proposal IDs 与 repository-only-hybrid 标识，不生成 vulnerability/risk/probability score。

## 9. Native path preservation

`NativePathAdapter.preserve()` 接收现有 Candidate Path schema-v2 mapping，并返回相同对象、相同字段和相同顺序；它不把 native path 重建为 hybrid approximation。controlled smoke 将一条 native path 放入 M5，unit test 同时检查对象 identity 与 value equality。最终 `candidate_paths.jsonl` 是 native preservation 与新 hybrid paths 的并集。

## 10. Bounded path search

`BoundedPathBuilder` 使用确定性、cycle-safe graph search，并设硬上限：`max_depth <= 20`、每 anchor pair `max_paths <= 20`、`max_nodes_expanded <= 10000`。默认 smoke 使用更保守的限制，达到边界会写明 project、anchor 与 limit 的 path diagnostic。

搜索按 support class、relation、edge ID 稳定排序；访问同一路径中已有 node 时触发 cycle prevention。不存在候选链时记录 `NO_CANDIDATE_PATH`，而不会因为同一项目同时出现 input/effect anchor 就合成跳跃边。

## 11. Path dominance 与 deduplication

path fingerprint 基于 ordered node IDs、ordered relation kinds 与 proposal IDs。完全相同的路径折叠；当端点相同且 stronger deterministic edge 已表达同一调用关系时，冗余 structural form 在图阶段被抑制。含不同 semantic proposal、不同端点或不同关系的路径不会被静默合并。

## 12. Controlled fixture

controlled fixture 复用 M4 manual proposal set，不调用 LLM，也不读取 benchmark CVE、patch、known vulnerability location 或 CWE。场景矩阵覆盖：native preservation、repository-only hybrid、CodeQL-assisted hybrid、field/state、framework、callback、cycle、duplicate path、invalid role/proposal edge、`NEEDS_MORE_EVIDENCE` inactive 和 disconnected anchors。

CloudStudio 在 Git `26a9baf4abb1867c804df885c8dc56b14955bae3` 上执行 controlled smoke，返回码为 0。实际产物为 68 个 node、46 条 edge、8 条 candidate path，其中 native 1 条、hybrid 7 条、repository-only hybrid 5 条。7 条 hybrid path 的平均长度为 3.285714，平均每条含 2.714286 条 proposal edge；搜索展开 43 个节点，cycle prevention 2 次、exact dedupe 1 次、truncation 0 次、invalid-edge rejection 2 次、`NO_CANDIDATE_PATH` anchor pair 74 个。

三类 edge 的实际数量为：`DETERMINISTIC_FACT=2`、`STRUCTURAL_EVIDENCE=3`、`ADMISSIBLE_SEMANTIC_PROPOSAL=41`。场景矩阵的 11 项断言全部为 true：native preservation、repository-only、CodeQL-assisted、field/state、framework、callback、cycle prevention、duplicate suppression、invalid proposal rejection、`NEEDS_MORE_EVIDENCE` inactive、指定 disconnected pair 无路径。

## 13. Repository-only hybrid path

受控场景至少生成一条只由 repository structural evidence 与 `ADMISSIBLE_SEMANTIC_PROPOSAL` 组成、CodeQL edge 数为 0 的完整 input-to-effect path。每段仍携带真实 EvidenceRef；它证明 CodeQL 不是构造候选链的资格门槛，但不证明该链语义正确或可利用。

云端实例 `hpath-4059313434b2a6d0850f4baf` 的 ordered relations 为：

`EXTERNAL_INPUT [ADMISSIBLE_SEMANTIC_PROPOSAL] -> LEXICAL_CALL [STRUCTURAL_EVIDENCE] -> SECURITY_EFFECT [ADMISSIBLE_SEMANTIC_PROPOSAL]`

其 `path_length=3`、`proposal_edge_count=2`、`structural_edge_count=1`、`deterministic_edge_count=0`、`codeql_edge_count=0`。两条语义边分别绑定 proposal `proposal-6a42d5df043ff900595ba0e3` 与 `proposal-0a1b7da7e9256e63b352bb16`；结构边绑定 repository relation `controlled-lexical-call-b`。整条路径可回溯到 EvidenceRef `evidence-1d61d7d3f368e8361c3f23ad`、`evidence-dff7bb14a15831a45c81d6e4`、`evidence-bf07e812ad91965c1432708a`，且 unresolved semantics 显式保留 input/effect 两个 proposal。

## 14. CodeQL-assisted hybrid path

受控场景还把 `CODEQL_DATAFLOW` deterministic edge 与 External Input、语义 proposal、Security Effect proposal 组合在同一 ordered path。CodeQL relation 只有在 status `OK` 工具结果、精确 EvidenceSourceKind、匹配 tool-call identity 与 query/result provenance 都存在时才进入图。

云端实例 `hpath-564a8a410c5921fa744d6d02` 的 ordered relations 为：

`EXTERNAL_INPUT [proposal] -> CODEQL_DATAFLOW [deterministic] -> WRAPPER_FLOW [proposal] -> CODEQL_DATAFLOW [deterministic] -> SECURITY_EFFECT [proposal]`

其 `path_length=5`、`proposal_edge_count=3`、`deterministic_edge_count=2`、`codeql_edge_count=2`。两个 CodeQL edge 分别绑定实际 tool-call `controlled-codeql-before-semantic` 与 `controlled-codeql-after-semantic`，并绑定 EvidenceRef `evidence-b03a59de03ebf42c935a7d42` 与 `evidence-a7b7adc19489241a90252270`；中间 `WRAPPER_FLOW` 保持 proposal `proposal-f4c712878f5b4f2e77dafdd1` 与 `ADMISSIBLE_SEMANTIC_PROPOSAL` 身份。完整路径共保留 5 个 EvidenceRef，未把 proposal edge 升格为 CodeQL fact。

## 15. Real-project smoke

真实云端 grounding smoke 固定使用与 M4 相同的 deterministic family：`P006`、`P007`、`D001`、`D002`、`V001`、`V002`、`V003`、`V004`。它消费既有 M1 inventory、M2 entity indexes、M3 tool-call artifacts 与 M4 real-project proposals/gate/evidence artifacts；V002/V003 明确保留 CodeQL unavailable 状态。每个项目独立建图、限界搜索和写 artifact，禁止跨项目 relation。

新增 manual anchor 只依据 source-grounded ProgramEntity，选择规则与 benchmark 漏洞位置无关。smoke 不使用 CVE、patch、known vulnerability type/location 或 CWE，也不为追求“每项目必出漏洞路径”而放松图规则。

CloudStudio 固定 8 项目 smoke 返回码为 0。逐项目结果如下；`positive` 是精确的 selected input -> same-node grounded effect，`negative blocked` 是同一 input -> 指定 disconnected effect：

| project | CodeQL ready | nodes | edges | paths | repository-only paths | positive | negative blocked | no-path pairs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P006 | true | 6 | 4 | 2 | 2 | true | true | 2 |
| P007 | true | 6 | 4 | 2 | 2 | true | true | 2 |
| D001 | true | 6 | 4 | 2 | 2 | true | true | 2 |
| D002 | true | 6 | 4 | 2 | 2 | true | true | 2 |
| V001 | true | 6 | 4 | 2 | 2 | true | true | 2 |
| V002 | false | 4 | 2 | 1 | 1 | true | true | 1 |
| V003 | false | 4 | 2 | 1 | 1 | true | true | 1 |
| V004 | true | 6 | 4 | 2 | 2 | true | true | 2 |

真实 smoke 合计 44 个 node、28 条 proposal-derived edge、14 条 hybrid path，全部为 repository-only hybrid；`CODEQL_DATAFLOW` 实际参与数为 0。六个 CodeQL-ready 项目仍消费并记录 M3 tool-call artifact hash，但现有 M4 grounded anchors 没有可合法拼入这些局部路径的 deterministic CodeQL relation，因此实现没有为追求 CodeQL edge 数而伪造连接。这是机制 smoke 的透明结果，不影响 controlled fixture 对 CodeQL-assisted composition 的正向验证。

## 16. Disconnected-anchor negative test

每个真实项目都选择一个确定的 External Input proposal、一个同节点 grounded Security Effect positive anchor，以及一个不同实体且没有 asserted relation 的 Security Effect negative anchor。验证不是“某个 anchor pair 没路径”这一弱条件，而是精确断言：selected input -> expected same-node effect 的 path 存在；同一个 selected input -> 指定 disconnected effect proposal 的 path 不存在。

8/8 项目的 expected same-anchor positive path 均构造成功，8/8 指定 disconnected negative pair 均被阻断；真实 smoke 的 `all_disconnected_negative_pairs_blocked=true`，并产生 14 个 `NO_CANDIDATE_PATH` anchor pair。V002/V003 在无 CodeQL DB 时仍分别形成 1 条 source-grounded repository-only positive path，同时各自保持 1 个 disconnected no-path pair。

## 17. Mechanism metrics 与 artifacts

云端 authoritative root 为 `/workspace/experiment-output/artifacts/work1-agent-v11/m5_hybrid_graph/`，包含 `graph_nodes.jsonl`、`graph_edges.jsonl`、`candidate_paths.jsonl`、`graph_diagnostics.jsonl`、`path_diagnostics.jsonl`、`summary.json` 与 `manifest.json`。controlled、real-project 及每项目 subroot 分别保存可审计输入/输出；combined manifest 保留 component manifests、Git SHA、schema version、project identity、ProgramEntity/M2/M3/M4 input hashes 与最终 artifact hashes。

最终 combined root 的实际统计为：112 个 node、74 条 edge、22 条 candidate path（native 1、hybrid 21、repository-only hybrid 19）。support class 为 `DETERMINISTIC_FACT=2`、`STRUCTURAL_EVIDENCE=3`、`ADMISSIBLE_SEMANTIC_PROPOSAL=69`；CodeQL-derived edge 2 条。21 条 hybrid path 的平均长度为 2.428571，平均 proposal edge 数为 2.238095。搜索共展开 85 个节点，cycle prevention 2 次、exact dedupe 1 次、truncation 0 次、invalid-edge rejection 2 次、`NO_CANDIDATE_PATH` 88 个 anchor pair。

最终 CloudStudio checkout、controlled smoke、real smoke、全量测试返回码均为 0；云端测试为 `138 passed, 1 skipped, 1 warning`。combined、controlled、real 三层 manifest 的 Git SHA 均精确等于 `26a9baf4abb1867c804df885c8dc56b14955bae3`，所有已声明 artifact SHA-256 与文件实值一致，所有 JSONL 均可逐行解析。real manifest 含 8 个 project component lineage，项目顺序为 `P006,P007,D001,D002,V001,V002,V003,V004`；全部记录 `llm_used=false`、benchmark vulnerability location/patch/CVE/CWE 未使用。combined manifest 保留 controlled 与 real 两个完整 component lineage。

M5 只报告 graph/path 数量、relation/support class、proposal/CodeQL/repository edge contribution、native/hybrid/repository-only path、平均长度、proposal edges per path、dedupe、cycle prevention、search truncation、invalid-edge rejection 与 `NO_CANDIDATE_PATH`。`detection_rate` 固定为 `null`；本阶段不报告 Detection Rate、Avg FDR 或 Avg F1。

## 18. 已知限制与不成立的结论

- M5 不证明 candidate path 在语义上正确。
- M5 不证明 candidate path 可被利用。
- M5 不证明 protection/sanitization 缺失或无效。
- M5 不证明存在漏洞。
- M5 不证明某个 CWE 分类正确。
- repository structural relation 仍是局部、保守的程序结构证据，不等价于 runtime dataflow。
- M4 proposal 的 manual origin 与不确定语义仍完整保留，真实项目 smoke 不是正式 vulnerability experiment。
- V002/V003 没有 CodeQL DB；D003 等历史 DB 限制不应被解释为关系不存在。
- bounded search 可能有意不枚举更深或更多的候选链，truncation 必须结合 diagnostics 解读。

## 19. M6 handoff

M6 只能消费 M5 中逐边可回溯的 Candidate Path，并继续验证 proposal-derived unresolved semantics、危险上下文、防护与可利用性；不能把 `ADMISSIBLE`、path presence 或 support ordering 当作漏洞概率。M5 完成门槛包括：repository-only 与 CodeQL-assisted hybrid path 均被 controlled smoke 构造；native path 原样保留；固定 8 项目 real smoke 完成；指定 disconnected pair 全部阻断；search bounds、invalid-edge exclusion、lineage hashes 与全量回归验证通过。

结论：`PROCEED_M6`。M5 的 A-J 成功条件均已满足；M6 应把真实项目中尚未由 deterministic CodeQL relation 加强的 proposal-only 路径视为优先验证对象，而不是已确认漏洞。按任务边界，本阶段在此停止，不启动 M6、LLM Agent、prompt engineering 或正式 benchmark evaluation。
