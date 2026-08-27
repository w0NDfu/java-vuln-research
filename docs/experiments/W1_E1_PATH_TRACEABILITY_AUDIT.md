# W1-E1 DEV16 Path Traceability Audit

- 范围：同一 18 项目、同一 E0 baseline query 与当前 Route A frozen artifacts。
- 本次仅做离线解析与关联；未重跑 CodeQL，未读取 GT，未修改 Detector、propagation semantics、Route B、Wrapper/Library、Field/State 或 LLM。
- E0 SARIF：`/workspace/experiment-output/W1-E1-DEV16-E0-20260826-002/baseline/*.sarif`
- Route A：`/workspace/experiment-output/W1-E1-DEV16-20260826-001/`
- 逐条工件：
  - `/workspace/experiment-output/W1-E1-PATH-TRACEABILITY-AUDIT-20260827-001/e0_path_traceability.jsonl`
  - `/workspace/experiment-output/W1-E1-PATH-TRACEABILITY-AUDIT-20260827-001/pair_gate_audit.jsonl`
  - `/workspace/experiment-output/W1-E1-PATH-TRACEABILITY-AUDIT-20260827-001/route_a_pair_gate_audit.jsonl`
  - `/workspace/experiment-output/W1-E1-PATH-TRACEABILITY-AUDIT-20260827-001/summary.json`

## 1. E0 SARIF 审计与 path-level identity

E0 baseline 目录含 18 份 SARIF：

- SARIF results：296
- codeFlows：437
- threadFlows/native paths：437
- E0 summary 中的 baseline_paths：437（与逐条 threadFlow 一致）
- path-level 可审计：437/437（100%）

每条路径生成稳定 ID：

`<project_id>:r<result_index>:c<code_flow_index>:t<thread_flow_index>`

并保留：

- project_id、native_path_id；
- source（首个有效 threadFlow location）；
- sink/effect（末个有效 threadFlow location）；
- 全部有效 path locations/nodes；
- rule_id、CodeQL tool identity；
- SARIF 文件、result/codeFlow/threadFlow 索引等 provenance；
- SARIF 未提供的 message/taxa/value-role 原字段按原样保留为空；若 Route A 命中则附加 candidate entity/critical role。

因此本次不需要扩展 E0 exporter，也不需要重新运行 E0。

## 2. E0 path 到 Route A candidate 的逐条 join

Join 键为 frozen artifact 中的 `(project_id, file, line)`，首节点作为 source，末节点作为 effect/sink；未做笛卡尔积，也未用 GT 放宽匹配。

| 指标 | 数量 | 比例 |
|---|---:|---:|
| E0 native paths | 437 | 100% |
| source matched ExternalInputCandidate | 151 | 34.55% |
| effect matched SecurityEffectCandidate | 0 | 0.00% |
| both endpoints matched | 0 | 0.00% |
| both endpoints FW/BW active | 0 | 0.00% |
| E0-derived pair admitted | 0 | 0.00% |
| E0-derived STATIC_CONNECTED | 0 | 0.00% |

source 命中的 unique Route A candidate_id 为 27 个；effect 命中的 unique candidate_id 为 0 个。

这意味着本次没有出现“E0 两端都在 Route A、两端也都 active、但 E1 Data/Call path 没有复现”的 case。不能把当前 E0→E1 差异归因于已证实的 pair connector implementation mismatch；在逐条证据上，阻塞发生在 effect endpoint join 之前。

## 3. 统一 failure taxonomy（E0 path 粒度）

采用互斥优先级：先判两端候选是否存在，再判 FW/BW，再判 pair gate/path 结果。

| failure taxonomy | 数量 |
|---|---:|
| MISSING_INPUT_CANDIDATE | 0 |
| MISSING_EFFECT_CANDIDATE | 151 |
| MISSING_BOTH_CANDIDATES | 286 |
| INPUT_FW_EMPTY | 0 |
| EFFECT_BW_EMPTY | 0 |
| PAIR_GATE_REJECTED | 0 |
| SAME_REGION_NO_BASE_FLOW | 0 |
| STRUCTURAL_FRONTIER | 0 |
| STATIC_CONNECTED | 0 |
| NOT_EVALUABLE | 0 |
| IMPLEMENTATION_ERROR | 0 |
| **合计** | **437** |

对问题 “E0 已经存在 native path，但 W1-E1 没有 Candidate Path” 的归因：

- A（Route A 缺 Input）：本次精确 join 中没有“仅缺 Input”的路径；
- B（Route A 缺 Effect）：151 条；
- C（FW/BW 单侧失活）：0 条，因为没有 path 同时命中两端；
- D（pair gate 没把两端放到一起）：0 条可判定；
- E（两端都有且 active，但 E1 Data/Call path 未复现）：0 条。

286 条属于两端候选同时未命中。这里的“缺 Effect”是对 frozen E0 SARIF sink location 与 frozen Route A effect evidence 的精确 join 结果，不是根据 GT 或 CVE 推断。

## 4. Route A pair-gate audit

Route A 未生成全笛卡尔积。审计只复用现有 gated 输出：

- observed unique gated input/effect pairs：6
- corresponding raw structural-frontier rows：287
- structural frontier pairs：6
- STATIC_CONNECTED：0
- Candidate Paths：0
- 所有 observed gated pairs 位于 P010

`route_a_pair_gate_audit.jsonl` 为 6 个去重后的 gated pair 记录，保留 project、candidate IDs、frontier reason、structural distance 和 provenance。`pair_gate_audit.jsonl` 则为 437 条 E0 native path 的逐条 gate 判定；由于 E0 path 没有一条同时命中两端，E0-derived admitted pair 为 0。

因此当前 artifact 能证明的是“已观察到的 6 个 pair 被送入 structural frontier，但没有形成静态连接”；它没有序列化所有未进入 gate 的 Route A 候选组合，不能把未序列化组合虚构成额外的 pair 拒绝计数。

## 5. 与 Route A endpoint funnel 的关系

现有 Route A frozen funnel 仍为：

- ExternalInput candidates：254，全部可映射；
- SecurityEffect candidates：59，全部可映射；
- FW-active：123；
- BW-active：14；
- STATIC_CONNECTED：0。

本次 E0 path-level join 的 effect 命中为 0，说明 E0 baseline 的 437 条 native path 与当前 Route A SecurityEffect evidence location 没有精确重合；这与“Route A 有 59 个 effect candidate”是两个不同命题，不能把后者当作 E0 sink 覆盖证明。

## 6. 最终结论

1. **E1 是否仍有基础实现问题：是，但当前已定位为 endpoint representation/coverage 闭环未完成，而不是已证实的 FW/BW connector 失败。**  
   当前最直接的证据是 437 条 E0 native path 中 0 条命中 Route A effect endpoint，且没有任何 both-active case。

2. **是否已有证据支持 Route B：否。**  
   当前结果首先暴露的是 E0 sink 与 Route A effect candidate 的逐条可追溯覆盖缺口；在没有 both-active path 的前提下，不能据此宣称 Route A 语义已被充分验证并切换 Route B。

3. **是否已有证据支持新的 propagation semantics：否。**  
   没有出现“两端都在 Route A 且 FW/BW active、但 E1 仍无法连接”的证据，因此不能用 Wrapper/Library、Field/State 或其他新 propagation semantics 解释当前结果。

审计完成后停止；未启动下一实验。
