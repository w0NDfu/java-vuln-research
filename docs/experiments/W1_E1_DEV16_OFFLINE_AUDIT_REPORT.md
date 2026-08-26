# W1-E1 DEV16 离线审计报告

- 审计范围：现有 18 项目 frozen artifacts
- 审计类型：离线读取、去重、关联和 post-hoc 核对
- 明确未执行：CodeQL 重跑、Detector 修改、GT 反向修正、E2、Route B、LLM
- 主要工件：
  - `/workspace/experiment-output/W1-E1-DEV16-20260826-001/endpoint_candidates.jsonl`
  - `/workspace/experiment-output/W1-E1-DEV16-20260826-001/input_forward_funnel.jsonl`
  - `/workspace/experiment-output/W1-E1-DEV16-20260826-001/effect_backward_funnel.jsonl`
  - `/workspace/experiment-output/W1-E1-DEV16-20260826-001/frontier_cases.jsonl`
  - `/workspace/experiment-output/W1-E1-DEV16-20260826-001/project_status.jsonl`
  - `/workspace/experiment-output/W1-E1-DEV16-20260826-001/e0_evaluator_sanity.json`
  - `/workspace/experiment-output/W1-E1-DEV16-ATTRIBUTION-20260826-001/bw_by_effect_type.csv`
  - `/workspace/java-vuln-research/reports/runs/W1-E1-DEV16-E0-20260826-002/summary.json`

## 1. SecurityEffect 去重审计

### 1.1 原始候选粒度

`endpoint_candidates.jsonl` 中筛选 `kind=SECURITY_EFFECT`：

- 原始行数：59
- unique `candidate_id`：59
- 重复 `candidate_id`：0
- effect backward funnel 关联行：59
- BW-active：14
- BW-empty：45
- mapping 成功：59/59

因此“总候选 59”在候选 ID 粒度上是正确的，问题不在 SecurityEffect 候选生成重复。

### 1.2 按 unique candidate_id 的正确分类

| effect_type | unique candidates | BW-active | BW-empty |
|---|---:|---:|---:|
| DYNAMIC_EVALUATION | 19 | 2 | 17 |
| FILESYSTEM_ACCESS | 19 | 7 | 12 |
| PROCESS_EXECUTION | 16 | 2 | 14 |
| RENDERING | 5 | 3 | 2 |
| **合计** | **59** | **14** | **45** |

### 1.3 为什么会出现 62 和 BW-active 不一致

62 不是 unique `candidate_id` 的统计口径，而是 attribution/classification 层对 effect label 或中间记录的汇总口径。该层允许同一候选在不同分类记录中再次出现，或把 frontier/label 记录当成候选记录；它因此不能作为候选总数，也不能直接和 59 个 BW funnel 候选做 BW-active 比较。

本次离线审计对权威候选文件和 effect funnel 按 `candidate_id` 做了显式 join：

- 候选没有重复；
- 59 = 14 + 45；
- 正确 effect_type 合计为 59，而不是 62。

所以 62 以及对应的 BW-active 分类合计不一致，属于下游汇总的粒度混用/重复归类问题，不是 3 个额外 SecurityEffect，也不是 CodeQL 结果多报。

## 2. Input–Effect pair funnel

### 2.1 端点门槛（endpoint-level）

| 阶段/原因 | 数量 | 口径 |
|---|---:|---|
| ExternalInput 总数 | 254 | unique candidate_id |
| EMPTY_FW | 131 | 131 个 Input 的 forward reachable set 为空 |
| FW-active | 123 | 有 forward reachable node |
| SecurityEffect 总数 | 59 | unique candidate_id |
| EMPTY_BW | 45 | 45 个 Effect 的 backward reachable set 为空 |
| BW-active | 14 | 有 backward reachable node |

EMPTY_FW/EMPTY_BW 是端点级计数，不能和 pair 级计数直接相加：一个空端点可以阻塞同项目中的多个潜在 pair，而 frozen artifacts 没有为每个被阻塞的笛卡尔 pair 生成一行拒绝记录。

### 2.2 frozen artifact 中实际可审计的 pair 记录

`frontier_cases.jsonl` 提供了结构 frontier 记录：

- raw structural frontier rows：287
- unique input/effect candidate pair：6
- STATIC_CONNECTED：0
- frontier 所在项目：仅 P010

原生 frontier reason 分布：

| 原生 reason | rows | 解释 |
|---|---:|---|
| CALL_ADJACENT | 222 | 输入/效果落在不同 call component，尚未形成静态传播边 |
| NEAR_CALL_REGION | 29 | 输入/效果落在不同 call component 的邻近区域，仍未形成静态传播边 |
| SAME_METHOD | 36 | 同一 method，structural_distance=0，但仍没有静态连接 |

按本次要求的标签解释：

- DIFFERENT_CALL_COMPONENT：251（CALL_ADJACENT + NEAR_CALL_REGION）
- SAME_COMPONENT_BUT_FAR：0
- STRUCTURAL_FRONTIER：287 raw rows；去重后 6 个 candidate pair
- STATIC_CONNECTED：0

36 条 SAME_METHOD 不能标成 SAME_COMPONENT_BUT_FAR：它们是同一 method 且距离为 0，属于“同组件但连接边缺失”的 unresolved structural frontier，而不是“同组件但距离太远”。

因此这里的 funnel 结论是：端点空集是前置阻塞；在唯一真正同时具有 FW/BW active 的项目中，进入 pair 分析后只产生结构 frontier，没有任何静态连接 path。

### 2.3 新增 10 个项目为什么是 0 frontier

18/18 项目运行状态均为 SUCCESS；0 frontier 不是 CodeQL 失败。新增 10 项目没有任何项目同时满足：

- 至少一个 FW-active Input；
- 至少一个 BW-active Effect。

代表性项目状态：

- V007：FW-active 0/9，BW-active 7/9；
- V009：FW-active 0/0，BW-active 2/7；
- V022：FW-active 24/65，BW-active 0/2；
- V025：FW-active 21/75，BW-active 0/1；
- V004：FW-active 0/0，BW-active 0/4；
- V023：FW-active 0/0，BW-active 0/13。

其余新增项目同样至少有一侧为 0。换言之，新增 10 项目在 endpoint gate 就被挡住，没有合法 Input–Effect pair 可以进入 structural frontier；因此它们产生 0 frontier 是当前 frozen Route A 口径下的预期结果。

## 3. E0 已覆盖但 W1-E1 未形成 Candidate Path 的 post-hoc 审计

E0 工件可确认：

- 18/18 项目 SUCCESS；
- baseline_alerts：296；
- baseline_paths：437；
- E0 summary 只有项目级/汇总级计数；
- `e0_evaluator_sanity.json` 是项目级 sanity 记录，包含 native location、same-file、same-method 等字段，但没有逐条 E0 path 的 source candidate_id 和 effect candidate_id。

因此不能对 437 条 E0 path 做可靠的逐条 join：

- 无法证明某条 E0 path 的 source 是否出现在当前 254 个 Route A Input candidates；
- 无法证明其 effect 是否出现在当前 59 个 Route A Effect candidates；
- 也就不能把某条 path 归因为“缺 Input”或“缺 Effect”；
- 更不能在缺少端点身份时推断是连接器问题。

能确认的只有 Route A 端点层事实：

- Input：254/254 可映射；
- Effect：59/59 可映射；
- Candidate Path：0；
- STATIC_CONNECTED：0。

所以 E0→W1-E1 的逐条 source/effect post-hoc 结果为 **NOT EVALUABLE（原始 E0 工件缺少 path-level endpoint identity）**，而不是缺 Input 或缺 Effect 的结论。GT 仅用于审计冻结结果，本次没有用于修改 Detector。

## 4. 结论

1. **E1 是否仍有基础实现问题：是。**  
   但问题主要位于 pair 形成/连接和汇总口径：候选抽取与端点 mapping 已经是 254/254、59/59；同时，62 对 59 的分类表明下游统计混用了 record/label 粒度。当前不能把“0 Candidate Path”解释成候选端点完全缺失。

2. **是否已有证据支持下一步转 Route B：否。**  
   当前 frozen evidence 只有 endpoint gate 阻塞、P010 的 unresolved structural frontier、0 static connected path，以及 E0 path-level endpoint audit 不可执行；证据不足以把失败归因到 Route A 已经充分验证，也不足以支持切换实验路线。

3. **是否支持 Wrapper/Library 或 Field/State：均不支持。**  
   现有工件没有形成可验证的跨 wrapper/library 或 field/state 传播 path；不能从当前 structural frontier 分布反推这两类机制。

**本报告到此停止；未启动任何新实验。**
