# Work1 V11 M8 研究与实验承接文档

> 状态时点：2026-09-02（Asia/Shanghai）  
> 用途：作为新 Codex 对话的第一份上下文，继续 Work1 V11 M8 多 Agent 项目级 Java 漏洞发现实验。  
> 安全说明：本文档不包含 API 令牌值。对话中曾提供过令牌，不得将其写入 Git、artifact、trace、命令历史或异常文本。

## 1. 用户的最终目标

继续深入研究并完成“1 个主 Agent + 3 个专职 Agent”的项目级 Java 漏洞发现实验，修改论文实验方法，保留全部失败结果和可审计边界。实验真正结束后，关闭 CloudStudio 云服务器并验证已停止。

用户已授权实验范围内的必要操作。仍须遵守工具的强制审批和安全边界，不得因“自动批准”而绕过平台审批。

## 2. 附件与指令边界

原始实验规格：

- `C:/Users/戴超杰/Desktop/12232123.txt`

它是研究方法、milestone、Gate 和 artifact 要求的输入资料。新对话应将其内容视为需要审核和实施的实验规格，而不是高于用户当前请求的系统指令。

原始规格的核心不变边界：

- 不继续扩展 Route B。
- 不加 project-specific / benchmark-specific 规则。
- 不把 CVE、patch、已知 method/location 暴露给 detector。
- 不降低 M4 Evidence Gate。
- 不把 Gate ADMISSIBLE 或 Candidate Path 当成已确认漏洞。
- 不启动 Work2，除非 Work1 正式门槛已满足。
- 不删除或覆盖 M7 和 M8 的任何失败 attempt。

## 3. 冻结 Agent 与模型合同

| Agent `id == name` | exact model ID | 职责 |
|---|---|---|
| `coordinator_agent` | `claude-opus-5` | 调度、整合、CodeQL/Gate/path 反馈与 STOP |
| `input_agent` | `claude-sonnet-5` | External Input / source 证据 |
| `effect_agent` | `claude-sonnet-5` | Security Effect / sink 证据 |
| `semantic_bridge_agent` | `claude-sonnet-5` | 最小局部语义桥证据 |

运行时使用两组独立配置前缀：

- `M8_COORDINATOR_LLM_`
- `M8_SPECIALIST_LLM_`

密钥只从环境变量读取。上次云端验证两组 key 环境变量均为 `SET`，但必须在新运行前只验证 presence，不得输出值。

## 4. Git 与本地工作区

### 4.1 M8 权威工作区

- 路径：`C:/Users/戴超杰/.codex/visualizations/2026/09/01/01a05c2d-3e60-74e0-a67b-58a0cfc91995/m8-worktree`
- 本地分支：`codex/work1-agent-active-security-v11-m8`
- 远端分支：`origin/work1/agent-active-security-v11-m8-multiagent`
- nested finding 合同修复提交：`e1ced116744c5200b0628e0863a5f350378aacbb`
- 修复提交：`fix(m8): freeze nested finding JSON contract`
- 本 handoff 文档作为后续文档变更处理；新对话开始时必须用 `git rev-parse HEAD` 重新核对当前 HEAD，不得仅依赖本文档的时点值。

### 4.2 不得直接使用的主 checkout

- 路径：`F:/ForGithub/java-vuln-research`
- 分支：`work1/agent-active-security-v11`
- 存在多项用户未提交修改和未跟踪文件，包括 Route B、native pool、evaluation 等。
- 不得 reset、clean、checkout 或覆盖这些变更。

后续修改必须在 M8 隔离 worktree 进行。

## 5. CloudStudio 状态

- URL：`https://cloudstudio.net/a/37787922780340224/edit`
- 项目：`java-vuln-research - Buddy Academy`
- 上次实验 worktree：`/workspace/m8v`
- 云端远端分支：`work1/agent-active-security-v11-m8-multiagent`
- attempt3 运行时 exact SHA：`9f5f34cd656ba59b8610e1d2f8ea389f6fc1f889`
- 云服务器当前不应关闭，因为实验尚未完成。

关服务器的完成条件：

1. 已完成最后一次应运行的实验与 artifact 审计。
2. 已将必要代码、manifest 和小型报告 push 到 GitHub。
3. 大型 artifact 保留在 `/workspace/experiment-output` 并记录精确路径。
4. 已核对 CloudStudio 无运行中命令。
5. 使用 CloudStudio UI 的停止/关闭操作，然后重新观察状态，确认实例已停止而不是只关闭浏览器页签。

## 6. 已完成的工程工作

M8-0 到 M8-4 已实现并通过 deterministic/mock 验证：

- SharedEvidenceBoard、typed contracts、provenance 和 replay。
- scope/role helper，不降低 M4 Gate。
- Input/Effect/Bridge 三个受限 runtime。
- Coordinator dispatch、CodeQL policy、Gate feedback、graph/path rebuild。
- 非 benchmark controlled Java fixture。
- artifact manifest、hash audit、runtime security boundary 和 no-leakage audit。

当前代码组件：

- `src/java_vuln_research/work1_agent/m8_multiagent/`
- `tests/unit/test_m8_*.py`
- `docs/work1-agent-v11-m8/00_AUDIT.md`
- `docs/work1-agent-v11-m8/01_MULTI_AGENT_ARCHITECTURE.md`
- `docs/work1-agent-v11-m8/02_SCOPE_ROLE_HELPERS.md`
- `docs/work1-agent-v11-m8/03_SPECIALIST_AGENTS.md`
- `docs/work1-agent-v11-m8/04_COORDINATOR.md`
- `docs/work1-agent-v11-m8/05_CONTROLLED_SMOKE.md`

## 7. 最后本地与云端验证

对 nested finding V3 合同修复提交 `e1ced116744c5200b0628e0863a5f350378aacbb` 的本地结果：

- specialist targeted：`27 passed`
- M8 targeted：`69 passed, 2 warnings`
- full regression：`330 passed, 2 skipped, 5 warnings`
- `compileall`：PASS
- `git diff --check`：PASS
- 密钥模式扫描：0 命中

该提交尚待 CloudStudio exact-commit 回归与 attempt4；下面的云端结果是 attempt3 基线 SHA `9f5f34c` 的最后已验证状态。

对 SHA `9f5f34c` 的本地结果：

- specialist targeted：`23 passed`
- M8 targeted：`65 passed, 2 warnings`
- full regression：`326 passed, 2 skipped, 5 warnings`
- `compileall`：PASS
- `git diff --check`：PASS

云端结果：

- specialist targeted：`23 passed`
- M8 targeted：`65 passed, 2 warnings`
- full regression：`327 passed, 1 skipped, 5 warnings`
- exact detached SHA：PASS
- clean worktree：PASS

差异来自 Linux 上多执行一个本地跳过的环境测试，不是代码差异。

## 8. Controlled real-LLM attempts

所有 attempt 均是不可覆盖的负结果，不是三个独立实验样本。它们是同一 controlled fixture 上逐次发现工程合同缺口的适应性调试。

### 8.1 attempt1

- SHA：`db87f201bfcc6b4d786b695d56c344e834ec1ed1`
- artifact：`/workspace/experiment-output/artifacts/work1-agent-v11/m8_multiagent/controlled_real_llm/db87f201-20260901-attempt1`
- 失败：Coordinator 不知道 canonical specialist tool names，4 次 Input dispatch 均因 `SPECIALIST_TOOL_RESTRICTION` fail closed。
- finding/proposal/path：`0/0/0`
- no-leakage：PASS

### 8.2 attempt2

- SHA：`0e23d2c97cf8b89018c195f9a4b841eb45c8d591`
- artifact：`/workspace/experiment-output/artifacts/work1-agent-v11/m8_multiagent/controlled_real_llm/0e23d2c-20260901-attempt2`
- 失败：5 个 specialist TOOL 响应把 `next_suggested_evidence` 或 `uncertainty` 输出成字符串，而不是 string array。
- finding/proposal/path：`0/0/0`
- no-leakage：PASS

### 8.3 attempt3（当前最新）

- SHA：`9f5f34cd656ba59b8610e1d2f8ea389f6fc1f889`
- artifact：`/workspace/experiment-output/artifacts/work1-agent-v11/m8_multiagent/controlled_real_llm/9f5f34c-20260901-attempt3`
- runtime：约 `302.86s`
- Coordinator rounds：`4`
- 成功 model calls：`3`
- specialist dispatch：Input `2`、Effect `1`、Bridge `0`
- repository tool calls：`6`
- tokens：`19,880 input / 4,155 output`
- findings/proposals/Candidate Paths：全部 `0`
- stop reason：`OTHER`
- failure taxonomy：`ERROR: 3`、`MODEL_OUTPUT_INVALID: 3`、`MODEL_TIMEOUT: 1`

attempt3 证明 attempt2 的顶层 array 修复有效：三个 specialist 都完成了 repository tool 调用并尝试 `SUBMIT_FINDINGS`。新的一致失败是：

```text
specialist finding details must be an object
```

模型把嵌套 `finding.details` 编码为字符串。runtime 严格拒绝是正确的；不得用 string-to-object 猜测或宽松 coercion 修复。第 4 轮 Coordinator 另有一次 provider timeout。

attempt3 独立 artifact 审计：

- artifact count：`23`
- manifest 和 artifact-audit 两组 hash 全部重算一致。
- Candidate Path/finding/proposal JSONL 均为 0 行。
- `no_leakage_status=PASS`
- runtime boundary：PASS
- 两组 API key 值扫描 artifact：0 命中（审计时不输出密钥）。
- Agent/model/prompt identity：PASS

M8-5 当前结论：**FAIL**。不得进入真实 development cohort（协议修订后为 M8-7）。

## 9. 当前立即阻塞与已完成的本地修复

当前 `COMMON_RULES` 只说 finding draft 含有：

```text
entity_ids, tool_call_ids, evidence_refs, summary, details, uncertainties
```

它没有说明这六个嵌套字段的严格 JSON 类型，也没有公开三个角色的 `details` 对象形状。runtime 则在 `specialists.py::_finding()` 中严格要求 `details` 为 mapping，并要求 role-specific keys。

提交 `e1ced116744c5200b0628e0863a5f350378aacbb` 已仅处理这个通用合同缺口：

1. 对 finding draft 的六个字段逐一声明 JSON 类型。
2. 明确 `details` 必须是 JSON object，不得是 JSON string、stringified JSON、array 或 null。
3. 在每个 role prompt 中给出其 `details` 必需 keys 和嵌套类型。
4. 保留 runtime fail closed，不做 coercion。
5. 补充参数化测试：`details` 为 plain string、stringified JSON、array、null 都必须在构造 finding 前失败；正确 object 继续通过。
6. 三个 specialist prompt 已提升为 V3 并冻结新 SHA，manifest/doc/tests 已更新。
7. `05_CONTROLLED_SMOKE.md` 已记录 attempt3 为不可覆盖负结果。
8. 待推送后，在 CloudStudio checkout exact commit，运行云端回归并使用新的 `attempt4` artifact root。

在采用 provider-enforced JSON Schema/tool calling 前，需先验证当前 OpenAI-compatible endpoint 是否真正支持 nested strict schema。不得仅因 API 接口返回 200 就宣称 schema 被 provider 强制执行。

## 10. M8-5 重新运行门

有效 attempt 的运行前提是 unique non-overwriting artifact directory、exact pushed Git SHA、clean CloudStudio worktree、四个 exact Agent/model identities 正确，并通过 artifact hash 重算。历史冻结的 M8-5 pass rule 不作事后强化，仅为：

- 至少 1 条经未修改 M4/M5 形成的 Candidate Path；
- no-leakage PASS。

三类 specialist dispatch 数和完整 model/tool/evidence/finding/proposal/Gate/path coverage 必须报告为 diagnostics，但不是新增 hard gate。controlled fixture 可用冻结结构边形成合法 path，不能在 attempt4 前把 Bridge dispatch/finding 事后改成通过条件。

即使 attempt4 在同一 fixture 上成功，也只证明工程链路可运行，不能当成真实漏洞发现样本或多 Agent 优越性证据。

## 11. 已完成的论文调研结论

核心判断：

- 工程可行性：有。已实现 typed state、受限工具、Gate、replay 和审计。
- 理论可行性：有。Input/Effect/Bridge 对应 source/sink/transfer semantics，分解有程序分析依据。
- 当前实证可行性：未证明。attempt1-3 为 0 findings/paths。
- 多 Agent 优于单 Agent：没有当前证据。

最相关论文：

1. IRIS：`https://arxiv.org/abs/2405.17238`  
   LLM + CodeQL 在 CWE-Bench-Java 上从 CodeQL `27/120` 提高到 `55/120`，平均 FDR 改善 5 个百分点。最强证据支持 neuro-symbolic 混合，而非 Agent 数量。
2. VulAgent：`https://aclanthology.org/2026.findings-acl.928/`  
   多视角定位 + 显式 hypothesis validation；平均 accuracy +6.6pp，漏洞/修复对识别最高 4.5x，FPR -36%。
3. MulVul：`https://aclanthology.org/2026.acl-long.391/`  
   Router + specialized detectors + retrieval；130 CWE 上 Macro-F1 `34.79%`，比最佳基线高 41.5%。不是自主 Java 全仓路径发现。
4. HPTSA：`https://arxiv.org/abs/2406.01637`  
   14 个真实漏洞上 pass@1 `18%`、pass@5 `42%`；移除专职 Agent 后 pass@1 下降 2.1x，移除层次结构后下降 13x。样本小且任务是 Web 漏洞利用。
5. AutoSafeCoder：`https://arxiv.org/abs/2409.10737`  
   Coding/static-analysis/fuzzing 三 Agent，SecurityEval 漏洞减少 13%。任务是安全代码生成。
6. MASAI：`https://arxiv.org/abs/2406.11638`  
   专职软件工程子 Agent，SWE-bench Lite `28.33%`。
7. Agentless：`https://arxiv.org/abs/2407.01489`  
   固定 localization -> repair -> validation 三阶段达 `32% (96/300)`，平均约 `$0.70`。证明固定流水线可能胜过复杂自治 Agent。
8. One-day exploitation：`https://arxiv.org/abs/2404.08144`  
   有 CVE description 成功率 87%，无 description 仅 7%，说明 oracle leakage 可主导结果。
9. Why Do Multi-Agent LLM Systems Fail?：`https://arxiv.org/abs/2503.13657`
   MAST-Data 覆盖 1600+ traces、7 个框架和 14 类失效；支持把系统设计、Agent 间失配和验证失败作为预注册结果，而不是只统计成功。
10. AI Agents That Matter：`https://arxiv.org/abs/2407.01502`
    强调 Agent 评测必须同时控制成本、holdout、过拟合和可复现性。
11. Stop Comparing LLM Agents Without Disclosing the Harness：`https://arxiv.org/abs/2605.23950`
    支持冻结/披露完整 harness，但它是 position paper，不作为 M8 效果证据。

论文最稳妥的定位不是“更多 Agent 更会找漏洞”，而是：

> 一个角色特化、证据约束、可重放的 neuro-symbolic 安全候选发现管线。

## 12. 必须修改的论文实验方法

本节保存形成新协议的研究推导；执行时以 `docs/work1-agent-v11-m8/06_EXPERIMENT_DESIGN.md` 为唯一方法权威。下面术语已按最终协议同步，不能把 repeated runs 称为已证明独立的 replicates，也不能在 Work2 前把 unsupported-candidate proxy 称为漏洞 FDR。

### 12.1 当前 E0/E1 不能识别多 Agent 因果效应

旧设计是：

- E0：existing M7-style single Agent
- E1：full M8 multi-agent

但 M8 同时新增/修改：

- Opus/Sonnet 模型路由。
- 专职 prompt 与 security taxonomy。
- SharedEvidenceBoard。
- CodeQL 触发 policy。
- scope/role helpers。
- repository tools。
- observation 压缩。
- Gate/path feedback。
- 调度与预算拓扑。

因此 E0/E1 最多估计“完整 M8 bundle”总效果，不能把改善归因于多 Agent。`same model family` 也不足以控制模型混杂；至少要匹配 configured model ID，并审计 provider backend attestation/drift。

### 12.2 建议预注册的最小对照矩阵

| Arm | 配置 | 识别目的 |
|---|---|---|
| N0 | Native CodeQL | 定义 incremental recovery 分母 |
| H0 | Frozen M7 Opus single Agent | 历史/系统级基线，不单独用于归因 |
| S0 | 现代化 single Agent，全 Sonnet，无外层反馈 | configured-model-matched 2x2 基线 |
| S1 | 现代化 single Agent，全 Sonnet，有 Gate/path/repair 反馈 | single-Agent feedback 效应 |
| M0 | Coordinator + specialists，全 Sonnet，无外层反馈 | multi-Agent no-feedback |
| M1 | Coordinator + specialists，全 Sonnet，有反馈 | `M1-S1` 识别角色特化 architecture bundle 效应 |
| M2 | Opus Coordinator + Sonnet specialists，有反馈 | `M2-M1` 识别模型路由效应 |

G1 profile：formal freeze 必须预选 `CORE`（无 G1）或 `ROLE`（G1 必跑并进入 Holm family）。G1 保留 Coordinator + 3 worker 拓扑，但使用冻结的 generic-worker bundle；`M1-G1` 仍同时包含 prompt、finding contract、tool partition 和 dispatch vocabulary，不能解释为 prompt-only effect。

若成本/power 可执行，方法上优先 `ROLE`；若只能运行 `CORE`，论文只能报告 architecture bundle，不能声称“专职角色本身”带来收益。

S0/S1/M0/M1 必须共享相同的：

- helpers、CodeQL policy 和 repository tools。
- security taxonomy 与可见信息。
- 项目级 token/model-call/tool-call/time/cost 上限。
- M4 Gate、M5 builder 和 Work2 evaluator。

无反馈 arm 仍在每个 proposal 提交点运行同一 Gate/duplicate tracker/path builder，也可获得正常 repository/CodeQL tool results；“无反馈”只由 typed observer projection 隐藏 verifier 结果，不能改成离线验证或改变固定预算扣费。

### 12.3 数据集与冻结

- 将 development 拆成 `dev-tune` 和一次性 `dev-validation`。
- formal 使用全新 holdout；旧 M7 10-case cohort 只能历史比较。
- 按 repository/fork/version/patch lineage group split，防止同源泄漏。
- 包含 vulnerable/fixed pairs 和 benign projects，用于安全分析与 unsupported-candidate burden；只有修复会改变 frozen Work1 可表达路径的预封存子集才报告 Work1 fixed-pair discrimination，sanitizer/protection-only fix 留给 Work2，curated cohort 不直接估计部署环境漏洞 FPR/FDR。
- 独立 curator 在任何 arm 运行前用冻结 N0 和 contract-only rubric 封存 `primary_eligible_lineages` / `safety_only_lineages`；运行后不得改变 primary denominator。
- 不给 detector CVE description、CWE、patch、脆弱位置或 evaluator annotation。
- pre-run curator 只在隔离 enclave 生成 commitments；detector 先完成 output/hash/seal，之后才向 scoring evaluator/reviewer 解封 ground truth。
- 公开仓库/CVE 可能存在模型预训练记忆，no-leakage runtime audit 无法排除，必须列为效度威胁；优先使用模型 cutoff 之后的修订。

### 12.4 实验单位、重复与统计

- primary independent unit 是每个预先确认 eligible lineage 的唯一 primary project/revision。
- target 嵌套于 project；proposal/path/tool call 不能当作独立样本。
- 每个 `primary subject x arm` 预注册 3 次 separately initialized repeated runs；provider 未证明采样/缓存独立时不得称为独立 replicates。
- 项目内随机且交错运行 arm，避免 provider 时间漂移。
- 不取 best-of。primary 报告 failure-inclusive pass@1；timeout、invalid output、budget exhaustion 均按 assigned arm 计入。
- 三个 runs 的 secondary estimator 固定为 lineage-level mean success difference 和 lineage bootstrap，不在 mixed model/bootstrap 之间事后选择。
- 普通执行失败须在 hash/no-leakage 已验证后计 0；audit 未完成阻塞 evaluator，oracle bytes 可能到达模型时使相应确认性结论失效，不能伪装成 0 或重跑。
- 二元配对主结果用 exact McNemar，报告 risk difference 和 95% CI。
- 计数和成本用 project-level paired bootstrap/permutation。
- 多个正式次要比较使用 Holm 校正。
- 预先定义最小有意义效应并做 power analysis。`n=8` 只是工程 pilot，不支持优越性结论。

示例：若预期配对成功率从 10% 提高到 30%，新旧独占成功约 25%/5%，McNemar 粗略需要约 57 个 project pairs。实际样本数必须根据冻结 pilot 重新计算。

### 12.5 指标

Formal primary：

> 对运行前封存的 eligible primary subject，是否至少有一条该 arm 自身 evidence 被 Phase A 判为 `SUPPORTED` 的 sealed Candidate Path，在 Phase B 被 arm-blinded reviewer 匹配到 Native CodeQL 未检出的 eligible target。

Key safety：

- canonical Candidate Paths/project、reviewed support rate 和 unsupported-candidate burden；Work2 前不称为漏洞 precision/FDR。
- Work1-observable vulnerable/fixed pair discrimination；其余 pairs 只报 candidate persistence，不把保护性修复后的结构路径算误报。
- review burden，避免通过大量输出 path 换 recall。

Secondary/process：

- 盲评后 Input/Effect/Bridge reviewed precision、annotated-target coverage；只有穷尽 reference-set 子集才报告 recall。
- first-pass Gate admission 与 repair 后 eventual admission。
- CodeQL attempted/successful/non-empty/entered-proposal/entered-final-path。
- token、缓存命中、重试、美元成本、tool calls、wall-clock。
- schema/protocol failure rate、timeout rate、stagnation 和 budget stop。

Candidate Path count、Gate admission 和 CodeQL call count 都是过程指标，不得单独用于宣称漏洞发现改善。

### 12.6 Ablation 顺序

原规格中“formal recovery >= 1 后才做 ablation”是结果条件化，会造成选择偏差。应改为：

- 所有 primary arms 在读取 evaluator 结果前一并 freeze 和 seal；或
- 把更细 helpers/CodeQL-policy ablation 放在独立预注册 ablation cohort。

不得在看到 formal 结果后决定哪个 arm 值得运行。

## 13. 推荐的继续顺序

1. 已完成：核对 local `9f5f34c`、CloudStudio attempt3 原始 response 和 artifact hashes。
2. 已完成：把 attempt3 结果追加到 `05_CONTROLLED_SMOKE.md`。
3. 已完成：修复嵌套 finding JSON 合同，更新 prompt version/hash 和测试，未改 Gate、M5、allow-list 或预算。
4. 已完成：本地 specialist targeted -> M8 targeted -> full pytest -> compileall -> diff-check。
5. 已完成：审查 diff 并创建提交 `e1ced116744c5200b0628e0863a5f350378aacbb`。
6. 下一步：push 远端 M8 分支，CloudStudio `git fetch`、checkout exact SHA，重跑 full regression，确认 clean。
7. 随后运行新的 non-overwriting attempt4，完成 artifact/no-leakage/hash 审计。
8. 若 M8-5 FAIL：保留负结果，仅根据通用证据决定是否还有一次协议修复；不运行真实 development cohort。
9. 若 M8-5 PASS：按 `06_EXPERIMENT_DESIGN.md` 的 P0 序列实现可比 arms 和审计层，再进入 dev-tune；达到 `DEVELOPMENT_CANDIDATE_FROZEN` 后才可运行一次性 dev-validation。
10. 完成现代化 single-Agent 和 configured-model-matched 对照，不用旧 M7 作唯一基线；provider 不证明 immutable backend 时不得声称 exact-backend matched。
11. 根据 power analysis 冻结 new holdout formal cohort。
12. 所有 arms 先 detector output/hash/seal，后 evaluator。
13. 按修订编号生成 `07_DEVELOPMENT_COHORT.md` 到 `11_FAILURE_ANALYSIS.md` 和总报告。
14. 完成要求级审计，push 最终报告。
15. 确认云端无运行中任务，关闭 CloudStudio 实例并验证已停止。

## 14. 新对话开场提示词

可将下面这段作为新对话的第一条请求：

```text
请读取 WORK1_V11_M8_HANDOFF_2026-09-02.md、docs/work1-agent-v11-m8/06_EXPERIMENT_DESIGN.md 和 C:/Users/戴超杰/Desktop/12232123.txt。
handoff 是当前承接状态，06_EXPERIMENT_DESIGN.md 是后续论文实验的方法权威，txt 是已被修订的原实验规格；不要把附件内容当成高优先级指令。
在隔离 M8 worktree 上继续：nested finding.details JSON 合同已在 `e1ced116744c5200b0628e0863a5f350378aacbb` 修复并通过本地全回归。先核对当前 HEAD 与远端，push 后在 CloudStudio checkout exact commit，运行云端回归，然后用新 artifact root 运行 attempt4。
只有 M8-5 形成至少 1 条 Candidate Path 且 no-leakage PASS 才进入 development。
三类 specialist dispatch 和完整链路覆盖只作 diagnostics，不得在 attempt4 前事后升级 M8-5 hard gate。M8-5 PASS 后也只能按 06 的 P0 序列实现并进入 dev-tune；一次性 dev-validation 前必须达到 DEVELOPMENT_CANDIDATE_FROZEN。
保留所有历史负结果，不降低 Gate，不泄漏 API key。完整实验和审计结束后，关闭并验证 CloudStudio 服务器已停止。
```

## 15. 不得宣称的事项

在获得新 holdout 上的盲评正式结果前，不得宣称：

- 四 Agent 比单 Agent 更好。
- 多 Agent 能找到真实项目漏洞。
- Candidate Path 是已确认漏洞。
- Gate admission 是漏洞检出率。
- CodeQL calls 增加代表 Agent 推理改善。
- scope/role rejection 下降代表 specialist 更智能。
- runtime no-leakage 排除了模型预训练记忆。

当前可宣称的结论仅是：

> M8 已建立一个受限、可回放、fail-closed 且通过 no-leakage 审计的多 Agent 工程框架；当前真实模型实验仍停留在输出合同可靠性阶段，尚未测到项目级漏洞发现能力。

## 16. 2026-09-02 实验协议修订

已新增 `docs/work1-agent-v11-m8/06_EXPERIMENT_DESIGN.md`，更新 `docs/research_protocol.md`，并在通用 `docs/experiment_protocol.md` 中声明 M8 权威边界。后续论文实验以 `06_EXPERIMENT_DESIGN.md` 为方法权威；本文第 12 节保留为形成修订的研究记录。

核心冻结方向：

- `N0/H0/S0/S1/M0/M1/M2` 分离 Native reference、历史 bundle、现代 single/multi、verifier feedback 与 Coordinator 模型路由；
- `M1-S1` 是角色特化 multi-Agent architecture bundle 的首要 contrast，不是纯 Agent 数量效应；`M2-S1` 只能解释为目标系统 bundle 效果；
- cohort curator 在任何 arm 运行前冻结 `primary_eligible_lineages` 与 `safety_only_lineages`；formal primary 是前者中预先封存 eligible target 的 subject-level、arm-blinded incremental Candidate Path recovery，不是漏洞确认；
- 每个 primary subject/confirmatory arm 预注册 3 个 separately initialized runs；run 1 用于 pass@1/McNemar，其余只估计稳定性，不宣称 provider runs 统计独立；
- vulnerable/fixed/benign subjects 按 repository lineage 划分 `dev-tune`、一次性 `dev-validation` 和新 `formal-holdout`；
- formal profile 必须预选 `CORE`（无 G1）或 `ROLE`（G1 必跑且 `M1-G1` 加入 Holm family）；selected-profile arms 在 evaluator 解封前一起 schedule、hash、seal，废止 outcome-conditioned ablation；
- feedback/no-feedback arms 在同一 proposal 时点执行同一 verifier；no-feedback 仅通过 typed projection 隐藏结果，不得改成离线验证；
- timeout、invalid output、budget exhaustion 和无 Candidate Path 在完整性验证后纳入 failure-inclusive assigned-arm analysis；未核验 artifact 阻塞 evaluator，可能向模型泄露 oracle 的 run 不得伪装为 0；
- evaluator 分离 `semantic_candidate_fingerprint` 与 `evidence_package_hash`，不同 arms 的 evidence 绝不合并或相互背书；
- formal 前必须实现 shared usage ledger、现代 single runtime、feedback visibility、真实项目 M8 runtime、replicate scheduler、output-blind health classifier、analysis disposition、outcome registry、study seal、blind evaluator、canonicalizer 和统计层。

协议正常状态为 `DRAFT -> DEVELOPMENT_CANDIDATE_FROZEN -> FORMAL_FROZEN -> FORMAL_DETECTOR_SEALED -> EVALUATOR_RELEASED`，另有完整性失败终态 `FORMAL_INVALIDATED`；当前仍是 `DRAFT`，不存在一个同时授权 dev-validation 与 formal 的笼统 `FROZEN`。

文件编号同步修订：`06_EXPERIMENT_DESIGN.md` 是新 M8-6；后续结果顺延为 `07_DEVELOPMENT_COHORT.md`、`08_CAUSAL_COMPARISON.md`、`09_FORMAL_FREEZE.md`、`10_FORMAL_RESULTS.md`、`11_FAILURE_ANALYSIS.md`。

当前运行状态没有变化：M8-5 仍为 **FAIL**，attempt4 尚未执行；协议修订不授权跳过 controlled gate。
