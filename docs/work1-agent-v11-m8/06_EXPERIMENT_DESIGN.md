# Work1 V11 M8：多 Agent 因果实验设计与预注册协议

> 协议状态：`DRAFT / NOT DEVELOPMENT_CANDIDATE_FROZEN / NOT FORMAL_FROZEN`
> 版本日期：2026-09-02（Asia/Shanghai）
> 当前工程门：M8-5 `FAIL`；本文不授权启动 development 或 formal run。

## 1. 协议地位与当前结论

本文是 M8 后续开发比较、冻结和正式评测的实验方法权威文件。它修订原始规格中不足以支持因果归因的 E0/E1 设计，但不改写或删除 M7、M8 attempt1--3 的历史结果。

截至本文版本：

- `coordinator_agent` / `claude-opus-5` 与三个 Sonnet specialist 的目标系统具有工程可行性，但真实模型链路尚未通过 M8-5；
- attempt1--3 均为同一 controlled fixture 上的适应性协议调试，不是三个独立样本；
- 当前没有证据表明四 Agent 优于单 Agent，也没有项目级真实漏洞发现结果；
- `ADMISSIBLE`、Candidate Path、Gate admission 和 CodeQL call 均不能解释为漏洞确认；
- 只有 M8-5 在新的不可覆盖 attempt 中同时形成至少一条 Candidate Path、通过 no-leakage 与 artifact hash 审计，才允许执行 development；
- 即使 controlled smoke 通过，也只证明链路可运行，不能进入论文效果表。

可行性判定分三层：

| 层次 | 当前判定 | 证据 |
|---|---|---|
| 工程概念 | 有条件可行 | typed board、受限 tools、Gate、M5、replay/no-leakage 已实现；真实输出合同仍未过 M8-5 |
| 因果识别 | 设计上可行 | 本文用 configured-model-matched single/multi、feedback 和 routing arms 拆开原 E0/E1 bundle；backend 未经 provider attestation 时单列限制 |
| 当前可执行性 | 不可执行 | 现代 single runtime、M0/M1 model injection、shared ledger、scheduler、study seal、盲评与统计层尚缺 |
| 统计/成本 | 尚未证明 | 需要一次性 validation、power simulation 和总成本预算；8-project pilot 不足以支持优越性结论 |

所以，“主 Agent + 三专职 Agent”是一个可以被严格检验的假设，不是当前已被支持的结论。

本文取代以下旧条款：

1. `docs/work1-agent-v11-m8/00_AUDIT.md` 中把 M7 E0 与完整 M8 E1 直接用于证明多 Agent 收益的设计；
2. 原规格中“正式结果至少 1 个 recovery 后才决定是否运行消融”的结果条件化规则；
3. `docs/research_protocol.md` 中 whole-project agents 被排除、formal 只运行一次、detector manifest 固定为四字段的旧限制；
4. 原 M8-6 至 M8-10 的文件编号。本文为新的 M8-6；后续结果文档顺延为 `07_DEVELOPMENT_COHORT.md`、`08_CAUSAL_COMPARISON.md`、`09_FORMAL_FREEZE.md`、`10_FORMAL_RESULTS.md` 和 `11_FAILURE_ANALYSIS.md`。

不被取代的边界包括：不扩展 Route B、不降低 M4 Gate、不修改 M5 原生路径语义、不向 Detector 暴露 CVE/CWE/patch/已知位置、不覆盖失败 artifact、不在看到 formal evaluator 结果后调 Detector，以及 Work1 未过门时不启动 Work2。

## 2. 文献证据与可外推边界

| 工作 | 经核验的主要结果 | 对 M8 的方法含义 | 不能外推的结论 |
|---|---|---|---|
| *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities*（Li, Dutta, Naik；ICLR 2025；[arXiv:2405.17238v3](https://arxiv.org/abs/2405.17238v3)） | CWE-Bench-Java 120 个漏洞上，CodeQL 发现 27 个，IRIS+GPT-4 发现 55 个；平均 FDR 改善 5 个百分点 | 支持 LLM 与静态分析互补，要求保留 Native CodeQL 增量分母 | 不支持“Agent 数量”因果效应；其 target-CWE prior 与本研究 no-prior 设置不同 |
| *VulAgent: Hypothesis-Validation Driven Multi-Agent Architecture for Vulnerability Detection*（Wang et al.；Findings ACL 2026；[DOI](https://doi.org/10.18653/v1/2026.findings-acl.928)） | 多视角定位与显式 hypothesis validation；平均 accuracy +6.6pp，vulnerable/fixed pair 识别平均 2.46x，FPR 降低 36% | 支持把角色化观察、假设验证、fixed-pair discrimination 和 FPR 纳入设计 | 代码单元分类结果不能证明自主 Java 全仓路径发现 |
| *MulVul: Retrieval-augmented Multi-Agent Code Vulnerability Detection via Cross-Model Prompt Evolution*（Wu et al.；ACL 2026；[DOI](https://doi.org/10.18653/v1/2026.acl-long.391)） | Router + specialized detectors + retrieval；130 CWE 上 Macro-F1 34.79% | 支持测试专职语义与路由 | PrimeVul 上的 C/C++ function-level multiclass classification、retrieval 和 prompt evolution 与 M8 无先验 Java 项目探索不同 |
| *Teams of LLM Agents can Exploit Zero-Day Vulnerabilities*（Zhu et al.；[arXiv:2406.01637v2](https://arxiv.org/abs/2406.01637v2)） | 14 个 Web 漏洞上 pass@1 18%、pass@5 42%；作者报告移除 task-specific agents 后 pass@1 低 2.1x、pass@5 低 50%，移除 hierarchy 后分别低 13x、6x | 支持 Coordinator-specialist 与层次结构消融，也说明随机运行需重复 | 论文未为这些消融给出 p-value/CI；小样本 Web exploitation 不能证明 Java 静态漏洞发现 |
| *MASAI: Modular Architecture for Software-engineering AI Agents*（Arora et al.；[arXiv:2406.11638v1](https://arxiv.org/abs/2406.11638v1)） | 模块化子 Agent 在 SWE-bench Lite 达 28.33% | 支持清晰职责与局部上下文可能降低长轨迹成本 | 软件修复不是安全候选发现；不能替代安全专职语义对照 |
| *AutoSafeCoder*（Nunez et al.；NeurIPS 2024 SafeGenAI workshop；[arXiv:2409.10737v2](https://arxiv.org/abs/2409.10737v2)） | Coding、static-analysis、fuzzing 三 Agent 在 SecurityEval 上相对 baseline 报告漏洞减少 13% | 支持把生成、静态验证和动态反馈分工 | 安全代码生成不是既有 Java 项目的 whole-repository vulnerability discovery；不能提供 M8 效果量 |
| *Agentless: Demystifying LLM-based Software Engineering Agents*（Xia et al.；[arXiv:2407.01489v2](https://arxiv.org/abs/2407.01489v2)） | 固定 localization--repair--validation 流程在 SWE-bench Lite 达 32%（96/300），平均成本约 0.70 美元 | 要求保留现代化 single-Agent/fixed-pipeline 基线，不能默认自治越复杂越好 | 软件修复分数不能作为 M8 效果量 |
| *LLM Agents can Autonomously Exploit One-day Vulnerabilities*（Fang et al.；[arXiv:2404.08144v2](https://arxiv.org/abs/2404.08144v2)） | 有 CVE 描述时 GPT-4 成功率 87%，无描述时 7% | 直接支持 oracle 信息隔离与 Detector/Evaluator 分离 | 只证明显式描述影响，不能证明 runtime no-leakage 已排除预训练记忆 |
| *Why Do Multi-Agent LLM Systems Fail?*（Cemri et al.；[arXiv:2503.13657v3](https://arxiv.org/abs/2503.13657v3)） | MAST-Data 含 1600+ 条、7 个框架的 traces；14 类失效归入系统设计、Agent 间失配和任务验证，taxonomy 人工标注 kappa=0.88 | 要求预注册失败分类、通信/验证审计，并把“多 Agent 可能失败”作为一等结果 | 跨编码、数学和通用 Agent 的 failure taxonomy 不能提供 M8 的效果量 |
| *AI Agents That Matter*（Kapoor et al.；[arXiv:2407.01502v1](https://arxiv.org/abs/2407.01502v1)） | 指出 Agent benchmark 常忽略成本、holdout、过拟合和可复现性 | 支持同时报告质量/成本、使用 lineage holdout、公开完整配置与失败 | 方法批评不能证明任何具体 M8 arm 更优 |
| *Stop Comparing LLM Agents Without Disclosing the Harness*（Zhang et al.；未同行评审 position paper；[arXiv:2605.23950v1](https://arxiv.org/abs/2605.23950v1)） | 论证 context、tools、orchestration、verification 等 harness 差异可反转模型排名 | 要求公开并冻结完整 harness，分离模型、反馈和拓扑处理因素 | 不作为 M8 有效性的实证证据 |

因此，论文可检验的定位是：

> 一个角色特化、证据约束、可回放的神经符号安全候选发现管线，是否在同模型、同工具、同反馈与同项目级预算条件下，提高 Native CodeQL 未覆盖目标的项目级候选恢复概率。

在正式盲评前，论文不得使用“多 Agent 更强”“发现真实漏洞”或“证明自主审计有效”等表述。

## 3. 研究问题、处理因素与 estimand

### 3.1 Confirmatory research questions

- **RQ1 Architecture bundle**：在全 Sonnet、相同 feedback、tools、helpers、Gate、path builder 和项目级预算下，Coordinator + 三个角色特化 specialists 相比现代化 single Agent 是否提高项目级 incremental candidate recovery？该处理同时改变协调拓扑、上下文边界和角色 prompt 分区，不解释为“仅增加 Agent 数量”的纯效应。
- **RQ2 Feedback**：把 Gate/path/scope-role repair 结果重新送回模型，是否分别改善 single-Agent 与 multi-Agent 的项目级 recovery？
- **RQ3 Routing**：在相同 multi-Agent harness 下，把 Coordinator 从 Sonnet 改为 Opus 是否改善 recovery，其成本和失败率代价是多少？
- **RQ4 Safety/efficiency**：效果是否以更多 unsupported candidates、fixed/benign 误报、review burden、tokens、model calls 或 wall-clock 为代价？

### 3.2 预注册 estimands

对 formal `primary_eligible_lineages` 中每个 lineage 预注册的唯一 primary project/revision 单元 `p`，令 `Y_{p,r}(a; U_{p,r,a})` 表示 arm `a` 在 separately initialized run `r` 和冻结执行条件下，受模型/provider 随机性 `U` 影响时是否恢复至少一个 Native CodeQL 未覆盖的 eligible target。

primary estimand 是固定 cohort 上 `r=1` assigned runs 的 `M1-S1` 配对风险差；它是预先选择的一次 pass@1 实现，不宣称消除了模型随机性。其余 contrast 是 pre-specified secondary estimands。secondary stochastic estimand 使用三个 runs 的 project-level 平均成功概率与 run-to-run variance。下面 shorthand `Y(a)` 均指 `Y_{p,1}(a; U_{p,1,a})`：

- 架构效应：`E[Y(M1) - Y(S1)]`；
- multi-Agent feedback 效应：`E[Y(M1) - Y(M0)]`；
- single-Agent feedback 效应：`E[Y(S1) - Y(S0)]`；
- 模型路由效应：`E[Y(M2) - Y(M1)]`；
- 目标系统总效果：`E[Y(M2) - Y(S1)]`，只解释为“目标 bundle 相对现代 single Agent”的效果。

`M1-S1` 是论文的首要因果 contrast，estimand 是资源匹配条件下“角色特化 multi-Agent architecture bundle”的效果，不是 Agent 数量的纯效应。`M2-S1` 不能单独归因于多 Agent，因为它还包含 Coordinator 模型路由变化。

### 3.3 角色专职语义问题与 G1 profile

`G1` 用相同 Coordinator + 三 worker 拓扑和全 Sonnet 模型，但三个 worker 共享同一 generic-security prompt、generic finding contract 和只读工具并集。它与 `M1` 共享 worker 数、最大 dispatch、通信轮数、board envelope、verifier、feedback 和项目级预算。`M1-G1` 被明确解释为“角色专职 bundle”，包括 role prompt、role-specific finding contract、tool partition 和 Coordinator dispatch vocabulary，不能缩写为 prompt-only effect；`G1-S1` 仍同时包含上下文分区与 Coordinator 控制差异。

formal freeze 必须在下列两个 profile 中二选一并 hash，之后不得改变：

- `CORE`：不运行 `G1`，不对角色专职 bundle 作 confirmatory 结论；
- `ROLE`：`G1` 是必跑 confirmatory arm，`M1-G1` 加入 secondary Holm family，power、schedule 和成本按增加后的 arm 数重新计算。

若 `G1` 没有按 `ROLE` profile 与其他 arms 一起注册、运行和封存，任何事后 `G1` 结果都只能标为 exploratory。更细的 prompt/schema/tool-partition 分解需要新的 factorial cohort，不能从 `M1-G1` 单独归因。

方法上优先 `ROLE`，因为它能回答“专职”是否在相同多调用拓扑上提供增量；若 formal cost/power budget 无法支持，则选择 `CORE` 并把结论严格限制为 architecture bundle，不得仍声称角色专职本身有效。

## 4. Arm 注册表

| Arm | 配置 | 用途 | 因果地位 |
|---|---|---|---|
| `N0` | exact frozen Native CodeQL | 定义增量恢复分母和 native preservation | deterministic reference |
| `H0` | 已冻结 M7 Opus single Agent | 保存历史系统结果 | historical only；不参与纯架构归因 |
| `S0` | 现代化 single Agent；全 Sonnet；无 verifier feedback | single no-feedback 基线 | confirmatory |
| `S1` | 现代化 single Agent；全 Sonnet；有 verifier feedback | single feedback 基线 | confirmatory |
| `M0` | Sonnet Coordinator + 三个 Sonnet specialists；无 verifier feedback | multi no-feedback | confirmatory |
| `M1` | Sonnet Coordinator + 三个 Sonnet specialists；有 verifier feedback | configured-model-matched multi | confirmatory |
| `M2` | Opus Coordinator + 三个 Sonnet specialists；有 verifier feedback | 用户指定的目标系统 | confirmatory system arm |
| `G1` | 全 Sonnet；相同 multi 拓扑与 verifier feedback；generic worker bundle | 角色专职 bundle 对照 | `ROLE` profile confirmatory；否则不进入 formal |

表中名称是论文 shorthand。机器 artifact/manifest 的 exact `arm_id` 使用 `m8_n0 / m8_h0 / m8_s0 / m8_s1 / m8_m0 / m8_m1 / m8_m2 / m8_g1`，避免与既有 M1--M5 程序分析 milestone 混淆。

`M2` 保持冻结身份：`coordinator_agent` 使用 `claude-opus-5`；`input_agent`、`effect_agent`、`semantic_bridge_agent` 使用 `claude-sonnet-5`；四者均 `id == name`。控制 arms 的模型变化是实验处理，不修改 `M2` 合同。`semantic_bridge_agent` 是 registry ID；`BRIDGE_AGENT` 和 `BRIDGE_FINDING` 分别是 role/finding enum，不得混写为不存在的 `bridge_agent`。

IRIS 等读取 target-CWE 或 query/fix 先验的方法可作为单独标注的 `PRIOR_ASSISTED_POSITIVE_CONTROL`，但不得与无先验 arms 合并排名或用于 `M1-S1` 因果结论。任何额外外部 baseline 必须先补全正式引用、exact upstream commit、输入先验和可比性审计。

`N0` 对每个 subject 在 exact frozen config 下确定性执行一次，并在 curator eligibility seal 与 Agent schedule 生成前封存；它不是随机交错的 stochastic arm，Detector 只接收其允许的 artifact identity，不接收 target-miss selection。随后 `S0/S1/M0/M1/M2` 执行全部预注册的 separately initialized repeated runs；`G1` 仅在 `formal_profile=ROLE` 时加入同一 confirmatory Cartesian schedule。`CORE` profile 不得附加 formal `G1`；后续另跑只能作为新 cohort 的 exploratory study。`H0` 只导入旧 M7 provenance/result，不在新 holdout 上冒充配对 arm；若未来决定在新 holdout 重跑 M7，它必须注册为另一个新 arm，而不能改写 H0。

## 5. Arms 间不变量与唯一允许差异

### 5.1 Confirmatory arms 的共同合同

`S0/S1/M0/M1` 必须共享：

- exact `claude-sonnet-5` 模型、provider、endpoint protocol、temperature、seed policy、max output、timeout 与 transport retry policy；
- 同一 project-side input、security taxonomy、repository index、M1--M3 facts、六个 frozen CodeQL tools 和 tool result status 语义；
- 同一 repository tool 实现、bounds、project confinement、scope/role helpers、M4 Evidence Gate、M5 graph/path builder 与 search limits；
- 同一项目级 input/output token、model-call、repository-tool、CodeQL-call、proposal 和 wall-clock ceiling，以及同一 price-table/accounting rule；
- 同一 schema strictness、fail-closed parser、no-leakage boundary、artifact 和 evaluator；
- 同一 project、revision、CodeQL DB、arm order randomization block 和 replicate count。

`M2` 除 Coordinator exact model 和由此产生的 provider price 外，其余合同与 `M1` 相同。所有 confirmatory arms 保持相同 token/model/tool/wall-clock ceilings；美元成本是 outcome，不作为单 arm 提前停止条件。若触及研究总支出安全上限，scheduler 只能对称暂停尚未完成的整个 project block。`G1` 的唯一处理是上文冻结的 generic-worker bundle；不得同时改变模型、worker 数、调用上限、feedback、verifier 或总预算。

`claude-opus-5` / `claude-sonnet-5` 是冻结的 configured model IDs，但第三方 endpoint 可能把字符串实现为可漂移 alias。manifest 必须同时记录 configured ID、response-reported model/version 和 provider deployment revision（若提供）。formal 优先要求 provider-pinned immutable revision；若 provider 不提供，论文只能称 configured-model matched，并把 backend identity 记为 `NOT_ATTESTED`。block 内观察到 model identity 改变时对称暂停整个 block，不得只重跑表现较差的 arm；无法排除跨 block 漂移时不得把差异解释为 exact backend 的纯架构效应。

### 5.2 “无 feedback”的精确定义

这里的处理因素命名为 `verifier_feedback_visible`，不是“模型看不到任何工具结果”。

所有 arms 都继续看到完成当前动作所必需的 repository/CodeQL tool result、structured-output validation 和安全边界错误。否则模型无法执行，且会同时改变工具可用性与可靠性。

`S0/M0` 隐藏且禁止重新进入模型决策的内容仅包括：

- Gate 的 `ADMISSIBLE / NEEDS_MORE_EVIDENCE / REJECTED / DUPLICATE / ALREADY_SUPPORTED / UNSUPPORTED` 结果与理由；
- path build 成功、失败、截断和 connectivity 反馈；
- scope/role semantic repair 建议；
- proposal-level failed hypothesis 与 `repair_of` 历史。

每个 proposal 在所有 arms 中都按相同顺序和提交时点同步经过同版本 Gate、duplicate tracker，并在适用时触发同一 path builder；每次都更新独立 verifier state、写出相同粒度 artifact，并按同一确定性规则扣除 verification/proposal 预算。不得把 `S0/M0` 改为 Detector 结束后的离线验证，也不得让其跳过 duplicate、path 或 stopping-state 计算。

唯一差异是 observer projection：`S0/M0` 的模型 observation 只能收到固定 `PROPOSAL_RECEIVED` 回执；verifier 结果写入模型不可读的 append-only audit channel，Coordinator、single-Agent policy、stopping 和后续 observation 均不得读取其状态、计数、理由、graph 摘要、repair history 或 terminal reason。`S1/M1/M2` 从下一次既有模型 observation 起可读取详细 feedback，并据此修复、重提或主动停止。所有 arms 的自动预算/安全停止规则相同，不能用 `PATH_FORMED` 等被遮蔽结果提前终止 no-feedback arm；feedback arm 因可见信息自主改变后续行为是 RQ2 的预期处理效应。不得给 feedback arms 额外的专用 model call、repair quota 或延长 wall-clock。

`verifier_feedback_visible` 必须由独立 typed contract、information-flow test、model-visible transcript diff 和 observation snapshot test 证明，不能只改 prompt 文案。审计还必须证明 no-feedback 上下文没有 verifier-derived bytes，同时两类 arms 共享同一 per-proposal invocation rule、verifier version、提交时点和固定预算扣费；总调用数可因反馈导致的后续 proposal 轨迹不同而不同，并作为处理后的过程结果报告。

### 5.3 现代化 single Agent

`S0/S1` 不是旧 M7 的直接重跑。它们必须使用与 multi arms 相同的现代 security taxonomy、repository/CodeQL tools、helpers、typed evidence/proposal contracts、Gate/M5 和项目级预算。单一 Sonnet reasoner 自己执行 input/effect/bridge discovery 与 proposal submission，不通过隐藏的 specialists 或额外模型调用。

因此：

- `H0` 估计旧系统到新系统的 bundle change；
- `M1-S1` 才估计在现代 harness 内的架构处理效应；
- 若没有实现并测试现代 `S0/S1`，论文不得用 H0 替代。

### 5.4 CodeQL status 与 Gate 语义

CodeQL tool 状态固定为 `OK / EMPTY / ERROR / UNAVAILABLE / UNSUPPORTED / ENTITY_NOT_MAPPED`。后四类不表示关系不存在。所有 arms 必须共享同一工具实现、数据库快照、状态语义、缓存策略和错误处理；对相同 canonical call 与相同输入，结果必须可重放一致。不同 arms 可以因模型决策不同而调用不同工具并观察不同证据，不要求随机轨迹产生相同 evidence；不得只为某 arm 降级、补跑或人工注入查询结果。

Gate 状态保持当前代码与 schema 的完整枚举：`ADMISSIBLE / NEEDS_MORE_EVIDENCE / REJECTED / DUPLICATE / ALREADY_SUPPORTED / UNSUPPORTED`。`ADMISSIBLE != vulnerability`。Gate admission 的正式过程指标必须按 `repair_of` family 聚类，分别报告 first-pass admission 与 eventual admission，不能把每次 repair attempt 当独立分母。报告中使用命名空间 `gate_status.*`，避免与 evaluator 的 `review_label.UNSUPPORTED` 混淆。

## 6. 数据集、split 与 lineage 隔离

### 6.1 三个互斥阶段

1. `dev-tune`：用于通用工程调试、prompt/schema/budget 调整和成本测量；结果不进入正式效果表。
2. `dev-validation`：一次性读取；只验证冻结候选配置的 readiness、失败率与成本，不得在看 evaluator outcome 后继续调 Detector。若失败，回到新的 dev-tune 版本，把该 validation split 永久降为 development，并从全新 lineage 另建下一版一次性 validation。
3. `formal-holdout`：全新项目/修订 lineage；独立 curator 可在 enclave 内为 eligibility 冻结 ground truth，但所有 Detector arms 完成、hash、seal 后，scoring Evaluator/reviewer 才可解封该 manifest。

旧 M7 10-case cohort 和任何已用于 prompt/规则/预算修复的 repository 只能进入 `HISTORICAL` 或 `DEVELOPMENT_ONLY`，不能进入 formal-holdout。

### 6.2 Lineage group

split 与统计 cluster 的最小单位是 `repository_lineage_id`，至少把以下内容归到同一 lineage：

- 同一 repository 的 vulnerable/fixed revisions；
- forks、vendor copies、backports、cherry-picks 和镜像；
- 共享同一 patch、根因或高度相似代码的派生项目；
- benchmark 中同一上游组件的多个包装项目。

同一 lineage 不得跨 `dev-tune`、`dev-validation` 和 `formal-holdout`。split verifier 必须在任何 Detector run 前 fail closed。Detector manifest 只写不可枚举的 `split_commitment`，不得写可由公开项目列表离线猜测的裸 lineage-manifest hash。

### 6.3 Subject composition 与 pre-treatment analysis sets

formal cohort 在任何 Agent arm 执行前，由不能读取 arm 输出的独立 cohort curator 使用 ground truth、冻结 `N0` 和 contract-only expressibility rubric 完成 eligibility 审核。curator 必须先生成并 seal 两个互斥集合：

- `primary_eligible_lineages`：每个 lineage 至少有一个预先确认的 eligible target，并且预先指定且仅指定一个 `primary_vulnerable_subject_id`；对应 fixed revision 和同 lineage 额外 revisions 只进入 safety/secondary analysis；
- `safety_only_lineages`：benign-only lineages、fixed-only lineages、没有 eligible target 的 vulnerable revisions，以及只为 review burden/robustness 纳入的其他 subjects；这些 lineage 不产生 McNemar primary row。

`formal_primary_analysis_set` 等于封存时的 `primary_eligible_lineages`，`formal_safety_analysis_set` 等于全部预注册 scheduled lineages。formal primary `N` 在 scheduler 生成前即为前者的数量；运行后不得因某 arm 的输出、失败、path 数或 reviewer 判断改变 denominator。这是 pre-treatment eligibility-defined population，不是运行后 modified ITT。

formal safety set 应覆盖 vulnerable/fixed pairs、benign projects/revisions，以及不同 repository、CWE family、项目规模和构建生态；这些角色和标签只存在 curator/evaluator enclave。fixed/benign subjects 不因没有 `primary_vulnerable_subject_id` 而违反 cohort 合同。

优先选择目标模型公开 knowledge cutoff 之后的 revisions；provider 未披露 cutoff 时记录 `NOT_DISCLOSED`，不得把样本称为 zero-day。无法排除预训练记忆的公开历史项目必须记录 `MEMORIZATION_RISK`，不得用 runtime no-leakage PASS 抵消这一威胁。

### 6.4 Detector 与 evaluator manifest

Detector-side canonical subject manifest 只允许 project-side 字段：

- `subject_id`、`project_id` 的随机、不承载 role/lineage 语义的 pseudonymous 标识；
- `repository_revision`、`source_root`、`codeql_db_path/status/identity`；
- frozen Native CodeQL artifact identity；
- frozen generic M1--M5 artifact identities；
- arm、replicate、schedule、config 和 budget hashes。

`repository_lineage_id`、`primary_vulnerable_subject_id`、analysis-set membership、`CVE/CWE`、vulnerable/fixed/benign role、patch/fix commit、target file/function/line、root cause、known method、M6 diagnostics 和 reviewer annotation 只存在 curator/evaluator enclave。运行 scheduler 只接收预生成的 opaque subject/run schedule、split 名、`split_commitment` 和 `eligibility_commitment`，不得读取 lineage mapping、analysis set 或 revision role。commitment 使用 evaluator-side secret key 的 HMAC-SHA-256，或 `SHA-256(random_256_bit_nonce || canonical_manifest)`；key/nonce 与 canonical manifest 在 cohort Detector seal 前均不得进入 scheduler/Detector。`repository_lineage_id` 必须由独立 cohort curator 生成，不能编码项目角色或漏洞信息。

这里的 pseudonymization 不是项目匿名化：`source_root`、revision 和源码内容可能让模型或 reviewer 识别公开项目。no-leakage 保证的是不提供 evaluator label、known target 和 patch oracle；它不能排除项目识别、公开知识或预训练记忆。

## 7. 实验单位、重复、随机化与 failure-inclusive analysis

### 7.1 实验单位

primary 的独立单位是每个 `primary_eligible_lineage` 预注册的唯一 `primary_vulnerable_subject_id`，它对应一个 `project/revision`。fixed/额外 revisions 的 secondary analysis 按 `repository_lineage_id` 聚类。target、finding、proposal、Gate attempt、Candidate Path、tool call 和 model call 都是嵌套观测，不能当独立样本扩充 `n`。

### 7.2 Replicates

formal 预设每个 `project x confirmatory arm` 运行 `R=3` 个 separately initialized repeated runs。provider 未公开全部采样与缓存机制时，不能把它们宣称为统计独立 replicates。三次都保留，不得重写、挑选或取 best-of。

- `replicate_index=1` 是 confirmatory pass@1 和 exact McNemar 的唯一输入；
- `replicate_index=2,3` 用于估计 run-to-run stability、failure rate 和 project-clustered success probability；
- `any-success`、`best path`、`pass@3` 只可作为明确标注的描述性结果，不能替代 primary；
- 如果正式 freeze 前的 power/cost analysis 证明 `R=3` 不可执行，必须在看到 formal 结果前修改本协议版本并重新 seal，而不能在运行途中减少失败 arm 的 replicate。

每个 repeated run 和每个 arm 都必须使用空白模型会话、隔离的 board/controller/runtime state、唯一 request/run ID，且不得读取先前 arm 的 observations、findings、proposals、Gate/path 或 outcome。会改变模型可见内容或工具语义的应用层 cache 必须禁用或按 run 隔离；只允许 content-addressed、只读且经重放证明输出 byte-identical 的 repository/CodeQL cache，并记录 hit provenance。provider 支持 seed 时使用 scheduler 预生成且逐 run 不同的冻结 seed；不支持时记录 `NOT_SUPPORTED`。显式 provider cache 应关闭或按 arm 对称隔离；隐式 cache 不可观测时记录为 validity threat。

### 7.3 随机与交错执行

每个 project/replicate 是一个 block。用预注册随机种子为 block 生成 arm order，并采用平衡 Latin-square/循环顺序使每个 arm 在 provider 时间窗口中的位置尽量均衡。不得先跑完一个 arm 再跑另一个 arm。

记录：UTC start/end、provider request ID、endpoint model version（若提供）、temperature、seed value/support、session/cache isolation、cache status、CloudStudio/environment identity 和 concurrent load。temperature 0 不解释为确定性，项目内随机交错只缓解而不能证明 `U` 独立同分布。

### 7.4 Failure-inclusive assigned-arm analysis

每个 subject 接受所有 arms，随机化的是 block 内执行顺序，不是把 subject 只分配到一个 treatment；因此这不是临床平行组意义的 intention-to-treat。本文使用 `failure-inclusive assigned-arm analysis`：每个预注册 run key 始终留在其 assigned arm，工程失败不作为 missing 或被替换成成功重跑。`ITT-like` 只可用于解释这一保守类比，正式表名不用 ITT。

以下都保留在分配 arm 中，并对该 replicate 的 primary outcome 计 `0`：

- model timeout/unavailable、invalid structured output、schema failure；
- budget exhaustion、stagnation、Coordinator/specialist failure；
- tool选择失败、没有 proposal、Gate 全拒绝或没有 Candidate Path；
- 模型没有使用可用 CodeQL。

每个 scheduled run key 还必须有独立于 `Y` 的 `analysis_disposition`：

- `VALID`：artifact/hash/no-leakage 已验证；普通成功或上述工程失败均可进入分析；
- `BLOCKED_UNVERIFIED`：scheduled key 缺失、audit 未完成或 hash mismatch 尚未解释；Evaluator 不得解封，也不能先按 `0` 出结果；
- `INVALID_CONTAMINATED`：forbidden evaluator/oracle bytes 已经或可能已经到达模型上下文；它不是执行失败、不是 missing、不得计 `0` 或 replacement。

安全边界在读取禁止内容前 fail closed 且 audit 可证明 `bytes_read=0`、`bytes_sent=0` 时仍属 `VALID` protocol failure，并计 `Y=0`。若 `INVALID_CONTAMINATED` 发生在任何 confirmatory arm 的 primary `replicate_index=1`，该 protocol version 不得发布 confirmatory efficacy/superiority 结论；只能封存 incident 和预注册的描述性 worst-case bounds。若仅发生在 replicate 2--3 或 safety-only subject，受影响的 secondary/safety estimand 失效，primary 只有在审计证明污染严格局限时才可保留。无法证明局限范围时，整个 formal study 失效。

共享基础设施 replacement 不能由研究者在看到 arm 输出后自由判断。formal freeze 必须包含一个 output-blind health classifier，它只读取：pre-block source/DB/config hashes、CloudStudio host/process exit records、artifact writer 的 pre-send transaction state、provider status incident timestamps，以及对每个 exact model 在预注册时点运行的 repository-free fixed canary 状态。classifier 不得读取 model response body、arm success、proposal/Gate/path、usage outcome 或 evaluator 数据。

只有以下客观事件可触发 replacement：模型请求前发现 source/DB/config checksum 不一致；host/process 级 crash 使整个 block 被外部终止；artifact writer 在 block 的第一个模型请求前无法建立原子 run root；或 provider 官方 incident 与 block health window 重叠，并且对该 block 使用的每个 exact model 的预注册 canary 都按冻结 retry rule 失败。replacement decision/hash 必须在解封任何 arm output 前写入 health ledger；保留旧 run、使用新 run ID，并重跑整个 `project x replicate` arm block。单 arm timeout、某一模型族不可用、schema failure、或根据结果推断“像 provider outage”都不是 replacement，均按 assigned-arm failure 计 `0`。

## 8. Primary、safety 与 process outcomes

### 8.1 Eligible target

独立 cohort curator 必须在生成 formal schedule 之前、且不能读取任何 formal arm 输出时确定并 seal：

```text
eligible_target = validated_project_target
                  AND frozen_N0_execution_valid_and_audited
                  AND native_codeql_missed_at_frozen_N0
                  AND expressible_by_frozen_Work1_candidate_path_contract
```

`N0` timeout、DB unavailable、query error 或 artifact 未通过审计都不能解释为“Native missed”；该 subject 只能预先进入 safety set，直至在 schedule freeze 前取得有效、不可覆盖重跑的 N0 artifact。`expressible_by_frozen_Work1_candidate_path_contract` 只根据冻结合同、项目源码和 annotation 判定，不得参考任何 arm 是否实际生成相似 path。没有 eligible target 的 vulnerable project 可预先进入 secondary/safety cohort，但不计入已封存的 formal primary `N`；fixed/benign outputs 仍进入 safety/review-burden 分析。运行后发现的 eligibility annotation 错误记录为 protocol deviation，primary 保守计失败，并另报排除该 lineage 的 sensitivity analysis，不能静默改变 denominator。

### 8.2 Work1 primary endpoint

对 `primary_eligible_lineage` 的 primary vulnerable project/revision 与 arm 的 `replicate_index=1`：

```text
Y = 1  iff  analysis_disposition = VALID
            AND 至少一条 sealed、canonical-deduplicated Candidate Path
            所属 canonical group 被盲评匹配到至少一个 eligible target
            AND 该 arm 的 path instance 被独立判为 SUPPORTED
Y = 0  iff  analysis_disposition = VALID 且上述条件不成立
```

`BLOCKED_UNVERIFIED` 和 `INVALID_CONTAMINATED` 没有可用于 primary McNemar 的 `Y`；它们触发上文的 release/validity rule，而不是被分析代码隐式转换为 0。

这称为 `project-level incremental candidate recovery`，不是漏洞确认。Candidate Path 即使匹配 annotation，仍只表示值得 Work2 验证。只有后续独立 Work2 对 protection/sanitizer/unsafe context 和漏洞成立性作出确认，论文才可报告 `confirmed vulnerability recovery`。

### 8.3 Key safety outcomes

- Work1-observable vulnerable/fixed discrimination：仅在 curator 预先封存 `work1_fix_observable=true`（修复会移除或改变 frozen Work1 contract 可表达的 target relation/path）时，要求 vulnerable revision 成功匹配且 fixed revision 不产生等价 target path；
- canonical Candidate Paths/project 与 reviewer minutes/project；
- per-project `UNSUPPORTED`、`DUPLICATE_WITHIN_ARM`、`UNDECIDABLE` candidate 比例及 lineage-level 95% CI；
- benign revisions 上的 target-equivalent candidate rate，以及 fixed revisions 上按 `work1_fix_observable` 分层的 candidate persistence；
- no-leakage、cross-project reference、artifact/hash 和 runtime-boundary violation rate；
- Native CodeQL preservation：分别验证 frozen artifact hash/byte identity 与既有语义结果未改变。

sanitizer、authorization check 或 effective-protection-only fix 可能保留同一结构路径，但其安全含义属于 Work2；这类 pair 的 Work1 discrimination 必须写 `NOT_EVALUABLE`，只描述 fixed-revision candidate persistence，不能算 false positive。所有 candidate-level safety 比例先在 `project/revision x arm` 内聚合，再对其预注册 analysis set 内的 lineage 作等权 macro-average；CI 以 lineage 为 cluster 重采样。不得把同一项目的大量 paths 当独立样本。Native preservation 分别报告 artifact hash/byte identity 与语义兼容性，不使用含混的 `byte-semantically unchanged` 合并两种合同。

在 Work2 确认前使用 `unsupported candidate rate`，不把它写成漏洞 FDR。若 Work2 执行，可另报告经确认漏洞的 precision/FDR，但必须保留 Work1 proxy 与 Work2 outcome 的区别。

### 8.4 Secondary/process outcomes

- 盲评后的 Input/Effect/Bridge reviewed precision、annotated-target coverage 和 project coverage；只有对预先建立穷尽 reference set 的子集才报告 recall，并明确其分母；
- first-pass Gate admission、eventual admission、repair attempts/family 和 reject reason；
- CodeQL attempted、`OK`、non-empty、entered-proposal、entered-final-path 的漏斗；
- repository/CodeQL tool calls、Coordinator rounds、specialist dispatches；
- input/output/cache tokens、model attempts、retries、timeouts、wall-clock 和美元成本；
- failure taxonomy、stagnation、budget stop、schema/protocol failure；
- Candidate Path relation-type diversity 和 evaluator-side canonical duplicate rate。

这些只解释机制和成本。Candidate Path 数、Gate admission、CodeQL call 或 specialist finding 数增加，均不能单独支持漏洞发现改善。

### 8.5 Outcome grain 与 denominator registry

formal freeze 必须把下表逐项实例化为 machine-readable registry；报告不得临时改变 subject set、replicate 或分母：

| Outcome | Analysis set / 独立 grain | Replicate rule | Denominator 与 inferential status |
|---|---|---|---|
| project-level incremental recovery | `primary_eligible_lineages`，每 lineage 一个 primary subject | `r=1` | 封存的 primary `N`；唯一 primary confirmatory endpoint |
| repeated-run success/stability | 同一 primary lineages | `r=1..3` 聚合为每 lineage 的 `mean_Y` | lineage 等权；11.2 的预注册 secondary estimator |
| Work1-observable vulnerable/fixed discrimination | 预先带 fixed pair 且 `work1_fix_observable=true` 的 lineages，每 lineage 一个二元结果 | 主报 `r=1`；`r=1..3` 只作稳定性附表 | frozen Work1-observable pairs；其余 pairs 只报 persistence/`NOT_EVALUABLE` |
| Candidate Path 数与 reviewer minutes | 全部 scheduled vulnerable/fixed/benign subjects，subject-level total | 主报 `r=1`；其余 runs 单列 | 每 subject 后按 lineage cluster；effect/CI，不作非劣性宣称 |
| `UNSUPPORTED` / duplicate / `UNDECIDABLE` 比例 | 每个 `subject x arm` 先 macro 聚合 | 主报 `r=1` | 分母是该 subject 的 reviewed evidence packages；零 candidate 时比例为 `NOT_EVALUABLE`，同时保留 count=0 |
| benign target-equivalent rate | 全部预注册 benign subjects，每 subject 一个二元结果 | 主报 `r=1` | 封存的 benign subject 数，CI 按 lineage cluster |
| fixed candidate persistence | 全部预注册 fixed subjects，按 `work1_fix_observable` 分层 | 主报 `r=1` | fixed subjects；非 observable stratum 不解释为 false-positive rate |
| Input/Effect/Bridge precision/coverage | 有对应 blind annotation 的 subject/finding package | 主报 `r=1` | precision 分母为 reviewed findings；project coverage 分母为 scheduled subjects |
| Input/Effect/Bridge recall | 仅 curator 在运行前封存了 exhaustive reference set 的子集 | 主报 `r=1` | exhaustive annotations 数；否则强制写 `NOT_EVALUABLE`，不得用 target coverage 冒充 recall |
| Gate/CodeQL/tool/process funnel | 每个 run 内按 proposal family、call 和 status 聚合，再到 subject/lineage | `r=1..3` 分层报告 | 纯 process/descriptive；calls/findings 不作为独立 `n` |
| tokens/cost/wall-clock/failure | 每个 scheduled subject-arm-run 的 ledger total | `r=1` 为主要成本对照；`r=1..3` 为稳定性 | paired subject difference，按 lineage cluster；provider 未报告值不作 0 |
| no-leakage/hash/native preservation | 全部 expected run keys 与所有 `N0`/native artifacts | 全部 runs | 完整性合同；报告精确 counts/status，不作为效果显著性指标 |

除 11.1 primary 和 11.2 明列的 secondary confirmatory contrasts 外，安全/过程结果均以 effect estimate、CI 和完整分母作预先指定的 descriptive analysis。没有冻结 non-inferiority margin 和相应 power 时，不得声称“安全性不差”。

## 9. 盲评与 canonicalization

Detector scheduler 必须完成所有预注册 arms 和 replacements，逐 run 写 output hash，并生成 cohort-level seal。运行期间的 scoring Evaluator 进程在 seal 前不得导入 ground truth 模块或读取 curator/evaluator manifest；pre-run curator 是物理/权限隔离的不同主体，只能写 sealed commitments，不能参与 Detector、scheduler 或后续调参。

这里的“盲评”精确指 reviewer 对 treatment assignment（arm/model/harness）的盲法；reviewer 为匹配 eligible target 必然读取项目源码和 evaluator annotation，不能宣称对 ground truth 或 project identity 双盲。盲评包必须移除或随机化：arm、model、prompt、生成者 agent role、run ID、成本、执行顺序、Git branch 和 failure taxonomy。所有 arms 先投影到同一个 provenance-neutral review schema；保留判断所需的 source/target semantic role、relation type、项目源码位置、证据与 path 结构，但不能保留 specialist-only 字段或通过路径命名泄露 arm。

Evaluator 在 reviewer 之前先执行冻结的跨 arm/replicate canonicalizer，并生成两个不可混用的 identity：

- `semantic_candidate_fingerprint` 用于跨 arm/replicate 分组，排除 proposal/finding/run-specific ID 和 evidence 强弱，至少包含 lineage、规范化相对源码路径、owner/source/target signature、source/target role 与 ordered semantic relation types；
- `evidence_package_hash` 绑定某一 arm path instance 自己的 canonical evidence JSON、规范化 evidence locations、snippet/source hashes、tool-call provenance 和 frozen source snapshot。

当前 M5 `path_fingerprint` 仅用于 run 内去重，不能替代任一 evaluator identity。相同 semantic fingerprint 只表示候选语义等价，不表示 evidence 等价；不同 evidence package 绝不做 union、不得选用“最强包”代表整组，也不能让一个 arm 继承另一个 arm 的 support judgment。

盲评分两个有顺序的阶段，避免 eligible annotation 影响 evidence 充分性判断，也避免一个 arm 的丰富 evidence 替另一个 arm 背书：

1. **Phase A, per-instance evidence support**：不显示 eligible-target annotation；每个 arm 的 sealed path instance 以统一 schema、随机顺序单独显示自己的 evidence，reviewer 标注 `SUPPORTED / UNSUPPORTED / DUPLICATE_WITHIN_ARM / UNDECIDABLE`。只有 `evidence_package_hash` 完全相同才可复用一次判断；否则必须独立判断，且 Phase A judgment 必须先 seal。
2. **Phase B, canonical target match**：Phase A seal 后才开放 evaluator target annotation；每个 canonical group 只显示 provenance-neutral semantic skeleton，reviewer 标注 `MATCH_ELIGIBLE_TARGET / OTHER_REVIEWABLE_SECURITY_CANDIDATE / NO_TARGET_MATCH / UNDECIDABLE`。结果可映射回各 arm，但某 arm 只有自己的 path instance 在 Phase A 为 `SUPPORTED` 时才计 primary recovery。

优先使用不同 reviewer panels 完成 Phase A/B；若人员限制必须复用 reviewer，仍必须先完成并封存全部 Phase A，之后才能读取 Phase B annotation，且不得回改 Phase A。

至少两名独立 reviewer 按冻结 rubric 标注，分歧由第三名 adjudicator 处理。workload 以 lineage 和 canonical group 为 block 随机平衡。reviewer 在每个 block 后额外猜测来源 arm 并给置信度；报告 arm-guess accuracy/CI 与按 blind-pack arm prevalence 计算的 chance baseline，用于量化 blinding 是否失败。猜测不改变 judgment。

报告 raw agreement、Cohen's kappa 和 Gwet's AC1；同时公开原始 contingency table。极端 prevalence 时以 raw agreement/AC1 解释，不能挑选更有利的 agreement 指标。

## 10. 资源预算与 usage ledger

正式比较必须先实现 project-level shared ledger。当前 M8 只把成功的 Coordinator response 计入 `model_calls/input_tokens/output_tokens`，specialist usage、timeout 和 provider error 会漏计，因此现有 summary 不能用于 arm 成本比较。

### 10.1 每次模型 attempt 的必需字段

- study/split/subject/arm/replicate/run/agent/role/model identity；
- attempt index、request timestamp、end timestamp、wall-clock；
- canonical prompt、observation、tool schema/catalog hash 与 serialized bytes；
- input/output/cache tokens，并区分 `PROVIDER_REPORTED / LOCALLY_ESTIMATED / NOT_REPORTED`；
- provider request ID、transport retry、HTTP/provider status；
- terminal status：success、timeout、invalid-output、provider-error、cancelled-before-send；
- billed cost 与 price-table identity；provider 不报告或价格未知时写 `NOT_REPORTED`，不能写 `0`；
- 与上一 observation 的重复 bytes，以及是否命中 cache（仅 provider 明示时记录）。

模型请求发出前先登记 attempt 并原子保留最大预算；成功后按冻结规则结算。timeout/error 仍计一次 attempt 与 wall-clock。若 provider 不返回 token，保留本地 canonical tokenizer estimate 与 `NOT_REPORTED` 的 billed usage，不能丢失调用。

### 10.2 共享 ceiling

每个 project/arm/replicate 共享以下 ceiling，Coordinator 和所有 specialists 共用，不能每次 dispatch 重新获得完整预算：

- model attempts；
- canonical input tokens、max-reserved output tokens；
- repository tool calls、CodeQL calls；
- proposal families、admissible proposals、Candidate Paths；
- wall-clock；

exact ceiling 数值只允许根据 controlled/dev-tune 的通用可靠性与成本证据调整，并在一次性 dev-validation 前冻结。formal arms 必须使用同一计算资源 ceiling；`M2` 的较高单价作为 routing treatment 的成本结果，既不能换取额外预算，也不能因单 arm 费用提前截断。研究总支出上限可以暂停整个未完成 project block，但不能选择性删除昂贵或失败的 arm。

## 11. 统计分析计划

### 11.1 Primary analysis

对 `replicate_index=1`，每个 `primary_eligible_lineage` 唯一预注册的 primary vulnerable project/revision 和两个待比较 arms 形成一对二元 `Y`：

- `M1` vs `S1` 是唯一 family-wise primary contrast；
- paired risk difference 点估计为 `(n10 - n01) / N`；报告两 arm 成功比例、discordant counts `n10/n01`、exact two-sided McNemar p-value，以及 Newcombe paired-score 95% CI；
- 不能把 path 或 target 当独立 observation；
- `UNDECIDABLE`、timeout、invalid output 和预算失败在 `analysis_disposition=VALID` 时计 `0`；完整性状态按 7.4 单独处理。

primary 不在“bootstrap 或 score CI”之间事后选择。McNemar 始终使用 conditional exact binomial p-value；paired risk difference 始终使用冻结实现的 Newcombe paired-score CI。lineage bootstrap 只作 robustness/safety/secondary interval，small discordance 或零 discordance 时仍报告 exact p、score CI 和原始 `2 x 2` 表。

### 11.2 Secondary confirmatory contrasts

`CORE` profile 的 secondary family 是 `M1-M0`、`S1-S0`、`M2-M1`、`M2-S1`；`ROLE` profile 在同一 family 中再加入 `M1-G1`。selected profile 内全部 p-value 用 Holm step-down 校正；不得把 `G1` 加入运行却排除出 multiplicity family。所有 raw p、adjusted p、effect size 与 95% CI 均报告，不以 `p<0.05` 代替实际效应。

计数、tokens、成本、review time 和 wall-clock 使用 project 内 paired difference；报告 median/IQR、mean 和 lineage-clustered bootstrap CI。bootstrap 固定为按 lineage 有放回重采样 `B=10,000` 次，使用 study manifest 的 `statistics_seed`，主报 BCa CI；BCa 因退化分布不可计算时按预声明 fallback 报 percentile CI 并标记原因。重尾成本不只报均值。

paired permutation sensitivity 使用每个 lineage 内交换两个 arm label 的 mean paired difference 作为统计量；`N<=20` 时枚举全部 `2^N` label swaps，否则用同一冻结 seed 做 `100,000` 次 Monte Carlo swaps。该检验依赖 sharp null 下的 within-lineage exchangeability；明显由定价机制决定的美元成本比较只报告 effect/CI，不把 exchangeability 不成立的 permutation p-value 强行解释。

三个 repeated runs 的预注册 secondary estimator 不在 mixed model 与 bootstrap 之间事后选择。对每个 primary lineage 定义 `mean_Y_p(a) = (Y_p1(a)+Y_p2(a)+Y_p3(a))/3`，对每个 contrast 报告 `mean_p[mean_Y_p(a)-mean_Y_p(a')]`；95% CI 使用与 11.2 相同的 lineage-level `B=10,000` BCa bootstrap 和冻结 fallback。另按 arm 报告每个 lineage 的成功次数分布 `0/3, 1/3, 2/3, 3/3`、failure class 分布和 within-lineage sample variance。三次 repeated runs 从不作为三个独立项目，也不拟合一个可由 analyst 临时选择结构的 mixed model。

### 11.3 Power 与样本量

formal eligible primary lineage 数必须在任何 holdout arm 输出不可见时，由一次性 dev-validation 的运行可靠性、预注册最小有意义架构效应和 discordant-pair 假设共同冻结。cohort curator 先完成 eligibility seal，再生成 final schedule；不能先运行再排除不利或“不可表达”的 subjects。`ROLE` profile 的 power/cost simulation 必须包含 `G1` 和五项 secondary Holm family；不能沿用 `CORE` 的 arm 数或 multiplicity 假设。

dev-validation 的 evaluator outcome 只可按预声明 sensitivity grid 更新 power/N 假设；不得据此删除 arm、选择更有利 contrast、修改 Detector、prompt、feedback、tools 或预算。若据其结果修改任何 Detector 因素，原 validation 永久转为 development，并必须使用新 lineage 重做 validation。

示例仅用于量级检查：若 `P(M1=1,S1=0)=0.25`、`P(M1=0,S1=1)=0.05`，两侧 `alpha=0.05`、power `0.80` 的 McNemar 正态近似约需 57 个相互独立的 primary lineage pairs；实际 `N` 必须在 eligibility seal 后用 exact/simulation power 和可执行成本冻结，运行期 failure 已由 `Y=0` 吸收，不能再用 post hoc “non-eligible”扣减。`n=8` development 只能是工程 pilot，不能支持优越性结论。

在 `09_FORMAL_FREEZE.md` 中必须写明：假设、最小效应、alpha、power、模拟代码/hash、最终 lineage/project 数、排除规则和可执行性预算。没有该附件不得开始 formal。

### 11.4 Missingness 与敏感性分析

- Detector/model failure 没有 missing outcome，在 `analysis_disposition=VALID` 时为 0；
- evaluator 不能判断的 Candidate Path 为 `UNDECIDABLE`，primary 按不匹配；
- 共享基础设施 replacement 的旧 run 不删除，主分析使用预注册 replacement，敏感性分析把旧 run 按 0；
- `BLOCKED_UNVERIFIED` 阻止 evaluator release，`INVALID_CONTAMINATED` 按 7.4 使对应 confirmatory/secondary claim 失效；两者都不是可插补 missingness；
- 报告 successful-execution-only 结果时必须标为 secondary，并与 failure-inclusive primary 并列，不能替代 primary；
- 对 memorization-risk、项目规模、CWE family 的分析只在样本量和预注册 strata 允许时进行，不作事后捞显著性。

### 11.5 统计方法依据

- 配对二元主检验沿用 McNemar（1947）*Note on the Sampling Error of the Difference between Correlated Proportions or Percentages*：[DOI](https://doi.org/10.1007/BF02295996)；
- paired risk-difference CI 预注册为 Newcombe（1998）*Improved Confidence Intervals for the Difference between Binomial Proportions Based on Paired Data*：[PubMed](https://pubmed.ncbi.nlm.nih.gov/9839354/)；
- 多个 secondary hypotheses 使用 Holm（1979）*A Simple Sequentially Rejective Multiple Test Procedure*：[JSTOR](https://www.jstor.org/stable/4615733)；
- project/lineage 重采样遵循 Efron 与 Tibshirani（1993）*An Introduction to the Bootstrap*：[DOI](https://doi.org/10.1201/9780429246593)；
- reviewer agreement 使用 Cohen（1960）kappa（[DOI](https://doi.org/10.1177/001316446002000104)）与 Gwet（2008）AC1（[DOI](https://doi.org/10.1348/000711006X126600)）；treatment-blind assessment 的必要性参考 Hróbjartsson et al.（2012）observer-bias systematic review：[BMJ](https://doi.org/10.1136/bmj.e1119)；
- power 不是事后补充项。正式 freeze 将公开 exact/simulation power 代码、输入假设和 sensitivity grid，而不是只引用经验样本数。

## 12. Freeze、artifact 与不可覆盖合同

### 12.1 Formal 前一起冻结

在任何 formal evaluator outcome 可见前，一次性冻结并 hash：

- protocol version、research questions、arms、contrasts、R、random seed 与 schedule；
- project list、revisions、lineage split、CodeQL DB、N0 artifacts；
- exact model IDs、provider、endpoint protocol、temperature/seed/cache/retry policy；
- prompts、tool catalog、schemas、helpers、feedback visibility、controller/runtime；
- shared budgets、path limits、failure/replacement rules；
- M4/M5/source code Git SHA 和 environment/container identity；
- detector/evaluator manifests、blind rubric、canonicalizer、unblind map hash；
- statistics code、power analysis 和 report template。

所有 selected-profile confirmatory arms 必须一起 schedule/freeze/seal。不得先看 M2 或 M1 evaluator 结果，再决定是否改用 `ROLE` profile；`CORE` 不包含 formal `G1`，`ROLE` 则必须完整运行 `G1`。更细的 helper/CodeQL-policy ablation 若未一同预注册，只能放在另一个新 cohort。

### 12.2 Artifact hierarchy

每个 run 使用不可覆盖目录：

```text
artifacts/work1-agent-v11/m8_study/
  <study_id>/<split>/<subject_id>/<arm_id>/r<replicate_index>/<run_id>/
```

最少包含：run manifest、model attempts、observations、repository/CodeQL tools、EvidenceRefs、三类 findings（适用 arm）、proposal/Gate family、graph/path、board replay、failure taxonomy、usage ledger、summary、no-leakage audit、artifact audit 和 seal。

study root 另含：protocol/arm/subject/schedule hashes、expected Cartesian run keys、terminal failure-inclusive assigned-arm outcome table、每 run 的 `analysis_disposition`、seal hash、cohort integrity seal 和 evaluator-release record。Efficacy evaluator release 要求每个 expected key 都有 sealed terminal row 且没有 `BLOCKED_UNVERIFIED`；`pending` 或静默缺失不能封存。普通模型、parser、schema、budget 或 tool failure 可以且必须写成 `VALID, Y=0`，不能为了“凑齐成功输出”重跑；`INVALID_CONTAMINATED` 可封存 safety incident，但不能取得 confirmatory efficacy release。

`hash mismatch` 或 no-leakage 异常先触发 study-level safety pause，按 7.4 的 disposition 处理：

1. 纯 audit 工具故障可在不重新运行 Detector、不改任何 output bytes 的前提下重算并保留两次 audit；解析前保持 `BLOCKED_UNVERIFIED`；
2. 若安全边界在任何禁止读取和模型请求前 fail closed，并证明 `bytes_read=0`、`bytes_sent=0`，affected run 作为 `VALID` terminal protocol failure 计 `Y=0`；
3. 若 forbidden evaluator/oracle bytes 已经或可能已到达模型，affected run 标记 `INVALID_CONTAMINATED`、禁止重跑且不产生可分析 `Y`。primary run 发生该事件时，该 protocol version 不作 confirmatory efficacy claim；只报告 incident scope、原始 assigned-arm table 和预注册 worst-case bounds；
4. 若无法证明污染局限于单一 non-primary run/subject，或 unblind map/ground truth 可能跨 run 可见，整个 formal study 的 confirmatory claim 失效，现有 artifacts 只可作安全/描述性报告。

Evaluator artifacts 写入独立根，不回写 Detector outputs。blind judgments 和 adjudication seal 完成后才允许 unblind；unblind map 不进入 Detector artifact。

## 13. Readiness gates 与 stopping rules

### 13.1 M8-5 controlled gate

attempt4 的有效运行前提是 pushed exact Git SHA、clean CloudStudio worktree、新目录、四个 exact Agent/model identity 正确，且 artifact hashes 可重算一致。历史冻结的 M8-5 pass rule 保持不变，仅为：

- 至少一条经未修改 M4/M5 形成的 Candidate Path；
- no-leakage PASS。

三类 specialist 的实际 dispatch 数，以及 model -> tool -> evidence -> finding -> proposal -> Gate -> path 各段覆盖，必须完整报告为 diagnostic coverage，但不是新增 hard gate。controlled fixture 的冻结结构边可能让合法 Candidate Path 在没有 Bridge specialist finding 的情况下形成；不得在 attempt4 前把“必须 dispatch 三类 specialist”事后升级为通过条件。若未来确需强化 gate，必须创建新协议版本和新 attempt 序列，不能改写 M8-5 历史判定。

失败则封存为新负结果。只允许基于通用工程合同证据决定是否再修复；不得用 fixture 答案、降低 Gate、扩预算或隐藏失败。通过后也不能直接跑 formal。

### 13.2 Development readiness

进入 `dev-tune` 前还必须实现并测试第 14 节 P0 contracts。dev-tune 只验证工程与机制，至少包含不同 lineage 的 vulnerable/fixed/benign 项目，不用 Detection Rate 作为调参目标。

dev-tune 的 revision role、target 和 evaluator label 在每次 Detector run/封存前仍只存在 curator/evaluator 侧。研究人员可在该 run seal 后解封 development evaluator outcome 来修改通用代码、prompt 或预算；任何被查看、用于诊断或重跑的 lineage 永久标记 `DEVELOPMENT_ONLY`，且不得把 project/CVE/known-location 特例写回 Detector。进入一次性 dev-validation 前，必须先达到 `DEVELOPMENT_CANDIDATE_FROZEN`；若解封 validation outcome 后改变任何 Detector 因素，状态返回 `DRAFT`，原 validation split 降为 development，并用全新 lineage 重新 validation。

一次性 dev-validation 的门在运行前冻结，至少覆盖：

- 所有 confirmatory arms 能完成真实项目运行；
- usage ledger 对 Coordinator/specialists/success/failure 求和一致；
- feedback visibility 与 arm-only-difference audit PASS；
- 至少一个项目完整走过 evidence -> proposal -> Gate -> Candidate Path；
- CodeQL 工具至少一次实际尝试，非 `OK` 状态解释正确；
- no-leakage、lineage split、study seal 和 blind pack PASS；
- scope/role engineering failure 不再主导全部 Gate family；
- 预算与预计 formal 总成本可执行。

不预设“Effect >= 50%、Bridge >= 30%、至少 3 paths”等 outcome-conditioned 优胜门作为 formal 进入条件；这些可作为工程健康描述，但不能因为某 arm 看起来更好才选择运行它。若可靠性不足以产生可评价输出，报告 feasibility failure 并停止 formal。

### 13.3 Formal stopping

formal schedule 开始后不按中间效果提前停止，也不允许 evaluator 查看部分结果。只可因安全事件、不可恢复基础设施故障或预注册成本上限暂停；恢复规则必须保持全部 arms 对称。

所有预注册 confirmatory arms 的 formal Work1 recovery 均为 0：报告负结果，不启动 Work2。任一 confirmatory arm 至少有 1 个 blinded eligible-target recovery 时，才按独立冻结协议启动 Work2，并对所有 arms 的 sealed、canonical-deduplicated matched/reviewable candidates 采用相同 arm-blind rubric，而不是只选择表现最好的 arm。Work2 结果不得反向修改 Work1 Detector。

## 14. 当前实现缺口与 P0 工程序列

本文目前是可审计设计，不是已经可执行的 harness。代码审计确认：

1. `N0` 只有旧 CodeQL runner，缺 arm/replicate/study seal；`H0` 只适合作历史导入；
2. `S0/S1` 没有现代化 single-Agent runtime；
3. `M0/M1` 会被现有 frozen Opus Coordinator 检查拒绝；
4. `M2` 目前只支持 `CONTROLLED_M8` fixture，不能作为真实项目 runner；
5. `G1` 被 specialist prompt、allow-list 和 finding type 硬绑定；
6. 没有 `ArmSpec`、formal profile、feedback visibility、curator/scheduler 权限隔离、keyed commitments、shared usage ledger、replicate scheduler、health classifier、analysis disposition、outcome registry、study seal、blind evaluator 或 statistics implementation；
7. 当前 M8 token summary 漏掉 specialists 和失败 attempts；
8. 当前 M5 fingerprint 包含 run-specific IDs，只适合 run 内去重，也没有分离 semantic candidate 与 evidence package identity。

正式 development 前按以下顺序实现：

1. `ArmSpec`、`FormalProfile`、`FeedbackVisibility`、`RunKey`、model backend identity/drift policy、pre-registered contrasts 和 arm-only-difference validator；
2. detector subject manifest、evaluator-only annotation manifest、pre-treatment analysis-set registry、split/eligibility commitments 与 lineage split verifier；
3. success/timeout/error 全覆盖的 shared usage ledger 和项目级预算；
4. 非 fixture 的真实项目 M8 runtime 与现代化 single runtime；
5. arm adapters、随机交错 scheduler、output-blind health classifier、analysis disposition、terminal assigned-arm outcome row 和 non-overwrite run layout；
6. per-run seal、complete Cartesian study seal、integrity state machine 与 evaluator release gate；
7. semantic/evidence 双 identity canonicalizer、匿名 blind pack、review/adjudication seal 和 unblind；
8. machine-readable outcome registry、exact McNemar、paired risk difference、lineage bootstrap、Holm 和 power simulation；
9. N0 adapter、H0 historical importer 与 prior-assisted baseline provenance。

最低测试集合：

- `test_m8_arm_registry.py`、`test_m8_formal_profile.py`、`test_m8_feedback_visibility.py`；
- `test_m8_usage_ledger.py`、`test_m8_budget_comparability.py`；
- `test_m8_subject_split.py`、`test_m8_analysis_sets.py`、`test_m8_manifest_commitments.py`、`test_m8_schedule_assigned_arm.py`；
- `test_m8_model_identity_drift.py`；
- `test_m8_health_classifier.py`、`test_m8_analysis_disposition.py`；
- `test_m8_real_project_runtime.py`、`test_m8_study_seal.py`；
- `test_m8_blind_evaluator.py`、`test_m8_canonical_identities.py`、`test_m8_statistics.py`；
- `test_m8_n0_adapter.py`、`test_m8_h0_import.py`。

这些实现必须通过现有 M4/M5/native preservation、M7/M8 regression、compileall、diff-check、secret scan 和 no-leakage tests。

## 15. 效度威胁与禁止性表述

### 15.1 Internal validity

- 模型、prompt、tools、helpers、feedback、harness 和预算同时改变会造成混杂；arm-only-difference audit 是硬门；
- provider 时间漂移、隐式 model update、缓存和并发负载通过项目内随机交错与完整 manifest 缓解，不能完全消除；
- feedback arms 会在同一 ceiling 内改变后续决策轨迹；RQ2 估计的是“可见反馈驱动的策略 bundle”，不是固定轨迹上的纯信息效应。不得给它额外调用机会，shared ceiling 和 usage ledger 必须先实现；
- evaluator 通过 blind pack、双人独立评审和封存后 unblind 降低偏差。

### 15.2 Construct validity

- Candidate Path 是 Work2 调查候选，不是漏洞；
- annotation match 是 proxy，不等于保护缺失或可利用性；
- Gate admission 测量 evidence contract，不测量漏洞成立性；
- CodeQL usage、finding 数和 path 数是过程指标，可能只反映更高 review burden。

### 15.3 External validity

- Java、所选 CWE、开放源码项目和可构建 CodeQL DB 限制外推；
- primary population 是 curator 预先确认的 Native-missed、contract-expressible eligible challenge set，估计条件恢复率，不估计真实部署中的漏洞 prevalence、全仓无条件 Detection Rate 或 field FPR；curated fixed/benign safety rates 也只能解释为本 cohort 的 candidate burden；
- HPTSA/MASAI/AutoSafeCoder/Agentless/MAST 等不同任务论文只用于架构或审计动机，不能当作本研究效果证据；
- 公开 CVE/仓库可能存在预训练记忆。no-leakage audit 只能排除运行时 oracle 输入，不能排除训练语料污染。

### 15.4 Statistical conclusion validity

- 小 cohort、同 lineage 多 revision、重复 runs 和多个 paths 都会产生伪独立；
- primary 每个 lineage 只使用一个预注册 project/revision paired outcome；额外 revisions 的分析按 lineage cluster；
- 多个 secondary contrasts 用 Holm；
- 报告 effect size/CI、所有 assigned-arm failures 和完整 contingency tables，不只报告显著性或成功案例。

### 15.5 在正式结果前允许与禁止的表述

当前允许：

> M8 已建立一个受限、可重放、fail-closed 且通过现有 no-leakage 审计的多 Agent 工程框架；真实模型 smoke 仍处于输出合同可靠性阶段，尚未测到项目级漏洞发现能力。

当前禁止：

- 四 Agent 比单 Agent 更好；
- Opus Coordinator 是改进原因；
- M8 已发现真实项目漏洞；
- Candidate Path、Gate admission 或 CodeQL call 是 Detection Rate；
- no-leakage PASS 排除了预训练记忆；
- attempt1--3 是可用于统计的三个重复实验；
- H0 与 M2 的差异可归因于任务分解。

## 16. 协议状态机与完成条件

本文不使用一个含混的 `FROZEN` 同时表示 development candidate 和 formal preregistration。正常路径与完整性失败分支为：

```text
DRAFT
  -> DEVELOPMENT_CANDIDATE_FROZEN
  -> FORMAL_FROZEN
  -> FORMAL_DETECTOR_SEALED
       -> EVALUATOR_RELEASED
       -> FORMAL_INVALIDATED
```

`DEVELOPMENT_CANDIDATE_FROZEN` 只授权一次性 dev-validation，不授权 formal。进入该状态前必须满足并 seal：

- P0 harness 和第 14 节测试全部通过，M8-5 controlled gate PASS，dev-tune 已封存；
- candidate arm registry、feedback contract、shared ceiling、pricing、model identity/drift policy；
- dev-validation lineage split、eligibility rubric、run keys、schedule、random seed；
- exact Git/environment/config/schema/prompt/tool hashes 和 validation release rule。

只有 dev-validation 完成且没有据其 evaluator outcome 修改 Detector，才可进入 `FORMAL_FROZEN`。该状态还必须补齐并 seal：

- final arm registry 与 `formal_profile`、contrasts、failure/contamination handling、output-blind health classifier；
- formal lineage cohort、`primary_eligible_lineages` / `safety_only_lineages`、power/N、R、schedule 和 random seed；
- blind rubric、canonicalizer、Phase A/B reviewers/adjudicator policy；
- exact Git SHA、environment、all config/schema/prompt/tool hashes；
- outcome registry、study seal verifier、statistics code/hash 和报告模板。

`FORMAL_DETECTOR_SEALED` 表示所有 expected run keys 已成为可审计 terminal rows，hash/no-leakage/incident-scope 审计完成，但 curator ground truth 尚未释放给 scoring Evaluator/reviewer。只有 efficacy release gate PASS 才能进入 `EVALUATOR_RELEASED`；primary contamination 或无法局限的 oracle exposure 进入 `FORMAL_INVALIDATED`，只允许发布 incident、完整性和明确标注的描述性 bounds，不允许 confirmatory efficacy claim。

任一冻结状态后的方法修改都产生 new protocol version、new Git SHA、new artifact root，并让尚未开始的下游 schedule 重新 seal。若 dev-validation 导致 Detector 修改，返回 `DRAFT`；一旦 formal evaluator 解封，原 formal cohort 永久只读，不能用于下一版 Detector 调参。
