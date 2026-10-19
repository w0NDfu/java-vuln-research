# vEcho 论文与公开代码核对（2026-10-19）

结论：公开组件可以运行，也可以补齐外围工程做独立复现实验；目前公开材料不足以严格重放作者原实验、保证重现其检测数字。此前把“公开仓库默认运行”“论文原始实验”和“我们编排的修复版”混称原版不准确。

本次仅阅读与离线统计，没有启动实验、知识库服务或模型调用。实验保持用户要求的停止状态。

## 核查对象与版本

- 公开仓库：<https://github.com/vEcho-project/vEcho>，本地 `vEcho/`。
- 本地与远端 HEAD 均为 `68da10388878f8626f0a1d124e500c979ac1e82d`；本地该仓库干净。提交说明为 `Publish sanitized vEcho artifact`，日期 2026-06-17。它不是作者完整历史实验目录。
- 完整核对的论文方法、实验设置与指标：arXiv v2，2026-03-04，<https://arxiv.org/html/2603.01154v2>。
- 另发现 SSRN 同作者论文：<https://ssrn.com/abstract=6981148>，搜索索引中的官方摘要标注 2026-06-23。其官方 PDF 本次返回 403；只核对到摘要，不能把 arXiv 的所有模型/参数外推到这一版本。
- 本报告的“未找到”限定于上述提交的全部 103 个受跟踪文件（含 `.gitignore`），不表示作者私下没有相应材料。

## 首先纠正结果版本混用

| 来源 | vEcho 命中 | IRIS 命中 | vEcho AvgF1 | IRIS AvgF1 |
|---|---:|---:|---:|---:|
| arXiv v2 表 II | 78/120 | 55/120 | 0.422 | 0.177 |
| 仓库两份结果 CSV，重新统计 | 73/120 | 50/120 | 0.3973870669 | 0.1166300542 |
| SSRN 官方摘要 | 73/120 | 50/120 | 0.3974 | 0.1166 |

CSV 与 SSRN 摘要的四项汇总吻合，说明做结果对比必须先固定论文版本。吻合本身不能证明 CSV 的实际模型、运行参数、输入和检索状态。

统计依据：`Result/vEcho_Result.csv`、`Result/IRIS_Result.csv`；均为 120 行。逐文件 SHA256、统计值和版本信息见同目录 `PAPER_CODE_AUDIT_20261019.evidence.json`。这只是复算已公布表格，不是重新检测 120 个项目。

## 论文机制与代码的对应关系

论文方法的要点是多来源候选、工具复核、记忆反馈与引导复扫；arXiv 主实验使用 GPT-4.1。它既有从源码主动找线索的 ScanAgent，也有以静态告警为初始输入的完整流程。单独源码扫描能运行，但覆盖的实验条件不同。[arXiv 方法与设置](https://arxiv.org/html/2603.01154v2#S3)

| 核查项 | 公开代码实际内容 | 对复现的影响 |
|---|---|---|
| 模型 | `scaner/internal/config/config.go:13`、`judge/vecho_judge/app/config.py:35` 默认 Kimi-K2.6 / SiliconFlow，可覆盖 | 默认配置不能当作 arXiv 主实验配置；SSRN 实际模型未由本次全文证实 |
| 扫描 | Go CLI 提供 scan/rescan 的 run、resume、export；有规划、种子发现、上下文链及报告导出 | ScanAgent 是真实可运行组件，不只是提示词或空壳 |
| 静态告警来源 | judge 只注册 canonical、vecho_scan、custom 三种输入适配；未找到 CodeQL/Coverity 调用脚本、查询包、版本锁定及多来源结果合并总管线 | 可自行转 canonical 接入，但不能直接重建作者原始候选集 |
| 告警格式 | custom 适配生成的 `tainted_data_flow=[]` | 接入静态告警时应保留原始路径节点；只映射文件/行会影响路径交集评分 |
| 复核工具 | 文件、目录、Java 上下文窗口、记忆读写及判定保存；Java 实现查找是文本/正则窗口 | 未提供 Web 搜索工具；当前 judge 提示词还明确排除外部公告、补丁和答案。这与 arXiv 的工具描述不同 |
| 知识读写 | 有 common 和项目知识检索、保存工具、Chroma 索引；默认 `use_tmp=true` 保存至 `kb_tmp` | 暂存文档不等于已被 RAG 检索；需审核迁入 `kb` 并更新索引，或明确记录其他策略 |
| 复扫反馈 | judge 生成 guidance 与 bundle；rescan 会将 guidance 加入规划和提示 | 已有 EVP 的组件支持，但没有自动反复调度到停止条件的顶层实验脚本 |
| 阴性判定的指导 | `outputs/writer.py:58` 默认 bundle 只收 true 的 guidance；另有完整 `guidance.json`，rescan 的 `--guidance` 可以接收 | 不能说代码完全不支持 FP 反馈；需要编排者显式传完整 guidance |
| 数据与评测 | 有 project_info、fix_info 和汇总 CSV；未找到原始逐条告警/路径/复核转录/运行清单、完整评测及匿名化脚本 | 元数据可用于新实验，汇总表无法代替原始证据或重建运行状态 |
| 环境 | Go 1.22、Python >=3.10；Python 依赖多为无精确版本要求 | 可建立新环境，历史依赖环境不能仅据此精确恢复 |

代码证据均来自上述未修改上游提交。模型、输入和工具范围的差别是实质实验条件；不能仅凭 API 调用成功认定已经对齐。

## 静态代码中能直接确认的运行障碍

1. `judge/vecho_judge/app/config.py:31` 使用 `parents[2]`，默认提示词会定位到 `judge/prompts/prompt_judger.txt`，该文件不存在；实际文件位于 `judge/vecho_judge/prompts/`。可以显式指定 `--prompt`，无须修改推理规则。
2. 扫描和复核客户端向配置 URL POST `{tool, arguments}`；记忆服务运行 FastMCP HTTP。代码中未提供两者的直接适配端点，完整部署需要协议适配或统一客户端。证据：`judge/.../memory_client/client.py:20`、`scaner/internal/memorymcp/client.go`、`memory/services/mcp_service.py:376`。
3. `judge/.../runtime/llm_loop.py:96` 在模型不调用工具时直接结束；若此前没有保存判定，`:135` 抛错。十轮上限也可能没有判定。这应记为执行失败，不能折算为漏洞未检出。
4. `scaner/internal/contextaudit/runner.go:71` 一个工作项报错会取消同一阶段其他工作项；`:193` 的外层超时包含客户端重试。长请求、限流和工具格式偏差可能阻断完整实验。
5. 原生 resume 会再次调用上下文审计；未见逐个已完成 case 的校验复用。因此不能把原生 resume 宣称为无重复费用的逐项续跑。

以上障碍有工程解决办法。超时、协议和结果保存修复不能证明检测质量提高；修改提示词、工具选择或停止规则也应另行记录，不能混称字节不变的原版。

## 昨天的实验到底验证了什么

实验室使用的是我们编排的 `scan → judge → 一轮 rescan → judge → 评分`，Kimi 经 OpenLux、独立空知识库，叠加记录在案的可靠性修复；未合入作者历史 CodeQL/Coverity 告警。评分是 tree-sitter 方法位置适配，不是作者公开的原始评测程序。

Spark `sample_0002` 最终流程正常结束、保留一条非基准位置告警，目标 CVE 评分为未命中。它证明修复后的这条运行链可结束；不能据此认定完整论文系统已复现，也不能据一例推断所有 120 个项目的检测率。

此前把“默认 Kimi”直接称为“作者论文原配置”不严谨；把“原版结果”统一引用 78/120 也混淆了 arXiv、SSRN 和仓库 CSV 三个来源。

## 能复现到什么程度

| 目标 | 判断 | 所需证据 |
|---|---|---|
| 跑通公开 Scan/Judge/Memory/Rescan 组件 | 可以，已有单样本工程证据 | 完整运行日志、无阶段失败、最终报告 |
| 按公开方法重建一套独立实验 | 有条件可行，需要补编排、静态输入、知识入库与评测 | 固定模型/提示词/查询版本，保留每个阶段原始产物；公开所有自补部分 |
| 严格重放作者实验、核验每条 TP/FP | 现有公开包不足 | 作者原始候选、路径、逐条判定、运行配置、知识库策略/状态、完整评分材料 |
| 保证得到 73/120 或 78/120 | 不能保证 | 材料对齐后仍需实验验证，API 非确定性也要记录 |

重新开展实验前，应先固定目标版本，并向作者核实与之对应的实际模型、采样/轮次参数、CodeQL/Coverity 版本与查询、静态告警、自动入库/人工审核策略、跨项目运行顺序、复扫停止条件、匿名化与评分脚本及逐条输出。不能先假定这些内容再大量调用模型。

如果材料拿不到，合理名称是“基于 vEcho 公开组件的方法重建/复现实验”，并单独列出缺失材料和自主实现。它仍有研究价值，但与“成功重现作者结果”是不同的完成标准。

## 关键公开代码链接

- [扫描默认配置](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/scaner/internal/config/config.go#L12)
- [复核配置和提示词位置](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/judge/vecho_judge/app/config.py#L29)
- [输入适配注册](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/judge/vecho_judge/adapters/__init__.py#L11)
- [复核提示词](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/judge/vecho_judge/prompts/prompt_judger.txt#L5)
- [复核工具与循环](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/judge/vecho_judge/runtime/llm_loop.py#L87)
- [复扫 bundle 输出](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/judge/vecho_judge/outputs/writer.py#L57)
- [知识默认暂存策略](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/memory/services/mcp_service.py#L163)
- [审核后入库和更新索引](https://github.com/vEcho-project/vEcho/blob/68da10388878f8626f0a1d124e500c979ac1e82d/memory/services/web_service.py#L387)
