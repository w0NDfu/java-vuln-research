# vEcho 实验重建框架

这是对公开组件缺失的**实验工程**的补充，不是作者未发布代码的原样还原。目标是固定输入和配置、接通多来源候选与反馈学习、保存逐条证据，再公平比较重建版与改进版。论文数字是否重现或超过，需要正式实验验证。

版本差异和代码证据见[论文/代码核对报告](../vecho_cloud/PAPER_CODE_AUDIT_20261019.md)，本轮测试与实验室路径见[验证记录](VALIDATION.md)。

没有恢复昨天的付费队列。示例 API 预算、最大请求数和价格默认是 0；`plan` 不请求模型，`run` 不带 `--execute` 也只展示计划。

## 已实现的完整链路

1. 按显式样本顺序读取 project_info，验证漏洞提交和工作树；导出不带 Git 的只读研究快照。CVE、提交标识、配置的项目/依赖名称按原字节长度屏蔽，行号/列位置不变。原始来源与变换清单在模型可见源目录之外。
2. 导入或执行配置好的静态分析生产命令：SARIF 2.1.0、Coverity JSON v7 形状、canonical JSON。SARIF URI bases、artifact/location 索引及多条路径得到保留；无法解析的来源报错。Coverity 保留诊断事件，明确不把它们称为独立证明的污点链。
3. 运行真实上游 ScanAgent；按完整路径与 CWE/规则保守合并，保存所有来源；不会只按终点折叠不同路径，也不会给只有位置的告警伪造路径。
4. 每条新候选调用真实上游 Judge，保存输入、判定、指导、工具调用和请求/响应。失败和 unknown 分开；缺失 save_result 不伪造成漏报或 false。
5. TP、FP 的指导均可反馈到真实 rescan；新候选继续复核，已有候选不重复判。显式配置最大复扫轮数、连续无新候选次数、候选上限。达到候选上限记不完整，不截断后伪装完成。
6. 知识服务复用上游 RAGEngine，提供现有客户端所需的工具 HTTP 协议；每次运行独占本地端口和知识目录，结束自动关闭。入库策略可选择 manual、auto_index、frozen、disabled；检索与入库失败传播为阶段失败。
7. 分析结束后才读取 fix_info，按原始源码方法位置做路径交集评分；汇总执行覆盖、缺失标签、unknown、检测率、AvgFDR、AvgF1。没有原作者评分程序，因此标注 tree-sitter 适配实现，不能称字节等同的 IRIS 或作者评测。
8. 完成项按输入/配置与输出 SHA256 校验后续跑。失败尝试保留原目录；扫描失败使用已修复的上游检查点复制续跑，完成 case 不重复做模型分析。失败 case 从头重试，**不是任意 HTTP 回合恢复**。

## 三种配置

| 文件 | 含义 |
|---|---|
| `configs/reconstruction.json` | arXiv v2 的 GPT-4.1 模型家族、多来源输入；自动索引和固定顺序共享知识落实论文反馈机制；历史入库策略、初态和顺序未知，明确标作重建假设 |
| `configs/enhanced.json` | 同一模型、输入、记忆策略与评分；更高上下文预算、最终轮保存适配及更多反馈轮次。属于改进假设，不预先声称更好 |
| `configs/source-only-ablation.json` | 显式去掉静态输入的消融，不能当完整论文复现 |

例子保留前十个样本的明确顺序；全量须在独立配置中列出 1..120。`replicate` 仅标识独立重复实验编号，不会偷偷启动多次；每个编号使用新的 workspace。模型、采样、价格、轮次、知识初态和顺序在开始后冻结，修改需新建实验，不能混入原组。

配置里的 context_tokens 是**操作员声明的提供商计费上界**，用于保守预留，必须核实所用路线。max_output_tokens 强制覆盖每次聊天请求；没有显式采样值时配置使用 `{}`，表示提供商默认。默认不代表作者历史温度或轮数已知。

## 安装和准备（不调用模型）

从本仓库根目录运行，Python >=3.10、Go >=1.22；完整记忆还需要上游 memory/requirements.txt 的依赖。请使用独立虚拟环境，保存实际 freeze，不修改旧实验环境。

```bash
python -m pip install -r reproduction/vecho_experiment/requirements.txt
python -m pip install -r /path/to/upstream-clean/memory/requirements.txt
python -m pip freeze > /path/to/experiment-environment-freeze.txt

# upstream-clean 必须是干净且固定提交的上游仓库。
git clone https://github.com/vEcho-project/vEcho.git /path/to/upstream-clean
git -C /path/to/upstream-clean checkout --detach 68da10388878f8626f0a1d124e500c979ac1e82d

python -m reproduction.vecho_experiment plan --config /path/to/experiment.json
python -m reproduction.vecho_experiment prepare --config /path/to/experiment.json
python -m reproduction.vecho_experiment preflight --config /path/to/experiment.json
```

`prepare` 将干净上游克隆到新 workspace/runtime/artifact，应用已测过的可靠性 overlay，按配置决定是否安装 Judge 保存适配，编译扫描器并写入哈希。它不会修改原始上游、旧结果或启动服务。配置中提供 artifact、dataset、workspace 的路径必须互相隔离，workspace 不得覆盖数据集。

模型网关统一设置 scan/judge/memory/embedding 的地址和模型；RAG 配置仅保存本轮临时本地令牌，真正提供商 key 只从环境读取。不要把 key 写进 JSON 或提交到 Git。

## 静态告警和生产命令

示例配置要求 CodeQL 与 Coverity 两份实际报告。填入真实版本、查询/检查器策略及报告 source_root。报告路径可使用 `{id}`、`{sample}`；相对路径相对于配置文件。绝对报告文件路径必须映射到 source_root，不能猜 basename。

没有历史报告时，可以使用已安装、已锁版本的工具重新生成；该输入属于**重建候选集**。每个来源可配置 `commands`、`version_command` 和 `timeout_seconds`。例如，先按官方 CodeQL CLI 建数据库并分析，再把最终 SARIF 写入 `{report}`。框架不代替 Coverity 许可证或供应商安装。

```json
{
  "tool": "CodeQL", "version": "<实际 CLI 版本>",
  "queries": "<已锁定的查询套件路径/包版本和哈希>",
  "format": "sarif", "path": "unused-when-generating.json",
  "source_root": "/实际/原始源码根目录",
  "version_command": ["/path/to/codeql", "version", "--format=json"],
  "commands": [
    ["/path/to/codeql", "database", "create", "{work}/database", "--language=java", "--source-root={source}", "--command=mvn -DskipTests package"],
    ["/path/to/codeql", "database", "analyze", "{work}/database", "/path/to/locked-suite.qls", "--format=sarifv2.1.0", "--output={report}"]
  ],
  "required": true
}
```

命令以 argv 运行，不拼 shell。源码构建是配置的显式工具步骤，原始目录可能产生构建文件；分析完会再次核对源码提交和 tracked diff。推荐为生成静态报告准备独立的已核验工作副本。

导入外部报告会记录“声明版本”，不冒称验证过生产过程。生产命令会检查实际版本输出，并保留日志。`query_files` 可以列出查询套件、包锁等文件，其实际字节哈希进入阶段身份，续跑时拒绝变更。`source_root` 可写为 `{source}`，自动映射当前已核验源码根目录。对未知 Coverity 导出布局先转 canonical 或 SARIF；拒绝悄悄丢字段。

SARIF 依据：[OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)。

## 正式执行与停止

只有准备、输入、价格、凭据和累计预算均配置好后，再执行：

```bash
python -m reproduction.vecho_experiment run --config /path/to/experiment.json --execute
python -m reproduction.vecho_experiment status --config /path/to/experiment.json
python -m reproduction.vecho_experiment stop --config /path/to/experiment.json
# 停止标记不会自动清除。明确要续跑时先移除该 workspace 的 STOP 文件，再用：
python -m reproduction.vecho_experiment run --config /path/to/experiment.json --execute --resume
```

stop 禁止新的模型请求；已在途请求仍可能耗时至配置的超时。Ctrl+C 还会终止本框架拥有的扫描子进程组，关闭本轮本地服务，不影响其他实验。

每个 workspace 的 budget.sqlite 使用跨线程事务预留费用，重启不重置。按照所声明的最大上下文/输出与价格预留最坏费用，收到有效 usage 后结算；超时、缺失 usage 和中断保留完整预留；超出声明上界则持久阻断新请求。所有模型角色和重试共同计费。**这不是提供商账单保证**：实际价格、计费规则和先前花费须正确配置，外部程序费用不由该账本控制。

预算 limit_usd 是含 opening_spend_usd 的累计上限。昨天已经花掉的钱应计入 opening_spend_usd，不能因新目录把授权预算重置。开销不确定时先核对服务商账单；默认零预算不运行。

## 人工审核知识

如需与公开代码默认暂存方式做消融，在独立配置中将 memory.policy 改为 manual，并标记 profile=ablation。manual 会将文档保存至 knowledge/<sample>/kb_tmp（共享模式为 knowledge/campaign/kb_tmp），只检索 kb。先读文档，记录其 SHA256，再显式批准：

```bash
python -m reproduction.vecho_experiment approve --config /path/to/experiment.json \
  --sample 1 --document common/general/<文件>.md --sha256 <审核过的SHA256>
```

此命令只记录审核决定，不调用 Embedding；下次明确执行实验并启动该知识库时校验哈希、入库和索引。auto_index 是另一组实验设置，不能与 manual 混报。campaign 共享知识时失败即停止队列，保持配置的跨项目因果顺序；project 隔离则可记录失败后继续其他项目。

## 产物、评测与公平比较

- experiment.json：配置、运行代码/模型/输入身份、状态与账本汇总。
- projects/sample_*/stages：每个静态来源、源快照、扫描、候选复核、复扫的输入身份、尝试历史和 SHA256 receipt。
- final-report.json / evaluation.json / result.json：最终候选、判定、轮次、终止原因、逐路径匹配和项目结果。
- private/model-requests：每个实际请求及响应（不记录授权头/提供商 key），包括失败收据；其中含源代码，保留在实验目录，不提交公共仓库。
- knowledge：知识初态、暂存、准入决定与索引。种子是操作员提供的研究输入，其哈希冻结；不能包含答案/修复标签。
- summary.json：完成与可评分样本分别列出；失败、缺失标签、解析错误不混成零检出。

```bash
python -m reproduction.vecho_experiment compare \
  --left /path/to/reconstruction/summary.json \
  --right /path/to/enhanced/summary.json --out /path/to/comparison.json
```

比较限定同一源身份的共同完成样本，列出新增、回退与缺失项目。应报告每次独立重复的分布、token/费用与运行时间，而非挑最好一轮；两组使用同样的静态输入、样本、匿名化和评分，不能按目标标签引导扫描或调参后复用测试集。unknown 和 blocked 覆盖也要报告；未匹配的告警不是已独立验证的误报。

## 离线验证

```bash
python -m unittest discover -s reproduction/vecho_experiment/tests -t . -v
VECHO_UPSTREAM_TEST_ROOT=/path/to/upstream-clean python -m unittest discover -s reproduction/vecho_experiment/tests -t . -v
```

测试覆盖真实 Git 快照、输入转换、反馈闭环、失败续跑、知识策略、路径评分和并发预算；第二条还用真实上游 Judge + OpenAI SDK + 本地假提供商验证接线。所有模型响应均为测试夹具，不是漏洞发现效果证据。

仍需外部提供：静态工具与许可证、真实报告或可重建查询配置、实际模型价格与凭据，以及可能由作者补充的历史实验材料。仅补代码不能制造这些输入，也不能保证获得作者相同的数字。
