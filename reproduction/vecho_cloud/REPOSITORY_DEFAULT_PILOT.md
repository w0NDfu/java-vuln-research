# 仓库默认配置：前 10 个项目

当前状态：用户要求暂停后，已完成[扫描可靠性修复](SCANNER_REPAIR.md)的离线验证及部署。
队列保持暂停，不能将以下历史启动说明解读为仍在扫描。

2026-10-18 用户明确要求按 vEcho 仓库自身配置先跑 10 个项目。
此前 GPT-4.1 mini 队列已停止，12 个完成结果及其他尝试仍保留。
GPT-4.1 目录仅做过环境准备，没有启动实验扫描。

实验室新目录：
`/home/dcj/java_vuln_work1/vecho-reproduction/experiments/vecho-default-first10-20261018`。
元数据见该目录 `experiment.json`，最新实验指针见总目录的
`migration/active-experiment.json`。

后续用户已授权修复第 1 个项目复核未保存的问题：保留 Kimi K2.6 和十轮上限，
最后一轮显式选择 save_result，证据不足允许 unknown；纯文本回复在剩余轮次内继续。
因此下表中的原生复核循环是最初启动配置，修复后的结果以
`judge_metadata.verdict_protocol`、实验目录 `judge-repair.json` 为准，不能混称完全原生。
未执行保存仍记失败，不把它伪装成有效判定。成功的已有判定及完成扫描通过检查点复用。
原始循环备份和原始产物哈希均保留。知识暂存方式、模型和并发没有改动。

| 项目 | 本轮设置 |
|---|---|
| vEcho 版本 | `68da10388878f8626f0a1d124e500c979ac1e82d` |
| 扫描及复核模型 | 仓库默认 `Pro/moonshotai/Kimi-K2.6`，OpenLux 对应 ID `kimi-k2.6` |
| 知识库 LLM | `gpt-3.5-turbo` |
| Embedding | `text-embedding-ada-002` |
| 上下文并发 | 仓库默认 5 |
| 复核循环 | 上游原生循环，10 轮；未应用之前的最终轮强制保存适配 |
| 知识保存 | 上游默认 `use_tmp=true`，保存到暂存目录，不自动改为直接索引 |
| 扫描预算 | 保留上游每块 8 轮、每任务 8 步、每步 6 轮、30 次工具调用 |
| 范围 | project_info.csv 中 ID 1～10 |

使用独立空知识库和独立结果目录，共用已核验的数据集、Python 依赖及缓存。
保留 judge 提示词路径修正、回环地址绑定和 MCP 协议桥接；API 地址及凭据
沿用用户的 OpenLux 账户，因此不是 SiliconFlow 原端点，也不能仅凭中转模型 ID
证明底层服务快照完全相同。此轮是公开仓库默认配置运行，不等同论文主实验：
论文采用 GPT-4.1，并包含历史 CodeQL/Coverity 输入等当前缺失材料。

知识库的暂存行为也按上游保留，不能把暂存文档写入宣称为已进入检索索引。

队列命令为：

```bash
EXP=/home/dcj/java_vuln_work1/vecho-reproduction/experiments/vecho-default-first10-20261018
"$EXP/python.sh" -u "$EXP/vEcho/repro/batch.py" --limit 10
```

查看该目录 `batch.log`、`vEcho/repro/batch-state.json` 和
`vEcho/repro/batch-summary.json`。不得重复启动已有队列。
`--limit 10` 对运行 ID 和统计范围均设定边界；越界值在模型调用前被拒绝。
首轮每个项目尝试一次，失败记录后继续；不会自动扩展到 120 个。
整体 API 授权上限仍是此前的 $15，未重置已花费用；既有令牌的 $8 总配额没有提高。
