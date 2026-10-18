# 实验室部署与续跑

实验目录固定为 `/home/dcj/java_vuln_work1/vecho-reproduction`。
所有源码、数据集、环境、缓存、日志和报告均放在此目录内。
此分支保存部署工具，vEcho 上游固定到
`68da10388878f8626f0a1d124e500c979ac1e82d`，不依赖未来上游 HEAD。

## 从 GitHub 部署

服务器需有 Git、uv 和 Go >= 1.22。在服务器执行：

```bash
ROOT=/home/dcj/java_vuln_work1/vecho-reproduction
mkdir -p "$ROOT"
git clone --branch codex/vecho-lab-reproduction --single-branch \
  https://github.com/w0NDfu/java-vuln-research.git "$ROOT/control"
python3 "$ROOT/control/reproduction/vecho_cloud/setup_lab.py" --root "$ROOT"
```

`setup_lab.py` 安装独立 Python 3.11.12，复制复现助手，应用已说明的
judge/memory 适配，编译扫描器，并下载、核验全量数据集；不调用模型。
它保留已有 `.env`、运行结果、知识库和源码，不强制重置已有 Git checkout。
`--skip-dependencies`、`--skip-dataset` 仅用于这些步骤已经完成的环境。

数据集是 120 个漏洞版本的完整源码快照，来自 77 个上游仓库；不是全部
历史分支和提交。实验室实际核验 519,093 个 tracked 文件，保留 Git 对象后
约 9.4 GiB。`dataset/dataset-state.json` 记录逐样本 commit、状态与元数据校验和。
克隆器支持 Git 2.25 的浅仓库，并可重复执行以复用缓存和已完成检出。

## 配置和运行

在 `vEcho/.env` 中填写 `OPENLUX_API_KEY`，其余默认使用
`gpt-4.1-mini`、`text-embedding-3-small`、4 个上下文任务并发。
`python.sh` 在导入助手前导出正确数据集路径及本目录下的缓存路径：

```bash
cd /home/dcj/java_vuln_work1/vecho-reproduction
./python.sh "$PWD/vEcho/repro/preflight.py"
# 仅全新实验使用 services.py；它会生成 memory/config.yaml。
./python.sh "$PWD/vEcho/repro/services.py"
nohup ./python.sh "$PWD/vEcho/repro/batch.py" > logs/batch.log 2>&1 < /dev/null &
```

`python.sh` 会切换到 `vEcho`，因此以上参数使用绝对路径。

已有云端实验应先迁移 `repro/runs`、知识库和原配置，保留原始归档及哈希，
再处理运行清单中的 `/workspace` 路径。只拉取本分支不等于迁移了历史实验。
迁移核对完成前不要启动第二份全量任务，以免重复费用或丢失知识库连续性。
云端状态已通过本分支中的加密包导入实验室，保留了全部 6,875 个原始文件。
原始归档及逐文件哈希位于 `migration/`；工作副本仅将评测中的 repo/report
路径本地化，并将两个遗留 running 清单标记为 interrupted，模型输出保持原样。
8 个完成样本与 2 个中断样本均已恢复。已有知识库的 kb 目录原本没有文件，
Chroma SQLite 快照也完整保留，没有额外灌入标签或知识。

恢复已有实验时应保留 `memory/config.yaml`，直接从 memory 目录启动
`main.py --service mcp --config config.yaml --mcp-host 127.0.0.1`，并从 vEcho
目录启动 `repro/memory_bridge.py`；两者均使用本实验的 Python 和缓存环境。
不要再次执行会重写该配置的 services.py。检查 5011/health 及 5010/mcp 工具列表
通过后再启动 batch.py。

首轮策略：跳过完成样本，保留并推迟已有失败/中断样本；新失败记录后继续下一项，
先尝试全部 120 个，再集中修复。`batch.lock` 防止重复队列。
总 API 授权上限沿用 $15；迁移不会重置预算。现有服务商令牌上限曾核验为 $8，
脚本本身不实现精确美元计量，依赖服务商令牌配额限制；不得因迁移扩大配额。

## 实验边界和仓库存储

这是廉价模型下的适配复现，不是论文配置的逐项精确复现。评测使用改编的
IRIS 方法交集规则和 tree-sitter；缺标签、语法失败、未跑样本显式区分。
详细适配与既有审计见 `README.md`、`LABEL_AUDIT.md`、`IDENTITY_REPAIR.md`。

Git 保存代码、模板、说明和 `reproduction/vecho_state/` 下的加密迁移包。
`.env`、配置中的密钥、数据集、模型缓存、运行结果、知识库和归档均不以明文提交。
加密包用 AES-256-GCM 加密，并用实验室 RSA 公钥封装随机密钥；私钥仅留在实验室。
`state_bundle.py` 解密时验证身份、完整性及原始归档哈希，不覆盖已有输出。

2026-10-18 部署核验：服务器已从本分支克隆 `control`，在现有目录成功执行
`setup_lab.py --skip-dependencies --skip-dataset`；judge 适配和扫描器构建完成。
数据集核验为 120/120、519,093 个文件。179 项依赖版本与云端一致；Go 测试、
36 项离线 Python 检查、模型及 Embedding 连通检查、两项记忆服务健康检查均已通过。
2026-10-18 已从 sample_0011 开始续跑，使用 4 个上下文任务并发。
这表示迁移和续跑已完成启动，不代表全量 120 个样本已经复现完成。
当前进度以实验室 `vEcho/repro/batch-state.json` 和 `batch-summary.json` 为准。
