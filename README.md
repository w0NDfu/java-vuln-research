# FastTrack 最新开发版（范围拒绝回流修复）

这是主线程当前源码的稳定复制。范围拒绝回流修复正在开发，尚未将该快照认定为回归或三例重跑通过；不包含任何检测成绩主张。

源码身份、文件哈希及发布状态见 [SOURCE_VERSION.json](SOURCE_VERSION.json) 和 [SOURCE_SHA256SUMS](SOURCE_SHA256SUMS)。原 A1 核心 SHA-256 为 `f4bb22a4457742b99ae08ade40c079165ecc75aed8fb0cb483d1a529b7890034`；三个版本的适配层不同，不能仅凭核心哈希认作同一版本。

## 开发与入口

需要 Python 3.10+。开发依赖：

```sh
python -m pip install -e ".[test,agentic]"
```

生产入口：`python -m java_vuln_research.work1_agent.r2_hecv_run --help`。正式检测仍须由实验室提供同版本源码身份、静态事实、依赖材料、预算和模型配置。

同步仅包含项目源码、查询、Schema、合成测试及必要适配器，不包含模型凭据、数据库、请求缓存或原始实验输出。运行资料与历史证据保留在实验室，不因源码发布被认定为已重新验证。

## 分支

固定维护 [a1](https://github.com/w0NDfu/java-vuln-research/tree/a1)、[r2](https://github.com/w0NDfu/java-vuln-research/tree/r2)、[latest](https://github.com/w0NDfu/java-vuln-research/tree/latest)。后续直接更新这三个分支，不再新建同步分支，详见 [BRANCH_POLICY.md](BRANCH_POLICY.md)。
