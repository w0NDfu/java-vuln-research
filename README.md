# FastTrack R2 / recovery-01

这是历史冻结源码的同步；没有在此次 GitHub 同步中重跑检测或评分。

源码身份、文件哈希及发布状态见 [SOURCE_VERSION.json](SOURCE_VERSION.json) 和 [SOURCE_SHA256SUMS](SOURCE_SHA256SUMS)。原 A1 核心 SHA-256 为 `f4bb22a4457742b99ae08ade40c079165ecc75aed8fb0cb483d1a529b7890034`；三个版本的适配层不同，不能仅凭核心哈希认作同一版本。

## 开发与入口

需要 Python 3.10+。开发依赖：

```sh
python -m pip install -e ".[test,agentic]"
```

`reference_entrypoints/` 保留原实验入口及冻结提示/规则；这些入口含历史实验室路径，仅供复现审查，不能作为通用一键运行脚本。

同步仅包含项目源码、查询、Schema、合成测试及必要适配器，不包含模型凭据、数据库、请求缓存或原始实验输出。运行资料与历史证据保留在实验室，不因源码发布被认定为已重新验证。

## 分支

固定维护 [a1](https://github.com/w0NDfu/java-vuln-research/tree/a1)、[r2](https://github.com/w0NDfu/java-vuln-research/tree/r2)、[latest](https://github.com/w0NDfu/java-vuln-research/tree/latest)。后续直接更新这三个分支，不再新建同步分支，详见 [BRANCH_POLICY.md](BRANCH_POLICY.md)。
