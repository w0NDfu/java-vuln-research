# 验证记录（2026-10-19）

实验室代码目录：`/home/dcj/java_vuln_work1/vecho-reproduction/experiments/reconstruction-framework-20261019`。
这里只准备了独立编译产物并做离线验证，没有恢复旧实验、启动付费扫描或使用真实提供商接口。

## 已完成

- Windows Python 3.10.3：44 项测试中 42 项通过，真实 Linux 扫描二进制与完整 RAG 两项因环境条件跳过。
- 实验室 Linux Python 3.11.12：**44 项全部通过，无跳过**。
- Go 1.24.3：独立干净上游克隆 + 已验证可靠性 overlay 编译成功。原始上游保持未修改。
- 真实上游 Go CLI 的 scan 与 guided rescan 经新网关调用本地假提供商，正常完成、产出可读取报告。
- 真实上游 Judge + OpenAI SDK 经新网关保存 verdict、usage 与转录。
- 真实上游 RAGEngine + Chroma 通过本地假 Embedding/LLM 完成知识准入、索引、检索。
- 完整离线工作流用真实 Git 仓库夹具测试静态输入合并、阴性指导触发复扫、新候选复核、方法交集评分与不重复请求的续跑。
- 检查点测试确认保留旧尝试，校验输入/产物哈希；扫描复制检查点后只重绑本轮本地端点与输出路径。逐 case 的证据校验由已部署 scanner overlay 实现。
- 并发预算测试确认事务预留不可穿透限额；未知用量保留预留、历史初始花费计入上限、账本重启不重置、上界违规持久拒绝后续请求。
- CLI plan、preflight、停止标记、结果防误改和项目隔离/共享知识顺序均有实现。

Linux 环境与构建记录见 `validation/linux.json`，原始测试日志保存在实验室该目录的 `tests.log`。

最近一次空值描述兼容修正另执行 snapshot/state 的 6 项定向测试通过；未扩大或重跑付费实验。

## 证据的边界

测试响应全部是合成夹具，不是检测准确率证据；原生扫描接线测试使用空种子完成响应，不能证明发现漏洞的能力。
没有执行实际 CodeQL/Coverity 分析，也没有持有 Coverity 许可证或作者的历史报告。静态生产命令执行器和导入器已实现，真实工具、查询配置与输出仍需提供。
没有实测增强版优于重建版；正式比较需用一致样本/来源/评分，单独记录重复实验与成本。

## 在实验室复查

```bash
cd /home/dcj/java_vuln_work1/vecho-reproduction/experiments/reconstruction-framework-20261019
export PYTHONDONTWRITEBYTECODE=1
export VECHO_UPSTREAM_TEST_ROOT="$PWD/upstream-clean"
export VECHO_SCANNER_TEST_BINARY="$PWD/offline-runtime/runtime/vecho-scan"
export VECHO_TEST_REAL_RAG=1
/home/dcj/java_vuln_work1/vecho-reproduction/.venv/bin/python -m unittest discover \
  -s reproduction/vecho_experiment/tests -t . -v
```

正式运行配置示例仍保留零预算/零请求数及待填写的价格、版本与报告位置。运行前先做 preflight，不能把该离线验证配置当作已具备全量实验输入。
