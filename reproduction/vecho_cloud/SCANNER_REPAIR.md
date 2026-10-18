# 扫描超时、参数兼容与断点修复

2026-10-18 用户要求修复。修复已部署到实验室的
`experiments/vecho-default-first10-20261018/vEcho`，但实验队列及记忆服务保持暂停。
本轮修复验证没有调用付费模型 API，未更换模型、并发或扩大配额。

## 改动

- `ToolCallRequest` 支持原生 `args` 及已观察到的同层参数格式。
  同时出现两种格式、空参数或非对象参数时明确拒绝，避免猜测或覆盖参数。
- ContextAudit 单任务请求失败后保存 `failed` 记录，其余任务继续；存在失败时
  整个扫描阶段返回 `incomplete` 和非零退出码，不生成可计入基准的完成报告。
- 显式 resume 核对种子完整身份、案例／结果身份与状态，以及已读取源码 SHA256，
  复用完成任务。失败任务先归档旧 case、transcript 和工具结果，再开始新尝试。
  原始会话的审计事件不清空。种子或证据源码变化时在请求前拒绝复用。
- Python 流程在恢复失败阶段前备份完整阶段和旧进程日志；完成阶段不重跑。
  每个样本增加独占锁，拒绝重复 runner。新 run 也不能覆盖已有扫描会话。
- 候选发现续跑保持已完成 block，工具结果从现有最大编号继续写。
  尚未完成的 block 会重新开始，失败上下文任务会重新尝试；不宣称能恢复到任意 HTTP 回合。
- 增加脱敏 `llm-attempts.ndjson`，记录每次逻辑调用耗时、尝试次数、HTTP 状态、
  finish_reason、返回 usage 及其可用性。没有响应时不能推算实际计费。
  返回 length 截断或空内容明确失败，避免误当作完整分析。
- 保留每次请求的有限超时，deadline 已耗尽就退出，不在无剩余时间时继续重试。
  resume 默认超时修正为和 run 一致的 180 秒，避免上游 resume 隐式降到 60 秒。
  可在 `.env` 显式设置 `VECHO_SCAN_TIMEOUT=600s` 调整后续尝试；本次没有自动调大。

这属于运行可靠性适配，未放宽证据判定、工具权限、漏洞位置标签或模型思考／工具调用轮次。
被阻断的只读 Bash 命令仍受原规则限制。

## 验证证据

实验室离线验证目录 `repair-validation/` 与实验根目录日志保存：

- 原有 Go 全套检查及新增修复检查通过。
- ContextAudit、LLM 包的 race 检查通过。
- 45 项 Python 检查通过，包括阶段备份、完成阶段跳过、未安装修复时拒绝恢复等。
- 第 3 个项目真实失败的 12 条参数调用全部回放通过。
- 原扫描 57 个完成任务通过只读检查点核验：第 1 个 35，第 2 个 10，第 3 个 12。
- 模拟接口验证单任务超时后另一任务仍完成；恢复只请求失败任务；已有结果字节不变。
- 源码或种子变化会在模型请求前拒绝恢复；未完成阶段不能生成 completed 报告。
- 部署前后核对全部 1,523 个原始运行文件，哈希均未变化；原扫描器和源码保留备份。
- 校验式安装连续执行两次，第二次零改动；已重新编译扫描器。

机器证据：`scanner-repair-validation.json`、`scanner-repair-test-result.json`、
`scanner-repair-race-result.json`、`python-scanner-repair-test-result.json`、
`scanner-repair-runs-before.sha256.json`。

离线验证证明修复行为和检查点兼容性；尚未验证中转服务长时间实际推理是否稳定，
也不保证以后不再发生超时。队列不会因本次修复自动恢复。

## 重复部署

`scanner_overlay/manifest.json` 固定上游 commit 和逐文件原始／修复 SHA256。
安装器先检查全部文件，遇到未识别本地修改立即拒绝，不会默默覆盖。

```bash
EXP=/home/dcj/java_vuln_work1/vecho-reproduction/experiments/vecho-default-first10-20261018
TOOLS=/home/dcj/java_vuln_work1/vecho-reproduction/control/reproduction/vecho_cloud
"$EXP/python.sh" "$TOOLS/apply_scanner_repair.py" --artifact "$EXP/vEcho"
# 编译测试和扫描器后再更换可执行文件；安装器本身只部署源码，不启动扫描。
```

恢复须使用修复后的 run.py 及扫描器，明确指定已有 run 目录；不运行无边界全量队列。
原始模型实验仍仅限前 10 个项目，$15 总授权和既有 $8 令牌配额继续沿用。
