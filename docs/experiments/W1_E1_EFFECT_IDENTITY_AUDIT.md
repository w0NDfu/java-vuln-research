# W1-E1 EffectIdentity Alignment Audit

## 1. 审计边界

本审计只比较现有冻结工件：

- E0：`/workspace/experiment-output/W1-E1-DEV16-E0-20260826-002/baseline/*.sarif`
- Route A：`/workspace/experiment-output/W1-E1-DEV16-20260826-001/`
- E0 path traceability：`/workspace/experiment-output/W1-E1-PATH-TRACEABILITY-AUDIT-20260827-001/e0_path_traceability.jsonl`

未重跑 CodeQL，未读取 GT，未修改 Detector，未新增候选规则或 propagation semantics，也未启动 E2、Route B、Wrapper/Library、Field/State 或 LLM。

审计对象为 437 条 E0 native path 的终端 sink/effect，以及 59 个按 unique `candidate_id` 计数的 Route A SecurityEffect。437 条路径对应 120 个唯一 E0 effect 位置。

## 2. 统一 EffectIdentity

统一身份字段如下：

| 字段 | E0 sink | Route A SecurityEffect |
|---|---|---|
| project | SARIF 所属 `project_id` | anchor `project_id` |
| file | SARIF terminal location；统一斜杠并做双向 suffix normalization | anchor `location.file` |
| method | 从冻结 `src.zip` 的 sink 上下文离线恢复 | `method_identity` |
| callsite | SARIF source range + 冻结源码语句 | `call_identity` |
| callee | sink 源码调用表达式 | `call_identity` 中的 callee/signature |
| argument_index | 仅在 SARIF range 能唯一定位实参时填写；否则为空 | `argument_index` |
| critical_role | E0 `rule_id` 所定义的 sink role | SecurityEffect `effect_type` |
| node_kind | SARIF taxa/源码节点形态 | `anchor_kind` |
| source_range | SARIF region；至少保留 file + line | anchor `location` 与 `call_identity` 行号 |

可审计性检查：

- 59/59 Route A SecurityEffect 均有 `MAPPED` analysis anchor，并具备 method、callsite、argument index、value role 与 location。
- 437/437 E0 sink 均有 project、file、line 与 CodeQL `rule_id`；120/120 个唯一 sink 位置均可从对应冻结 CodeQL 数据库的 `src.zip` 解析源码。
- 因而本次没有因工件缺失而落入 `NOT_EVALUABLE` 的路径。

## 3. 分层匹配结果

### 3.1 身份门逐级收缩

| 身份门 | E0 paths | 占 437 |
|---|---:|---:|
| same project：项目内至少有一个 Route A SecurityEffect | 356 | 81.5% |
| same file：规范化后文件相同 | 1 | 0.2% |
| same method | 1 | 0.2% |
| same callsite/source range | 0 | 0.0% |
| same callee/signature + critical argument/index | 0 | 0.0% |
| compatible value-role 且身份足以确认同一 effect | 0 | 0.0% |

81 条路径所在项目完全没有 Route A SecurityEffect。其余 356 条虽然项目内存在 effect candidate，但只有 1 条与任一 candidate 落在同一文件和方法。

该唯一近邻是 D002 的 `java/log-injection`：

- E0 sink：`src/main/java/spark/staticfiles/StaticFilesConfiguration.java:78`，调用 `LOG.warn(...)`；
- Route A effect：同一方法内第 76 行的 `java.io.PrintWriter.write(...)`，`argument_index=0`，`effect_type=RENDERING`。

两者相差两行，但 callee、critical argument 和 effect role 均不同。这是两个真实的不同调用点，不是 location off-by-one、source-range 表示或路径前缀差异。

### 3.2 互斥匹配漏斗

| 最佳匹配层级 | E0 paths |
|---|---:|
| exact-location match | 0 |
| same-callsite match | 0 |
| same-callee+arg match | 0 |
| semantic-compatible match | 0 |
| no-match | 437 |

`same project` 或仅有粗粒度 effect-family 相容不被计作 semantic identity；必须至少有 method/callsite/callee/critical-value 证据确认是同一安全效应。

## 4. 未匹配分类

分类优先级为：同一语义调用但位置编码不同 → 同一调用但 critical value role 不同 → 同文件/方法或粗粒度 family 相容但调用点不同 → 项目内仅存在不相容 effect type → 项目内无 effect candidate → 工件不足。

| 分类 | E0 paths | 说明 |
|---|---:|---|
| `LOCATION_REPRESENTATION_MISMATCH` | 0 | suffix normalization、行号与 source range 均未恢复同一 effect |
| `VALUE_ROLE_MISMATCH` | 0 | 没有路径先到达同一 callee/callsite，故不存在单纯 argument/value-role 偏差 |
| `CALLSITE_IDENTITY_MISMATCH` | 10 | D002 同文件/方法但为不同调用点 1 条；V022 粗粒度 RENDERING family 相容但不同调用点 5 条；V025 粗粒度 FILESYSTEM_ACCESS family 相容但不同调用点 4 条 |
| `EFFECT_TYPE_MISMATCH` | 346 | 同项目有 candidate，但当前 effect types 与 E0 rule sink family 不相容 |
| `TRUE_MISSING_EFFECT_CANDIDATE` | 81 | D001 57、D003 8、D004 8、P006 8；项目内 Route A SecurityEffect 为 0 |
| `NOT_EVALUABLE` | 0 | 冻结工件足以判断 |
| **合计** | **437** | 互斥且完备 |

粗粒度 family 相容仅用于区分 `CALLSITE_IDENTITY_MISMATCH` 与 `EFFECT_TYPE_MISMATCH`，不用于宣称匹配成功。保守映射只采用直接对应关系：`http-response-splitting/xss → RENDERING`、`path-injection → FILESYSTEM_ACCESS`。即使采用该宽松映射，10 条也没有同一 file/method/callsite/callee 证据。

项目级分解：

| project | paths | CALLSITE mismatch | EFFECT_TYPE mismatch | TRUE missing |
|---|---:|---:|---:|---:|
| D001 | 57 | 0 | 0 | 57 |
| D002 | 55 | 1 | 54 | 0 |
| D003 | 8 | 0 | 0 | 8 |
| D004 | 8 | 0 | 0 | 8 |
| P006 | 8 | 0 | 0 | 8 |
| P010 | 51 | 0 | 51 | 0 |
| V009 | 8 | 0 | 8 | 0 |
| V022 | 136 | 5 | 131 | 0 |
| V025 | 106 | 4 | 102 | 0 |
| **合计** | **437** | **10** | **346** | **81** |

## 5. 结论

1. **0/437 不是主要由表示层问题造成。** 路径前缀、斜杠和 suffix normalization 后仍只有 1 条落入同一文件；该条源码核验为两个不同 callee。没有证据支持把 0/437 解释为 location/value-role 编码误差。
2. **Route A SecurityEffect 存在系统性 coverage gap。** 81 条所在项目完全没有 effect candidate；346 条只有不相容 effect type；另 10 条最多达到同文件/方法或粗粒度 family 近邻，但不是同一调用点。
3. **E1 下一步应先修 effect coverage 与 E0↔Route A identity/interface contract，而不是先修路径字符串表示。** 本审计不修改冻结 Detector；结论是当前 endpoint identity 尚未达到可比较前提。
4. **当前证据不支持进入 Route B 或增加 propagation semantics。** 437 条路径没有一条建立同一 SecurityEffect 身份；在 effect endpoint 缺失或语义错位时，新增传播机制无法解释或修复该失败。应先使 Route A effect identity 可覆盖、可对齐，再用同一离线审计复核。

STOP：本报告未启动任何后续实验。
