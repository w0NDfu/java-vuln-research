# W1-E1 Dev16 验证集选择审计

## 冻结信息

- 分支：exp/w1-e1-candidate-path-coverage
- 选择冻结时间：2026-08-26（云端 CloudStudio）
- 清单：experiments/frozen_configs/w1_e1_dev16_manifest.yaml
- 目标规模：16 个项目；Dev8 的 8 个项目保持不变，新增验证 8 个项目。
- 选择信号：仓库身份、固定 revision、Java/JDK 与构建元数据、Maven/Gradle 元数据、框架/库身份，以及 CWE 类别仅用于类别多样性。
- 明确未使用：漏洞文件、漏洞方法/行、修复提交内容、GT 标签、CVE 描述或漏洞路径。

## 选择规则

1. 先排除 Dev8 已覆盖的同一仓库（允许同仓库不同版本的情况不作为新增仓库，以避免项目身份重复）。
2. 在 cwe-bench-java/data/project_info.csv 与 build_info.csv 的公开元数据池中，优先选择 build_info.status=success、可在云端 JDK/Maven 环境复现、且具有独立仓库身份的项目。
3. 新增集合覆盖 CWE-022、CWE-079、CWE-094 三类，优先小型或中型 Maven 工程，降低构建资源偏差。
4. 在 CodeQL 数据库可解析、revision 校验通过后，才允许进入最终运行清单；这些是工程可用性门槛，不是结果驱动替换。

## 已冻结项目

| ID | 仓库 | revision | Java/构建元数据 | CWE 类别 |
|---|---|---|---|---|
| V001 | square/retrofit | 7158698314daa138e993fac6a590ed19d78a8599 | JDK8u202 / Maven 3.5.0 | CWE-022 |
| V002 | dromara/hutool | 7687720c5125b29386d3bb9c7c2931da79664b73 | JDK8u202 / Maven 3.5.0 | CWE-022 |
| V003 | apache/tika | 38ff2a986af24ee255f1f91d654ea402f4016696 | JDK8u202 / Maven 3.5.0 | CWE-022 |
| V004 | codehaus-plexus/plexus-archiver | b9f9a425865eb47fb3665b3144ee4ca11f402704 | JDK8u202 / Maven 3.5.0 | CWE-022 |
| V005 | iris-sast/zip4j | d87ffa2d64ffb3a0a1cf0c7a69c7b19d7015bfde | JDK8u202 / Maven 3.5.0 | CWE-022 |
| V006 | rhuss/jolokia | 10727cab59a8fc2ae053bec6b2f26f48f1c4245c | JDK8u202 / Maven 3.5.0 | CWE-079 |
| V007 | jstachio/jstachio | 9ce20009d6bf726086fc528fceb174933077bff4 | JDK17 / Maven 3.5.0 | CWE-079 |
| V008 | apache/struts | b3a9d82d5830ef9cd7811cfa3f86a373ae52fada | JDK8u202 / Maven 3.5.0 | CWE-094 |

## 既有 Dev8（不变）

Dev8 的 P006/P007/P010/P012 与 D001–D004 逐字复用 w1_e1_dev8_manifest.yaml，不重新选择、不改 revision、不改数据库。

## 预声明替换与排除政策

- 只有在运行前的工程审计阶段发现 DB_NOT_AVAILABLE、BUILD_FAILURE、DUPLICATE_REPOSITORY、UNSUPPORTED_BUILD、VERSION_MISMATCH 或 SCOPE_LIMIT 时才可替换；替换必须来自同一预审计元数据池，并在本文件和 manifest 中留下时间戳、原项目、原因和替代项目。
- 运行开始后禁止任何替换，禁止结果驱动的项目增删。
- 不因候选输入数、FW/BW 数量、frontier 数量或覆盖率改变集合。
- 未进入清单的候选只记录上述六类排除原因，不记录漏洞标签或位置。

## 方法与隔离声明

Dev16 仅扩展项目覆盖面，不改变 W1-E1 的 Candidate→AnalysisAnchor、FW/BW Base Data/Call、STATIC_CONNECTED、STRUCTURAL_FRONTIER、既有归因和独立 evaluator 语义。检测运行的 manifest 不包含漏洞位置或 GT 字段。
