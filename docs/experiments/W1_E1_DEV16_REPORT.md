# W1-E1 Dev16（18 项目）验证扩展报告

## 1. 范围与身份

- 范围：W1-E1；不执行 E1.1、E2、Route B、LLM 候选扩展或最终 CWE 判定。
- 冻结清单：experiments/frozen_configs/w1_e1_dev16_manifest.yaml
- 选择说明：docs/experiments/W1_E1_DEV16_SELECTION.md
- 运行手册：docs/experiments/W1_E1_DEV16_RUNBOOK.md
- 云端分支：exp/w1-e1-candidate-path-coverage
- 冻结基线 HEAD：8996d094ad06123c95024d60b27aee5838a0f8bd
- 首版报告提交 HEAD：85ae87c9217dcb8ec676eff4318bf3fb81ac64e4
- 最终报告提交 HEAD：065a039b03acbe7fbca1241a9962fb876f2d286e
- 规模：18 个项目（Dev8 基线 8 个，新增验证 10 个）。
- 项目状态：18/18 SUCCESS，unknown_count=0。
- 云端环境：CodeQL CLI 2.26.3；Java 17.0.10；按同一 W1 语义重新建库并运行。
- 回归测试：36 passed，PYTEST_EXIT=0。

项目 ID：P006 P007 P010 P012 D001 D002 D003 D004 V001 V004 V005 V007 V021 V022 V023 V025 V009 V011

## 2. 候选、连通与结构前沿

| 指标 | 18 项目合计 |
|---|---:|
| ExternalInput / 输入锚点候选 | 254 |
| FW-active 输入 | 123 |
| FW-empty 输入 | 131 |
| FW active rate | 48.43%（123/254） |
| SecurityEffect / 效果锚点候选 | 59 |
| BW-active 效果 | 14 |
| BW-empty 效果 | 45 |
| BW active rate | 23.73%（14/59） |
| STATIC_CONNECTED | 0 |
| Frontier candidate paths | 0 |
| 结构前沿诊断 | 287 |
| Candidate expansion factor | 0.0 |

结构前沿去重：raw=287，unique frontier node pair=287，unique input/effect pairs=6，unique project/method-region=11。只有 P010 有前沿（1/18），Top-1 share=100%，Top-3 share=100%。效果类型全部为 RENDERING（287）；输入机制为 SERVLET_PARAMETER 185（64.4599%）和 SERVLET_PARAMETER_VALUES 102（35.5401%）。前沿原因：CALL_ADJACENT 222、NEAR_CALL_REGION 29、SAME_METHOD 36。失败分类：DIFFERENT_CALL_REGION 132、EMPTY_FW 131、EMPTY_BW 45、STRUCTURAL_FRONTIER 5。

新增 10 个项目没有产生新的结构前沿；287 个前沿仍全部来自 P010。

## 3. E0 独立评估与覆盖率边界

E0 读取独立 detector 输出后完成：native paths parsed=437，same-file locations=1192，same-method locations=822，exact-line overlap=NOT_EVALUABLE，revision mismatches=4。file-level coverage=0，method-level coverage=0，line-level coverage=NOT_EVALUABLE，E0 coverage=2，W1-E1 coverage=0，baseline-miss recovery=0。Candidate Coverage=NOT_EVALUABLE（没有可评估 candidate path，且 line-level GT 对齐不可用）；Baseline-miss Recovery=0/NOT_RECOVERED。未用 ground truth 调整候选，post-hoc GT overlay=NOT_AVAILABLE。

## 4. BW 归因

59 个效果候选全部 mapped；BW-active=14，BW-inactive=45。主根因 MAPPED_BUT_EMPTY_BW=45，次根因 NO_PREDECESSOR_IN_BASE_DATA_CALL=45。

| effect type | candidates | BW-active | BW-inactive | active rate |
|---|---:|---:|---:|---:|
| DYNAMIC_EVALUATION | 19 | 2 | 17 | 10.53% |
| FILESYSTEM_ACCESS | 19 | 7 | 12 | 36.84% |
| PROCESS_EXECUTION | 19 | 12 | 7 | 63.16% |
| RENDERING | 5 | 3 | 2 | 60.00% |

DYNAMIC_EVALUATION BW active rate=2/19=10.53%；STATIC_CONNECTED=0。

## 5. Dev8、验证集与合并集

“新增验证”列为合并集减去冻结 Dev8，属于预先定义的分层汇总。

| 指标 | Dev8（8） | 新增验证（10，差分） | 合并（18） |
|---|---:|---:|---:|
| Input candidates | 114 | 140 | 254 |
| FW-active | 78 | 45 | 123 |
| FW-empty | 36 | 95 | 131 |
| Effect candidates | 23 | 36 | 59 |
| BW-active | 5 | 9 | 14 |
| BW-empty | 18 | 27 | 45 |
| STATIC_CONNECTED | 0 | 0 | 0 |
| Structural frontiers | 287 | 0 | 287 |

## 6. 科学边界与决定

- scientific_method_changed=NO。
- detector_ground_truth_access=NO；没有用标签、CWE 或人工复核反向修改候选。
- NEXT_RECOMMENDED_EXPERIMENT=PROJECT_CONCENTRATED_EVIDENCE; INSUFFICIENT_EVIDENCE_FOR_E2。
- 结论：当前不启动 E2；下一轮先针对 P010 的 CALL_ADJACENT / DIRECT_DATA_CALL_NEAR_MISS 集中证据和 BW 空失活根因做受控诊断。
- 本报告记录云端可复核结果；未在本机执行实验。

## 7. 云端原始产物

- W1：/workspace/experiment-output/W1-E1-DEV16-20260826-001/
- E0：/workspace/experiment-output/W1-E1-DEV16-E0-20260826-002/
- P0A：/workspace/experiment-output/W1-E1-DEV16-P0A-20260826-001/
- attribution：/workspace/experiment-output/W1-E1-DEV16-ATTRIBUTION-20260826-001/
- metrics：/workspace/experiment-output/W1-E1-DEV16-20260826-001/metrics.json
- project status：/workspace/experiment-output/W1-E1-DEV16-20260826-001/project_status.jsonl
- attribution summary：/workspace/experiment-output/W1-E1-DEV16-ATTRIBUTION-20260826-001/summary.json
- BW root cause：/workspace/experiment-output/W1-E1-DEV16-ATTRIBUTION-20260826-001/bw_inactive_root_cause.json
