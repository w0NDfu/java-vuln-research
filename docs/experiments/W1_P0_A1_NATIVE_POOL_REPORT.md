# W1 P0-A1 Baseline-Preserving Native Pool Validation

## 结论

P0-A1 在 CloudStudio 云端完成。现有 E0 SARIF 被逐条解析并适配为 `CandidatePath`，随后写入统一候选池；没有重跑 CodeQL，也没有访问 detector ground truth。适配器未丢失路径，且 native path identity 在 evaluator 中 100% 保持。

- **E1 是否仍有基础实现问题：否（本次验证范围内）**。NativePathAdapter、CandidatePath union 字段、稳定 ID、统一池和 preservation evaluator 均通过云端测试与运行时不变量。
- **是否支持下一步转 Route B：是**。基础路径保真已建立，下一步可做 `P0-B ROUTE_B_STATIC_AUGMENTATION`；本报告不启动该实验。
- **是否支持 Wrapper/Library 或 Field/State：否**。本实验只证明 CODEQL_NATIVE 的保真适配，没有产生跨组件、wrapper/library 或 field/state 证据。

## 运行与版本

- 分支：`exp/w1-baseline-preserving-native-pool`
- 验证时源代码 HEAD：`406fb26`（`w1: add baseline-preserving native path adapter`）
- 项目集：frozen 18 项目 manifest `experiments/frozen_configs/w1_e1_dev16_manifest.yaml`
- E0 输入：`/workspace/experiment-output/W1-E1-DEV16-E0-20260826-002`
- P0-A1 输出：`/workspace/experiment-output/artifacts/work1/p0_a1_native_pool/W1-P0-A1-NATIVE-POOL-20260827-001`
- CodeQL 重跑：否；复用既有 E0 SARIF
- `detector_ground_truth_access`：`false`
- `scientific_method_changed`：`NO`

## 数量与不变量

| 指标 | 结果 |
|---|---:|
| 项目数（成功/总数） | 18 / 18 |
| E0 native paths 解析数 | 437 |
| NativePathAdapter 输出数 | 437 |
| 适配失败数 | 0 |
| 统一 candidate pool 数 | 437 |
| `path_origin=CODEQL_NATIVE` | 437 |
| 重复 `native_path_id` | 0 |
| 重复 `candidate_id` | 0 |
| parsed native = adapted native | 是 |
| preservation loss | 0 |
| preservation rate | 1.0（100%） |

`adapter_status.jsonl` 为 18 行项目级状态，`coverage_cases.jsonl` 为 437 行路径级 join 结果。所有 E0 native path 均能在 unified pool 通过 `native_path_id` 找到对应候选。

## 离线 preservation evaluator

Evaluator 重新使用同一 E0 SARIF path-level parser 生成期望 native IDs，再与 unified pool 做 ID join，不读取 GT 标签，也不反向修改 detector：

- E0 evaluable / covered：437 / 437（1.0）
- Native pool evaluable / covered：437 / 437（1.0）
- `baseline_paths_parsed`：437
- `native_candidates_adapted`：437
- `baseline_preservation_loss_count`：0
- `baseline_preservation_rate`：1.0

因此本实验只证明“统一池不会破坏 E0 路径”；由于没有加入 STATIC_AUGMENTED 路径，不能把 437/437 解读为新增漏洞覆盖率提升。

## 代码与测试

新增 `NativePathAdapter + Unified Candidate Pool`，扩展 CandidatePath 的 `path_origin`、native provenance、anchors、path locations 和 augmentation 预留字段，并保持 schema v2 兼容。云端完整测试结果：**49 passed, 1 skipped**。

关键产物：

- `native_candidate_paths.jsonl`
- `unified_candidate_pool.jsonl`
- `adapter_status.jsonl`
- `baseline_preservation.json`
- `coverage_metrics.json`
- `coverage_cases.jsonl`
- `run_manifest.json`
- `summary.json`
- `summary.md`

## 下一步

建议下一实验：`P0-B ROUTE_B_STATIC_AUGMENTATION`。应继续保持 detector、E0 SARIF、GT 边界和 native path identity 冻结；Wrapper/Library、Field/State 只有在后续实验产生对应静态证据后再评估。
