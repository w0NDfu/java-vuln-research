# 样本 1 复核编号冲突与补核计划

2026-10-17 22:25 更新：补核已完成，以下计划作为历史依据保留。当前第二轮目录 `rescan-judge/20261017-142054-482239`：六个唯一输入/结果，复用五条并明确迁移，只有 `194073598a178eaf--34ae4f86289a-1` 有新增非空模型轨迹，判定 true，用量 26,695 token。首轮五条全部复用；未重跑扫描。最终六条报告、六条路径、基准召回 0，完整性审计通过。新判定使用样本 2–6 之后的知识库，并非丢失历史结果的重建。原始文件及哈希备份位于 `/workspace/vEcho/repro/audits/repairs/20261017T141956Z`，结果与指标对比见 `/workspace/vEcho/repro/audits/identity-repair/sample_0001-result.json`。恢复时保留并发 1 的原始扫描配置；环境中的并发 4 用于第 7 个及后续新运行。

独立审计发现原复核器按 fingerprint 写文件，样本 1 复扫的两个不同追踪记录共用 `194073598a178eaf`，导致前一条结果与逐条日志被后一条覆盖。两条记录的 dedup_key 相同，但 description、affected_files、tainted_data_flow 和部分 metadata 不同，不能把后一条判定直接当作前一条判定。

原目录：`/workspace/vEcho/repro/runs/20261017T114309Z/sample_0001/rescan-judge/20261017-122532-790459`。
原 summary 表示六条输入、六次结果（true4、unknown2），实际只有五个结果文件。此前仅据运行汇总认定流程完整，不足以证明逐条记录完整。原评分与报告暂存，样本 1 **未通过严格完整性审计**，不能宣称全量实验完成。

已完成的离线核对：重新正常化原始复扫报告后，与原 normalized.json 完全一致。索引 1、2、3、4、5 的独立输入文件与记录一一匹配；只有索引 0 的历史记录被覆盖。没有按 summary 总数推断缺失判定。恢复计划保存在云端 `/workspace/vEcho/repro/audits/identity-repair/sample_0001-plan.json`，本次未调用模型。

新编号：

- 索引 0：`194073598a178eaf--34ae4f86289a-1`，待补核。
- 索引 1：`194073598a178eaf--85477306be80-1`，可以明确关联原最后保存的输入/结果。
- 其余四个唯一指纹保持不变。

已部署修复：碰撞输入以完整正常化内容哈希与出现次序取得不同编号；保留原 fingerprint 和 dedup_key。工具端绑定当前记录编号，防止模型提交别的编号。检查点迁移只复用有明确输入归属的原结果；旧尝试有失败时，不复用存在歧义的重复记录。新启动运行在 manifest 中标记 distinct input IDs v2。

恢复应在当前批次停稳或全部结束、且无其他模型阶段运行时进行，避免额外知识写入改变正在进行的复扫环境。不要为了补核重跑源码扫描。

恢复步骤：

1. 核对真实进程、batch_successor 状态和原样本的 completed scan/rescan session。确认没有运行器拥有样本 1。
2. 在样本目录创建带时间戳的备份目录，复制并记录原 run.json、final-report.json、evaluation.json 的 SHA-256；原各次 judge 目录保持原样。
3. 使用已部署的 v2 `run.py --sample-id 1 --resume-run /workspace/vEcho/repro/runs/20261017T114309Z/sample_0001`。首轮复核应复用五条原结果，重扫应复用已完成 session；第二轮应迁移五条明确归属的结果，仅补一条新复核。不要在仍有其他模型任务运行时启动。
4. 核对 checkpoint.json 的 reused_fingerprints、identity_migrations、新保存的六个唯一结果文件、memory_errors 和 failures。补核是当前知识库下的新判定，不等于恢复被覆盖的历史逐条日志；应明确记录这一适配。
5. 保存补核与原报告的差异、实际新增模型调用和备份哈希，重新运行 audit_completed.py。只有重新审计通过才能把样本 1 列为验证通过。

验证：31 项云端测试全部通过，包括重复输入唯一编号、确定性、原记录不变、只迁移最后可识别记录、存在失败时不错误复用，以及模型传错编号时仍绑定当前记录的检查。
