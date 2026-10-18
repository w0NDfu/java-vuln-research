# Cloud reproduction continuation

Cloud workspace: <https://cloudstudio.net/a/39057944878366720/edit>.
Helpers: `/workspace/vEcho/repro`; Python: `/workspace/venvs/vecho/bin/python`.
Use Chrome UI terminal. Never print `.env` or credentials. Services use loopback
ports 5010 and 5011. Inspect actual processes before starting anything.

The user authorized **$15 total API spending** for all 120 samples. OpenLux's
existing `gpt4` token remains enabled with an $8 total provider quota and roughly
$7 remaining, verified in the UI. The agent did not increase quota or recharge.

## Completed pilot

`runs/20261017T104917Z/sample_0002` is complete. See `PILOT_RESULT.md`.
Ten deduplicated reports, zero benchmark method hits. Evaluation was recovered
without repeating model calls after pinning tree-sitter 0.25.2 and Java 0.23.5.
Original tree-sitter 0.26.0 reproducibly crashed. `recovery-audit.json` retains
integrity evidence. Evaluation now runs in a subprocess.

## Current run, last observed 2026-10-17T12:27:04Z

`runs/20261017T114309Z/sample_0001` is running under PID 308114. Original batch
stopped when its first judge failed to save three of five results. First scan
was **not repeated**. Original attempt and successful verdicts remain preserved.

Documented judge adapter continues after text-only replies and requires
`save_result` on turn ten within the original ten-turn budget. Evidence may
remain unknown. `judge_checkpoint.py` reuses saved successful results only when
normalized inputs match. Reused usage must not be summed across attempts.
Failed original attempts lack usage/transcripts; provider billing is needed for
total costs. All **13 cloud offline tests passed** after the change.

Recovered first judge: `judge/20261017-120655-450953`, five results (three true,
two unknown), no failures. Checkpoint proves two earlier successes were reused.
Rescan session `20261017T120827Z` completed at 12:25:32Z: eight blocks, 35 seeds,
35 cases; six confirmed, six rejected, sixteen blocked, seven dead ends, ten tool
errors. Rescan judge saved three of six results at last check. Final evaluation
is absent; do not count sample 1 complete yet.

The existing resume shell automatically launches `batch.py` only after success
of sample 1. Log: `repro/logs/resume-sample-0001.log`. Batch skips completed samples
and stops on first failure. Old batch-state.json remains stale until the resume
finishes. Do not launch duplicate work. `run.py --resume-run` refuses to overwrite
incomplete scanner sessions; those require scanner session recovery.

## Next checks

```sh
pgrep -af '^/workspace/venvs/vecho/bin/python.*repro/(batch|run).py|^/workspace/vEcho/repro/bin/vecho-scan'
/workspace/venvs/vecho/bin/python /workspace/vEcho/repro/progress.py
tail -n 20 /workspace/vEcho/repro/logs/resume-sample-0001.log
```

After sample 1 finishes audit final judge failures/memory errors, report and
score, then confirm automatic continuation to sample 3. Partial cohort metrics
are in batch-summary.json. Failed/unrun samples are excluded. Configuration
groups distinguish the unmodified pilot from adapted judges. Full 120-sample
reproduction is still incomplete.

## Reproduction boundaries

GPT-4.1 mini for scanning/judging/memory, text-embedding-3-small embeddings.
Initial knowledge base empty, context concurrency one, one feedback rescan.
Inputs omit Git history and mask CVE strings but retain project/dependency names.
Evaluation applies IRIS v1 method-intersection using tree-sitter Java rather
than original CodeQL. Unmatched reports are not established false positives.
These deviations must accompany final results; do not claim exact paper replication.

Update 2026-10-17T12:29Z: sample 1 completed. Final rescan judge 20261017-122532-790459 saved six results (true4 unknown2), no failures or memory errors. Final dedup six reports, zero benchmark hits, no parse errors. Batch PID308109 automatically started sample3 under PID384771 at runs/20261017T122748Z/sample_0003. Completed cohort2/120,16paths,zero benchmark hits. See BATCH_PROGRESS.md. Do not restart the completed sample1 or the live batch.

Cloud runtime update: user explicitly authorized extending the current shutdown timer to 24 hours. Applied and verified in Cloud Studio: tomorrow 20:32 (2026-10-18, Asia/Shanghai), approximately 24 hours remaining. Screenshot evidence/shutdown-extended-24h.png. This consumes cloud machine time separately from the USD15 model API cap. Disk /workspace has about245GiB free; dataset7.8GiB, runs20MiB, prepared targets30MiB at last check.

Label audit update: audit_labels.py ran on all120 snapshots. benchmark_labels.py resolves9 slug aliases only with CVE+repository+listed fix commit. 680unique non-test targets,652mapped,13missing methods,13missing files,2missing classes,no parse errors. Samples44,79,80 lack labels; evaluate.py now writes unavailable_no_labels with null metrics, new batch.py distinguishes scored vs completed and excludes unscorable denominators. All17 cloud tests passed; re-evaluation of completed1and2 preserved every original serialized field. See LABEL_AUDIT.md. The currently live batch PID308109 imported the PREVIOUS summary function before this change; do not interrupt live scans just to reload it. If it later stops while summarizing a null-score sample, verify that run complete and restart the NEW batch.py to skip completed workflows, without rerunning models. Current scans use evaluate.py as a fresh subprocess and will pick up the label selector. No original CSV or input source was modified.

Latest verified ~2026-10-17T12:49Z: sample3 completed, scan session completed31/31 cases (blocked23,dead_end7,rejected1), zero confirmed reports. Judge/rescan not applicable, evaluation available recall0, paths0, no parse errors. Scan usage1203371 tokens (1114903in,88468out). Completed3/120; total16paths,zero benchmark hits. Sample4 is live at runs/20261017T124705Z/sample_0004, runnerPID456809,scannerPID457446,batchPID308109. Preserve original outputs. New helper summary audited to batch-summary-audit.json; live supervisor remains older code as noted above. Evidence batch-three-completed.png.

Latest 2026-10-17T12:57:48Z: sample4 initial scan completed21/21 (dead_end9,blocked10,confirmed2), first judge judge/20261017-125645-446590 true2 failures0. Rescan livePID494577, runner456809,batch308109; do not repeat initial scan/judge. Safe batch_successor.py watcherPID483192 is deployed and verified waiting for batch308109 start_ticks3402745289, updates state every30sec. It sends no signals, refuses any active work and refuses failed/incomplete current samples; if old supervisor later crashes on null scoring after a COMPLETED sample, it will exec the updated batch. Inspect batch-successor-state.json and logs/batch-successor.log before any manual batch restart. All21 cloud offline tests passed in8.962sec. Total complete remains3/120,zero benchmark hits; no score for sample4 yet. Token quota remains8USD as verified in UI, below authorized15. No quota/recharge changes. Log UI filters were inspected but no full-experiment total was verified; do not infer total from the partial two-hour window.

IMPORTANT ~2026-10-17T13:40Z: audit_completed.py added and run. Completed workflows4/120, strict verified3 (2,3,4), error sample1 rescan-judge missing records. Actual legacy duplicate fp194073598a178eaf corresponds to two DIFFERENT input traces at indexes0and1 with same dedup_key. Writer overwrote index0 result/transcripts with index1. Original summary6 outputs,true4unknown2 had masked loss. Do NOT relax audit or infer missing verdict from summary. judge_identity.py + judge_checkpoint.py now v2 unique IDs and conservative legacy migration; patch_judge_budget.py binds tool save_result ID to current input. run.py new manifests record distinct input IDs v2. All31 cloud tests passed9.636sec. New helpers deployed after sample5 parent had already loaded old code; sample6 onward should usev2, verify actual manifest. No model repair launched yet. Offline repair plan audits/identity-repair/sample_0001-plan.json proves reuse indexes1..5, only index0 missing, newIDs listed in IDENTITY_REPAIR.md. Keep model repair until batch stops/all models idle to avoid concurrent KB changes. BEFORE resume1 back up original run/final-report/evaluation with hashes; runresume reuses completed scans, firstjudge5 successes, secondjudge5 provable results and calls model for1 missing input only. Original judge folders untouched. Follow IDENTITY_REPAIR.md and rerun strict audit, do not claim1verified now. Strict auditor original scores preserved, reports/errors in completion-audit.json. Sample4 completed with5reports5paths recall0, no parse errors, strict auditpassed. Current5 at runs/20261017T131019Z/sample_0005 runner542551; scan15closed (dead_end7 blocked6 rejected1 confirmed1), firstjudge done, rescan32/36 asof13:38:59 (blocked22 confirmed4 dead_end5 rejected1). Process581732 was rescan but may since have finished; inspect live process/log first. Batch308109 +successor483192 remain. Never rerun completed model scans for audit failure.

Update 2026-10-17T13:49Z: user requested parallel execution because the run was slow. Set cloud .env VECHO_CONTEXT_CONCURRENCY=4 using dotenv.set_key, kept mode600 and all credentials private. Verified fresh common.load_env process reads4; /proc/308109/environ has no inherited override. Current sample6 was already launched with1 and remains untouched; sample7 onward should run4, VERIFY actual run manifest/process flags on next transition. This is case-level tracking concurrency, not four projects or judge concurrency. No duplicate work/restart. Current sample6 scan8/22, last event13:48:52Z. Current logs no rate-limit signal, but concurrency4 has not actually run yet; do not promise4x speed. API authorization15USD unchanged, provider quota8USD unchanged. Completed workflows5/120; strict verified4 (2,3,4,5), all zero benchmark hits; sample1 missing legacy overwritten judgment still pending posthoc repair after batch models idle. Sample4 final5reports5paths, sample5 final3reports3paths; sample6 at runs/20261017T134221Z/sample_0006 uses distinct input IDs v2. Batch308109, successor483192, run659073, scanner660028. See BATCH_PROGRESS.md latest status above historical notes. Do not mark full reproduction complete. Parallel setting evidence evidence/concurrency-four-configured.png.

Verified wait 2026-10-17T13:54Z: previous turn made progress by changing authoritative cloud concurrency setting to4. This turn confirmed live batch308109, successor483192, runner659073 and scanner660028 (ps all present, non-zombie). Current sample6 advanced scan12/22 ->17/22 ->21/22; latest cases dead_end6 blocked11 confirmed3 rejected1, last event13:53:57Z. No judge summary yet. Keep waiting on this same runner; no restart. Cloud README updated and confirmed containing sample7 onward concurrency4 note. Actual sample7 parallel execution remains unverified until transition. Evidence evidence/sample-six-progress.png. Full scope120, workflowscomplete5/120, strict4 with sample1 repairpending as previously documented. No new model calls manually launched.

Verified wait 2026-10-17T13:57Z: sample6 initial scanner660028 terminated successfully; session completed, scan_completed at13:54:06Z,22/22cases (dead_end7 blocked11 confirmed3 rejected1). First judge attempt judge/20261017-135406-457246 normalized3/results3/guidance3 true3 failures[], usage31379in+2883out=34262. Runner659073 remains live, automatic feedback RESCAN scanner705395 live (live_work independently inspects /proc), batch308109 live. Rescan latest tool_call13:56:52Z, still planning before cases. Current sample6 remains concurrency1; preserve all stages, don't restart. Completedworkflowcount still5, strict4; sample7 actual concurrency4 not yet verified. Evidence evidence/sample-six-rescan.png. Previous goal turn was verified wait with live process and advancing events. No blocker and no completion claim.

MAJOR UPDATE 2026-10-17T14:25Z: sample6 scans/judges completed, but old batch stopped because evaluator flagged archetype Java template parse error. Old batch308109 and successor483192 BOTH TERMINAL (live_work empty); successor finished_without_restart, correctly refused invalid scoring. Source6 is apache__camel_CVE-2018-8041_2.20.3; commit match/clean verified, original and prepared25158files, real GenericFileProducer path camel-core/... and ZipIterator components/camel-zipfile/... exist. Model fabricated candidate paths;13 rescan rejects are missing seed files; preserve evidence, do not rewrite candidates. Scan22=dead7blocked11confirmed3rejected1;10blocked hit originalturnbudget,1missingverifiedchain. Rescan35=confirmed7rejected13blocked14dead1, completed14:07:09Z.
Evaluator repaired narrowly: template_source only src/main/resources/archetype-resources with package ${package}; blank ## comments and replace package placeholder in memory with same byte count; line preserving, source untouched, flows retained, unknown syntax still errors. source_normalizations metadata recorded. All34cloudtests passed8.854sec. Deployed evaluate.py,test_java_template.py,run.py (resume preserves oldconcurrency),recover_evaluation.py (generic recoverymessage). Backup BOTH sample1/6 run,final-report,evaluation + hashes at audits/repairs/20261017T141956Z BEFORE alterations. recover_evaluation sample6 succeeded twice identicalscore, zeroerrors,8reports8paths recall0; finalreporthash preserved 47abb322e770c29addc2ee49749075c0c970529ee5fd1c92603f7a25d234369e.
With all models idle, resumed sample1 PID800485 completed. New secondjudge rescan-judge/20261017-142054-482239, firstjudge5 reused, secondjudge5 provable legacy migrations reused, only missingindex0 new nonempty transcript194073598a178eaf--34ae4f86289a-1 (18lines); remaining transcriptfiles empty reusedmarkers. New verdicttrue, usage25628in+1067out=26695 excludingmemory. Summary6unique results,true4unknown2,no failures; final6reports6paths recall0. New verdict POSTHOC at KBstate aftersamples2-6, not historical reconstruction. Audit/provenance saved audits/identity-repair/sample_0001-result.json; runmanifest posthoc_identity_repair field added, scanconcurrency retained1. Full audit_completed rerun:6candidates6verified,errors[], all_workflows_verifiedfalse (scope120stillpending).
Started NEW updated batch PID811696 log logs/batch-after-repairs.log (flock guarded). Actual sample7 at runs/20261017T142354Z/sample_0007 runner811722 scanner812052. Manifestconcurrency4 AND actualscanner --context-concurrency4 verified; cases not startedyet, latestblock_started14:24:39Z. Oldsupervisor/watcher NOT active and mustnotrestart. Newbatch supports missinglabelnullsummaries; no successor needed now. Keep no duplicatework. Evidence sample-seven-concurrency-four.png. Next verify contextaudit_started concurrency4/actualoverlap andlimits, waiton sample7. Audit already passed all6; don't repeat tests/audit without newfailure/completion/change. Budget15authorized unchanged; providertoken8 unchanged, shutdowntimer10/18 20:32. Current globalgoal active incomplete120.

Latest 2026-10-17T14:30Z: actual sample7 contextaudit_started data case_count26, concurrency4; event-derived peak open case count4, scan21/26 at last proof (after7/7blocks completed). No rate-limit signals found in event errors at preceding check. All new batch/run/scanner pids811696/811722/812052 verified live. evidence/sample-seven-concurrency-four.png now proves actual overlapping4 cases, not just flags. Six completed workflows remain strict-audited6, errors[]. Updated docs uploaded to cloud (README, BATCH_PROGRESS, IDENTITY_REPAIR, CONTINUATION) before this final observation. Full120 still incomplete; next wait same live sample7, then audit new completion. No models should be rerun for diagnostics. Batch uses newly fixed code; oldwatcher is terminal.

USER POLICY OVERRIDE 2026-10-17: user explicitly said first run all120, defer remaining fixes until the end, then asked start. Do not stop healthy queue for audits, optional repairs or documentation. CUA runtime reset; re-bound Chrome4 cloudtab276595660. Cloud UI now2cores4GiB with fresh terminal/workspace; prior4core8G/timer status is NOT currently verified. Actual live_work() empty while oldrun7/batchstate saidrunning; all oldprocesses gone. Preserved incomplete sample7 at runs/20261017T142354Z/sample_0007 for later recovery, NO rescan rerun now.
Restored original memory services from existing config.yaml WITHOUT reconfiguration/key/password changes or KB clearing: memory17677,bridge17678; MCP list_tools confirmed required4tools, MEMORY_READYtrue. Updated batch.py FIRST PASS policy: completedskip; any existing incomplete/unscored attempt defer(skip,retain evidence); new sample failure append failed_samples/failure_details and continue next; statusfirst_pass_complete/needs_repair when allattempted withpending, never claims fullsuccess. Same batch.lock guards duplicates. New test_first_pass.py verifies completed1/oldinterrupted2 skip, failure3 doesnotprevent4, filesunchanged, attemptedcount4/completed2/needsrepairtrue. LocalWindows lacksfcntl (notcloudfailure); cloudLinux targetedtest PASSED0.008s (ResourceWarning oldlock unclosed, nonblocking, no needfixnow). No broadtests/audits repeated.
Started firstpass batchPID28432 logs/batch-first-pass.log; actual sample8 runPID28455 scanner28823 at runs/20261017T144039Z/sample_0008, manifestconcurrency4 confirmed, liveprocesses independentlyverified. Statepolicy Attempt every sample once before repairing or retrying failures, deferredsample0007, completed6/120. Screenshot evidence/first-pass-started.png. Budgetsame15API, tokenquota unchanged8, no recharge. Next only monitor existing healthy batch/progress; defer sample7 and any newsampleerrors until ALL120attempted, then repair/recover. Do not follow old instructions to stop queue for newly identified nonblocking audit issues. Keep fullgoalactive untilallrequiredworkdone.
