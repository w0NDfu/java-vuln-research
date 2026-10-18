# vEcho cloud reproduction

For the laboratory server and GitHub branch deployment, use [LAB_SETUP.md](LAB_SETUP.md).
The original cloud paths below describe the earlier environment.

Pinned artifact: `68da10388878f8626f0a1d124e500c979ac1e82d`.
Dataset: `/workspace/dataset`, 120 exact vulnerable commits.

Evaluator dependencies are pinned in `evaluator-constraints.txt` (tree-sitter
0.25.2, tree-sitter-java 0.23.5). Version 0.26.0 crashed reproducibly on the real
pilot report. The runner evaluates in a subprocess so parser crashes are recorded
as failures. `recover_evaluation.py --run <existing run directory>` audits both
completed scanner sessions and accepted judge outputs, then recovers scoring
without repeating model requests; it currently supports the two-stage pilot.

This executes the public artifact. It does **not** claim an exact reproduction of
the paper: this low-cost configuration uses GPT-4.1 mini and text-embedding-3-small,
while the paper uses GPT-4.1 and the public artifact defaults to Kimi-K2.6;
historical SAST inputs and the authors' memory snapshot are absent. Context
concurrency was 1 for samples 1–6. At the user's request, the cloud environment
was changed to 4 for sample 7 onward; verify each run's recorded setting.
One rescan round is used, and the initial knowledge base is empty.
Original knowledge is indexed immediately (`save_tools.use_tmp=false`) so the
automated feedback loop can retrieve it, rather than waiting for web UI approval.

## Setup and execution

1. Fill `/workspace/vEcho/.env` on the server (mode 600). No keys belong in Git,
   terminal commands, screenshots, or chat. Fill **only `OPENLUX_API_KEY`**. The
   helpers pass that key to scan, judge and memory; no second key is required.
   All three stages use `gpt-4.1-mini`, and embedding uses
   `text-embedding-3-small`. The API base is `https://api.openlux.ai/v1`.
   Provider/token group routing determines the actual price; listed minimum
   prices are not a guaranteed billing rate for every token or group.
2. Verify the enabled token with two small live requests (chat tool call and embedding):
   `/workspace/venvs/vecho/bin/python /workspace/vEcho/repro/preflight.py`
   Check `repro/preflight.json`; both checks must pass. HTTP 401 with
   `This token status is unavailable` means the provider token is disabled.
3. Start the original knowledge service and loopback MCP protocol adapter:
   `/workspace/venvs/vecho/bin/python /workspace/vEcho/repro/services.py`
4. Run the first sample:
   `/workspace/venvs/vecho/bin/python /workspace/vEcho/repro/run.py --sample-id 2`
5. Inspect the latest pilot without displaying credentials:
   `/workspace/venvs/vecho/bin/python /workspace/vEcho/repro/progress.py`
6. After reviewing the real first-run cost/results, use `batch.py` for the dataset.
   It skips completed samples, holds a process lock, saves `batch-state.json` and
   `batch-summary.json`, and continues after recording a failure. Existing
   incomplete attempts are deferred; repair/retry happens after the first pass.
   Current authorization is $15; the existing provider token's $8 total quota
   is the lower spending bound. The script does not increase quota or recharge.

Logs, reports, usage files and failures are retained under `repro/runs/`.
Scan/rescan findings sharing the scanner's `metadata.dedup_key` are merged before
evaluation; the source-scanner-specific fingerprint alone is not a cross-stage key.
The runner stops on process and judge failures. The original scanner can close
individual blocks/cases as skipped or blocked when turn/tool budgets are exhausted;
these closures remain in its plan, context results and event log. A completed
process does not imply exhaustive coverage or that every case was resolved.
No fabricated results are substituted for missing credentials or failed requests.

## Input isolation and evaluation

Original dataset sources are not edited. Each scan uses a neutral `sample_NNNN`
source snapshot without `.git`; CVE strings are masked while preserving line
counts. Project/dependency names remain, so this is partial anonymization only.
Ground-truth CSVs and the source-to-CVE mapping stay outside scanner input paths.

`evaluate.py` applies IRIS v1's file/class/method intersection rule to vEcho JSON
paths. Locations are obtained with tree-sitter Java instead of CodeQL, so scores
are marked adapted rather than exact IRIS reproduction. Parse errors are reported.
Method keys omit parameter signatures as in IRIS v1. Unmatched findings have not
been independently proven false. Aggregate FDR/F1 require the same completed
sample set; failed or unrun samples must not silently be treated as negative.

`audit_labels.py` audits all benchmark method labels against the original buggy
snapshots without model calls. Nine project names differ between the supplied
CSVs; `benchmark_labels.py` accepts an alias only when CVE, GitHub owner/repository,
and a listed fix commit all match. Exact-name selection remains unchanged.
Selection provenance is included in new evaluation files. Samples 44, 79 and 80
have no matching labels even under this rule: their workflows can finish, but
their evaluation status is `unavailable_no_labels`, with null scores. New batch
summaries distinguish completed workflows, scored samples and unscorable samples;
missing labels are excluded from metric denominators, never counted as negatives.
Some existing labels reference methods/files absent in the buggy snapshot; those
labels are retained with explicit audit limitations rather than guessed remapping.
See `LABEL_AUDIT.md` and cloud `label-audit.json` for coverage details.

Changes to upstream source: correct the default judge prompt directory, surface
RAG query failures, and do not report a failed knowledge index update as success.
The real MCP protocol is preserved by the separate HTTP adapter on port 5011.
Both the original MCP service and adapter listen only on 127.0.0.1.

After the pilot, sample_0001 exposed judge failures: three of five records did
not call save_result within the ten-turn limit. `patch_judge_budget.py` adapts
the original judge to continue after text-only responses and explicitly request
save_result on the final permitted turn. Unknown is allowed when evidence is
insufficient; the turn budget stays at ten. This is an additional experimental
deviation from the upstream artifact, recorded in new run manifests. Existing
pilot outputs retain their original judge behavior.

`judge_checkpoint.py` reuses saved successful verdicts for identical inputs and
only re-judges missing records. Earlier attempts remain intact. Its checkpoint
manifest records reused fingerprints; usage summaries across attempts must not
be added blindly. Failed upstream attempts do not preserve full transcripts or
usage for their failed records, so provider logs are needed for total cost.
`run.py --sample-id N --resume-run <run directory>` can continue a completed scan
from its judge checkpoint; it rejects incomplete scan sessions. Use it only after
confirming no process owns that run. It does not automatically resume a partial
rescan, and should not be used on one without inspecting its state first.

`batch_successor.py --watch-pid <existing supervisor PID>` can wait for a known
older supervisor to exit before adopting the updated summary implementation. It
checks the process start time to avoid PID reuse, sends no signals, and refuses
to start if any scan/run/batch remains live or the old current sample is not in
the verified completed set. It never retries failed/incomplete model stages.
It also does nothing if the whole dataset is already complete. The new batch
still acquires its own lock before model calls. State/log files are
`batch-successor-state.json` and `logs/batch-successor.log`. Do not launch a second
successor without inspecting the actual existing process and its state.

## Offline completion audit and judge input identities

Run `audit_completed.py` after more workflows finish. It reads completed results,
checks source commit markers and clean original checkouts, validates stage closure,
verdict/input identities and final deduplication, then independently re-scores in
subprocesses. Original reports/manifests/evaluations are hashed and preserved.
`completion-audit.json` distinguishes completed candidates, verified workflows,
pending samples and errors. A zero exit only verifies the completed cohort; it
never proves all 120 workflows finished. Blocked cases remain explicitly counted.

The audit found a legacy collision in sample 1: two distinct flow traces shared
fingerprint 194073598a178eaf, so six judge inputs produced only five per-input
result/transcript files. Summary counts alone had hidden the overwrite. Its
one overwritten input was subsequently rejudged while all batch models were idle.
Five provable results were reused; the new judgment uses the knowledge base after
samples 2–6 and is explicitly a posthoc repair, not the lost historical verdict.
All six completed workflows now pass strict audit. See IDENTITY_REPAIR.md and
cloud `audits/identity-repair/sample_0001-result.json`.

`judge_identity.py` now gives colliding inputs stable separate IDs, preserving the
original fingerprint in metadata and leaving logical dedup keys unchanged. The
save_result tool binds IDs to the current input, independent of a model-supplied
ID. This is a documented adapter change, recorded as distinct input IDs v2 in new
run manifests. Existing running Python processes retain their already imported
version; inspect manifests/checkpoints rather than assuming the latest files ran.

Checkpoint migration only associates legacy saved results with the identifiable
last input for a duplicate ID, and only when the original summary had no failed
calls. Overwritten earlier inputs need new verdicts; no verdict is inferred from
summary totals. Failed ambiguous duplicates are not reused. All original attempt
folders remain unchanged. The current cloud suite contains 34 passing tests.

The evaluator recognizes the observed Maven archetype Java template form under
`src/main/resources/archetype-resources/`: Velocity `##` comments and the
`${package}` package placeholder are normalized in memory while preserving byte
counts and line numbers. It retains all report paths and leaves source files
untouched; remaining syntax errors still fail verification. Normalizations are
listed in evaluation JSON. Sample 6 scoring was recovered this way with no model
rerun and an unchanged final report hash; the original evaluation is backed up.
