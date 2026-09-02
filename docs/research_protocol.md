# Research protocol

## Authority and status

This repository implements Work 1: project-level discovery of evidence-backed
security Candidate Paths while preserving frozen Native CodeQL results. Its
research target is incremental recovery beyond Native CodeQL, but Work 1 output
may contain native-supported as well as incremental paths; the distinction is
made only against the exact frozen N0 reference. Work 1 does not decide whether
a vulnerability exists. Protection/sanitizer reasoning,
unsafe-context analysis, exploitability, final vulnerability typing, and final
confirmation remain Work 2 responsibilities.

For the M8 agent study, the detailed protocol authority is
`docs/work1-agent-v11-m8/06_EXPERIMENT_DESIGN.md`. As of 2026-09-02 that
document is a draft protocol and M8-5 is still failing; neither development nor
formal evaluation is authorized by the existence of the document alone.

Historical results and protocols remain immutable evidence. When a historical
document conflicts with the M8 design on E0/E1 attribution, conditional
ablation, replication, or formal-arm selection, the M8 design controls future
runs without rewriting the historical result.

## Scope

The conceptual Work 1 pipeline is:

```text
Java project
  -> Native CodeQL and frozen static facts
  -> external-input + security-effect discovery
  -> forward/backward multi-semantic search
  -> evidence-grounded semantic-gap proposal
  -> unchanged Evidence Gate
  -> sparse semantic overlay
  -> bounded Candidate Path
  -> immutable Detector artifacts
  -> independent blinded Evaluator
```

P0 supports M1 data/call semantics, M2 library/wrapper semantics, and M3
field/state semantics. M8 may compare a modern single Agent with a Coordinator
and three bounded specialists, but may not introduce project-specific rules,
expand Route B, lower the M4 Gate, change native M5 path meaning, or allow
unbounded agent collaboration.

Fine-tuning, reinforcement learning, learning-to-rank, broad framework/control
modeling, persistence modeling, and Work 2 vulnerability decisions remain out
of scope unless a later independently frozen protocol explicitly introduces
them.

## Non-leakage contract

The Detector receives only project-side inputs needed to run the frozen method.
Detector code, runtime input, prompts, tools, and observations must not read or
use:

- true CWE or CVE identifiers or descriptions;
- fix patches, fix commits, `fix_info`, vulnerable/fixed/benign labels;
- true vulnerable files, functions, line numbers, root cause, or known method;
- manually annotated sources, sinks, semantic bridges, or sanitizers;
- prior diagnostic proposals or any ground-truth-derived scan scope; or
- evaluator judgments, target matches, reviewer notes, or unblind maps.

The Detector-side manifest may contain pseudonymous, non-semantic subject and
project identifiers, repository revision and source root, CodeQL database
status/identity, frozen Native CodeQL and generic M1--M5 artifact identities,
arm/replicate/schedule identities, budgets, and config hashes. The separate
evaluator manifest owns all
ground truth, lineage mapping, pre-treatment primary/safety analysis-set
membership, primary-subject selection, and revision-role labels. The runtime
scheduler receives only an opaque precomputed schedule and does not own that
mapping. The Detector records only keyed or random-nonce `split_commitment` and
`eligibility_commitment` values; the secret key/nonce and canonical evaluator
manifests remain sealed until Detector completion. These identifiers are
pseudonyms, not an anonymity guarantee: source and revision content may reveal
a public project.

For future formal M8, an independent pre-run curator may use ground truth only
inside a sealed eligibility enclave. Every scheduled Detector run key must reach
a sealed terminal row before the separate scoring Evaluator or reviewers can
open that curator manifest. A verified timeout,
invalid output, budget stop, or pre-read fail-closed denial is sealed as a
failure-inclusive zero rather than omitted. A pending key, unexplained hash
mismatch, or incomplete audit is `BLOCKED_UNVERIFIED` and blocks release. If
forbidden evaluator/oracle bytes may have reached a model, the run is
`INVALID_CONTAMINATED`, is never converted to zero or replacement, and the
detailed M8 protocol determines which confirmatory claim is invalid. The
Detector must not import evaluation or annotation modules. Runtime no-leakage
does not prove absence of project recognition or LLM pretraining memorization;
both remain validity threats.

## Scientific boundary

A Candidate Path means that program facts, structural evidence, and an
Evidence-Gate-admitted local semantic proposal support a bounded path worth
independent investigation. It is not a confirmed vulnerability.

`ADMISSIBLE`, Candidate Path count, Gate admission, CodeQL calls, finding count,
or tool activity cannot substitute for project-level blinded recovery. Final
vulnerability typing still requires evidence equivalent to:

```text
ExternalInput AND Reachability AND SecurityEffect
AND UnsafeContext AND NOT EffectiveProtection
```

Work 1 does not claim the final two terms.

## Development and formal evaluation

Data is split by repository lineage into mutually exclusive `dev-tune`,
one-time `dev-validation`, and new `formal-holdout` cohorts. Vulnerable/fixed
revision pairs, forks, backports, and shared-patch derivatives remain in the
same lineage and split. Any subject used to change prompts, code, schemas,
budgets, or policies is development-only thereafter.

The old M7 ten-case cohort is historical, not a fresh formal holdout. Formal M8
uses pre-registered arms that separate a modern single Agent from the
role-specialized multi-Agent architecture bundle, verifier feedback, and
Coordinator model routing. The formal profile is frozen as either `CORE`
(without G1) or `ROLE` (with a confirmatory generic-worker G1); it cannot be
chosen after outcomes are visible. No-feedback arms execute the same online
verifier at the same proposal points, but a typed observer projection masks its
results from the model. The old M7 result may be reported as H0 provenance
but cannot replace a configured-model-matched modern single-Agent control. If
the provider does not attest an immutable backend revision, the study may not
call the comparison exact-backend matched.

All confirmatory arms are scheduled and frozen before any formal evaluator
outcome is visible. Formal runs use project-level shared resource ceilings,
non-overwriting artifacts, complete usage accounting, failure-inclusive
assigned-arm outcomes, project-blocked random order, pre-registered repeated
runs, and a cohort-level study seal. Timeout, invalid model output, budget
exhaustion, and no candidate are arm failures, not missing negative examples.

The primary Work 1 outcome is project-level incremental candidate recovery on
the first pre-registered repeated run. Before any arm runs, an independent
curator partitions the cohort into `primary_eligible_lineages` and
`safety_only_lineages`. Each primary-eligible lineage contributes exactly one
curator-frozen primary vulnerable project/revision and at least one eligible
target missed by exact Native CodeQL; benign-only, fixed-only, non-eligible, and
additional subjects remain in the pre-registered safety set without creating a
primary row. The sealed target and set membership remain evaluator-only.
Success requires at least one sealed Candidate Path whose own evidence package
is independently reviewed `SUPPORTED` and treatment-blindly matched to the
target. Evidence is never pooled across arms. Additional runs estimate
stability and cannot be selected as best-of. Fixed and additional revisions are
secondary observations clustered by repository lineage.

Protocol states are distinct: `DRAFT`, `DEVELOPMENT_CANDIDATE_FROZEN`,
`FORMAL_FROZEN`, `FORMAL_DETECTOR_SEALED`, `EVALUATOR_RELEASED`, and the
terminal integrity-failure branch `FORMAL_INVALIDATED`.
Development validation requires the candidate freeze; formal execution requires
the later formal freeze. No generic `FROZEN` label authorizes both stages.

Formal Work 1 recovery of zero across all confirmatory arms is a negative result
and does not start Work 2. At least one arm-blinded recovery in any
pre-registered confirmatory arm is required before a separately frozen Work 2
protocol evaluates the sealed, canonical candidates from all arms under the
same treatment-blind rubric. Work 2 results never flow back into the frozen
Work 1 Detector.
