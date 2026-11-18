# FastTrack latest repair source

This branch contains the frozen `82533 failure-01` source snapshot, including
range-refusal feedback and request failure settlement/recovery changes.
The original A1 core is preserved byte for byte.

Source identities and hashes are in [SOURCE_VERSION.json](SOURCE_VERSION.json)
and [SOURCE_SHA256SUMS](SOURCE_SHA256SUMS). Publication hashes are in
[PUBLISHED_SHA256SUMS](PUBLISHED_SHA256SUMS).

## Validation

This publication ran scoped offline production-boundary tests on Windows:
**106 passed; 2 failed because Windows does not provide `signal.SIGALRM`.**
Both failures occurred in the Linux production entry point's wall-time guard.
All 185 Python source files parsed successfully. See
[SYNC_VALIDATION.json](SYNC_VALIDATION.json) for the exact scope and limitations.
These are TEST ONLY engineering checks; this sync made no model requests,
performed no detection reruns, and makes no new detection or score claim.

## Running

Use Python 3.10+ in the authorized Linux laboratory environment.
Install dependencies with `python -m pip install -e ".[test,agentic]"`.
The entry point is:

```sh
python -m java_vuln_research.work1_agent.r2_hecv_run --help
```

Actual detection requires matching source, static-analysis receipts, dependency
contracts, history, configuration and declared budgets from the experiment
operator. They are not reconstructed by this source-only publication.
Credentials, benchmark data, databases, request caches, raw requests/responses
and experiment outputs remain outside this branch. In-progress 82534 changes
are not included in this frozen source identity.

## Branches

Historical [a1](https://github.com/w0NDfu/java-vuln-research/tree/a1) and
[r2](https://github.com/w0NDfu/java-vuln-research/tree/r2) are unchanged.
Current repair source is published directly to
[latest](https://github.com/w0NDfu/java-vuln-research/tree/latest).
See [BRANCH_POLICY.md](BRANCH_POLICY.md).
