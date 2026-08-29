# Pre-existing Worktree State

Captured before creating the Work1 V11 branch. These changes pre-date the V11 M0 audit and must not be discarded or rewritten as part of V11.

- Repository root: `F:\\ForGithub\\java-vuln-research`
- Source branch: `exp/w1-e1-candidate-path-coverage`
- Source HEAD: `b4c11c3` (`docs(w1-e1): record executable SecurityEffect validation`)
- Upstream: `origin/exp/w1-e1-candidate-path-coverage`
- Status: dirty

```text
## exp/w1-e1-candidate-path-coverage...origin/exp/w1-e1-candidate-path-coverage
 M schemas/candidate_path.schema.json
 M src/java_vuln_research/cli.py
 M src/java_vuln_research/evaluation/__init__.py
 M src/java_vuln_research/evaluation/coverage.py
 M src/java_vuln_research/frontier/candidate_path.py
?? codeql/route_b/
?? docs/experiments/W1_E1_EFFECT_REFACTORED_REPORT.md
?? docs/experiments/W1_P0_A1_NATIVE_POOL_REPORT.md
?? docs/experiments/W1_P0_B_ROUTE_B_REPORT.md
?? src/java_vuln_research/evaluation/route_b.py
?? src/java_vuln_research/native_pool.py
?? src/java_vuln_research/route_b_detector.py
?? tests/unit/test_native_pool.py
?? tests/unit/test_route_b.py
```

The V11 audit will add only files under `docs/work1-agent-v11/` in M0. Existing modified and untracked implementation files remain user-owned and are intentionally excluded from the M0 commit.
