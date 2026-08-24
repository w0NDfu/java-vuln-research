# java-vuln-research

Reproducible research framework for project-level Java vulnerability detection
with multi-semantic security analysis.

The current scope is **Work 1** only: project-level vulnerability-path discovery
using multi-semantic security behavior modeling. The first milestone is
`MSA-P0-E0`, a frozen native-CodeQL baseline that proves the complete local,
GitHub, CloudStudio, experiment, and report provenance loop.

## Operating model

- **Local = WRITE**: version-controlled research code is changed only in the
  local Windows workspace.
- **Cloud = RUN**: CloudStudio owns toolchain discovery, CodeQL execution, raw
  outputs, caches, and generated reports.
- **GitHub = SYNC + AUDIT**: source commits and compact run reports provide the
  audit trail; raw datasets, databases, logs, and credentials never enter Git.

See [the research protocol](docs/research_protocol.md) and
[the experiment protocol](docs/experiment_protocol.md) before running an
experiment.

## Cloud entry point

```bash
cp configs/examples/cloud.paths.yaml configs/local/cloud.paths.yaml
# Edit only configs/local/cloud.paths.yaml with paths discovered on the server.
bash scripts/cloud_preflight.sh
bash scripts/run_p0.sh
```

`configs/local/`, raw experiment output, datasets, and CodeQL databases are
ignored. Each run writes a compact report under `reports/runs/<RUN_ID>/` only
after execution.
