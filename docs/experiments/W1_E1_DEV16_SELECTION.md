# W1-E1 Dev16 Selection Freeze

- branch: `exp/w1-e1-candidate-path-coverage`
- selection_frozen: true
- detector_started: false
- freeze_scope: W1-E1 validation cohort only; no detector, evaluator, attribution, or ground-truth result was used for selection.
- selection_signals: repository identity, pinned revision, Java/build metadata, CodeQL database availability, and CWE category only for diversity.
- final_total_projects: 18
- dev8_baseline_projects: P006, P007, P010, P012, D001, D002, D003, D004
- successful_validation_projects: V001, V004, V005, V007, V009, V011, V021, V022, V023, V025

## Final validation cohort

| ID | Repository/tag | Revision | CWE category | CodeQL status |
|---|---|---|---|---|
| V001 | square/retrofit @ 7158698 | 7158698314daa138e993fac6a590ed19d78a8599 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V004 | codehaus-plexus/plexus-archiver @ b9f9a42 | b9f9a425865eb47fb3665b3144ee4ca11f402704 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V005 | iris-sast/zip4j @ d87ffa2 | d87ffa2d64ffb3a0a1cf0c7a69c7b19d7015bfde | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V007 | jstachio/jstachio @ 9ce2000 | 9ce20009d6bf726086fc528fceb174933077bff4 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V009 | apache/commons-io @ 2ae025f | 2ae025fe5c4a7d2046c53072b0898e37a079fe62 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V011 | OWASP/json-sanitizer @ fc612ab | fc612ab374de73d03864d56fb87b6a103b234489 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V021 | whitesource/CureKit @ v1.1.3 | 7b275a67a5992165deb186b2b3f7764ddd62d26 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V022 | ESAPI/esapi-java-legacy @ 2.2.3.1 | 2e8694c6beb3bbdb2645b882eba72ce41bc63242 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V023 | vert-x3/vertx-web @ 3.9.3 | 2146b7240096e25b40bb1acc083fa7ec79330989 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |
| V025 | apache/shiro @ shiro-root-1.11.0 | adb56c88521e0eeca710b2df17f6b3aeda85e4f35 | CWE-022 | DB_EXIT=0, RESOLVE_EXIT=0 |

## Excluded predeclared candidates

All exclusions use only an allowed operational reason.

- V002 dromara/hutool: `BUILD_FAILURE` (Beetl/Enjoy artifacts unavailable)
- V003 apache/tika: `BUILD_FAILURE` (Apache CXF 3.0.16 artifacts unavailable)
- V006 rhuss/jolokia: `BUILD_FAILURE`
- V008 apache/struts: `BUILD_FAILURE`
- V010 apache/commons-text: `BUILD_FAILURE`
- V012 jenkinsci/docker-commons-plugin: `BUILD_FAILURE`
- V013 codecentric/spring-boot-admin: `BUILD_FAILURE`
- V014 cbeust/testng: `BUILD_FAILURE`
- V015 apache/jspwiki: `BUILD_FAILURE`
- V016 kubernetes-client/java: `BUILD_FAILURE` (CodeQL tracer process exit 137)
- V017 undertow-io/undertow: `BUILD_FAILURE` (unavailable checkstyle artifact)
- V018 apache/karaf: `BUILD_FAILURE` (dependency resolution)
- V019 apache/james-project: `BUILD_FAILURE`
- V020 jlangch/venice: `BUILD_FAILURE` (no root Maven POM)
- V024 apache/mina-sshd: `BUILD_FAILURE` (import-maven-plugin execution failure)

No vulnerability file, method, line, fix, CVE description, ground-truth label, or path was used to select or exclude a project.
