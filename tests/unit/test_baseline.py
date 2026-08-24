from __future__ import annotations

import json

from java_vuln_research.baseline import summarize_sarif


def test_summarize_sarif_counts_alerts_and_code_flows(tmp_path) -> None:
    sarif = {
        "runs": [
            {
                "results": [
                    {"ruleId": "one", "codeFlows": [{"threadFlows": []}]},
                    {
                        "ruleId": "two",
                        "codeFlows": [
                            {"threadFlows": []},
                            {"threadFlows": []},
                        ],
                    },
                    {"ruleId": "three"},
                ]
            }
        ]
    }
    path = tmp_path / "result.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")

    assert summarize_sarif(path) == (3, 3)

