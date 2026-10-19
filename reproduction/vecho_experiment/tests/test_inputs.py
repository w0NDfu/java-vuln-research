import copy
import unittest
from reproduction.vecho_experiment import inputs
from .support import finding


class InputsTests(unittest.TestCase):
    def sarif(self):
        loc = lambda line: {"physicalLocation": {"artifactLocation": {"uri": "A.java", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": line}}}
        return {"version": "2.1.0", "runs": [{"originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///home/src/"}},
                 "results": [{"ruleId": "java/path-injection", "message": {"text": "candidate"}, "locations": [loc(3)],
                 "codeFlows": [{"threadFlows": [{"locations": [{"location": loc(1)}, {"location": loc(3)}]},
                                               {"locations": [{"location": loc(2)}, {"location": loc(3)}]}]}]}]}]}

    def test_sarif_retains_alternative_paths_and_base_uri(self):
        r = inputs.sarif(self.sarif(), "CodeQL", "/home/src")[0]
        self.assertEqual(len(r["tainted_data_flow"]), 2)
        self.assertEqual(r["tainted_data_flow"][1][0]["line_number"], 2)
        self.assertEqual(r["affected_files"][0]["file_path"], "A.java")

    def test_sarif_indexed_artifacts_and_thread_locations(self):
        p = self.sarif(); run = p["runs"][0]
        loc = run["results"][0]["locations"][0]
        run["artifacts"] = [{"location": loc["physicalLocation"]["artifactLocation"]}]
        loc["physicalLocation"]["artifactLocation"] = {"index": 0}
        run["threadFlowLocations"] = [{"location": copy.deepcopy(loc)}]
        run["results"][0]["codeFlows"] = [{"threadFlows": [{"locations": [{"index": 0}]}]}]
        r = inputs.sarif(p, "CodeQL", "/home/src")[0]
        self.assertEqual(r["tainted_data_flow"][0][0]["line_number"], 3)

    def test_paths_reject_escape_unmapped_absolute_remote(self):
        for path in ["../x", "%2e%2e/x", "/other/x", "C:/other/x", "file://remote/x"]:
            with self.subTest(path=path), self.assertRaises(ValueError): inputs.relative_path(path, "/home/src")
        self.assertEqual(inputs.relative_path("file:///C:/src/A.java", "C:/src"), "A.java")

    def test_no_path_is_not_fabricated(self):
        p = self.sarif(); del p["runs"][0]["results"][0]["codeFlows"]
        r = inputs.sarif(p, "CodeQL", "/home/src")[0]
        self.assertEqual(r["tainted_data_flow"], [])
        self.assertEqual(r["metadata"]["path_evidence"], "location_only")

    def test_dedup_identical_paths_keeps_origins_and_alternative_claims(self):
        a, b = finding(), finding(tool="Coverity")
        rows, excluded = inputs.merge_records([a, b])
        self.assertEqual(len(rows), 1); self.assertEqual(len(rows[0]["metadata"]["origins"]), 2)
        self.assertEqual(excluded, [])
        unrelated = finding(rule="unrelated")
        self.assertEqual(len(inputs.merge_records([a, unrelated])[0]), 2)
        b["tainted_data_flow"][0].insert(0, {"file_path": "A.java", "line_number": 1})
        self.assertEqual(len(inputs.merge_records([a, b])[0]), 2)

    def test_test_only_excluded_but_mixed_flow_kept(self):
        a = finding(); a["affected_files"][0]["file_path"] = "src/test/A.java"
        a["tainted_data_flow"][0][0]["file_path"] = "src/test/A.java"
        self.assertEqual(len(inputs.merge_records([a])[1]), 1)
        a["tainted_data_flow"][0].append({"file_path": "src/main/A.java", "line_number": 2})
        self.assertEqual(len(inputs.merge_records([a])[0]), 1)

    def test_coverity_events_preserved(self):
        p = {"issues": [{"checkerName": "PATH", "mainEventFilePathname": "/repo/A.java", "mainEventLineNumber": 3,
                         "events": [{"filePathname": "/repo/A.java", "lineNumber": 1, "eventDescription": "source"},
                                    {"filePathname": "/repo/A.java", "lineNumber": 3, "eventDescription": "sink"}]}]}
        r = inputs.coverity(p, "Coverity", "/repo")[0]
        self.assertEqual([x["line_number"] for x in r["tainted_data_flow"][0]], [1, 3])
        with self.assertRaises(ValueError): inputs.coverity({"findings": []}, "Coverity")

    def test_unknown_sarif_version_and_invalid_lines_fail(self):
        p = self.sarif(); p["version"] = "2.0"
        with self.assertRaises(ValueError): inputs.sarif(p, "CodeQL")
        r = finding(); r["tainted_data_flow"][0][0]["line_number"] = 0
        with self.assertRaises(ValueError): inputs.canonical([r])
