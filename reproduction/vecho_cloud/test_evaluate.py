import tempfile
import unittest
from pathlib import Path

from evaluate import declarations, path_key, score


class MatchingTests(unittest.TestCase):
    def test_method_hit_and_same_file_nonhit(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            (repo / "A.java").write_text("class A {\n void vulnerable() {\n  dangerous();\n }\n void safe() {\n  harmless();\n }\n}\n")
            fixes = [{"file":"A.java", "class":"A", "method":"vulnerable"}, {"file":"src/test/B.java", "class":"B", "method":"test"}]
            records = [{"fingerprint":"hit", "tainted_data_flow":[[{"file_path":"/A.java", "line_number":3}]]}, {"fingerprint":"miss", "tainted_data_flow":[[{"file_path":"A.java", "line_number":6}]]}]
            result = score(repo, records, fixes)
            self.assertEqual((result["recall"], result["tp_paths"], result["paths"], result["tp_alerts"]), (1,1,2,1))
            self.assertEqual(result["precision"], 0.5)
            self.assertAlmostEqual(result["f1"], 2 / 3)
            self.assertEqual(len(result["target_methods"]), 1)

    def test_empty_output_is_not_failure(self):
        result = score(Path("."), [], [{"file":"A.java", "class":"A", "method":"v"}])
        self.assertEqual((result["recall"],result["precision"],result["f1"]), (0,0,0))

    def test_constructor_nested_class_and_overloads(self):
        classes, methods, error = declarations(b'class A { A() {} void f() {} void f(int x) {} class B { void g() {} } }')
        self.assertFalse(error)
        self.assertIn("B", [x[0] for x in classes])
        self.assertEqual([x[0] for x in methods].count("f"), 2)
        self.assertIn("A", [x[0] for x in methods])

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            path_key("../metadata/fix_info.csv", Path("/tmp/source"))


if __name__ == "__main__":
    unittest.main()
