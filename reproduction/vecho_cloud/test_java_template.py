import tempfile
import unittest
from pathlib import Path

from evaluate import declarations, score, template_source


class JavaTemplateTests(unittest.TestCase):
    name = "archetypes/demo/src/main/resources/archetype-resources/src/main/java/Demo.java"
    source = b"## Velocity header\r\npackage ${package};\r\nclass Demo {\r\n void run() {}\r\n}\r\n"

    def test_template_preserves_locations_and_scores_without_dropping_flow(self):
        rendered, changes = template_source(self.source, self.name)
        self.assertTrue(changes)
        self.assertEqual(len(rendered), len(self.source))
        self.assertEqual(rendered.count(b"\n"), self.source.count(b"\n"))
        self.assertEqual(declarations(rendered)[1], [("run", 4, 4)])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / self.name
            path.parent.mkdir(parents=True)
            path.write_bytes(self.source)
            records = [{"fingerprint": "test", "tainted_data_flow": [[{"file_path": self.name, "line_number": 4}]]}]
            result = score(root, records, [{"file": self.name, "class": "Demo", "method": "run"}])
            self.assertEqual((result["paths"], result["tp_paths"], result["recall"]), (1, 1, 1))
            self.assertFalse(result["parse_error_files"])
            self.assertIn(self.name, result["source_normalizations"])
            self.assertEqual(path.read_bytes(), self.source)

    def test_ordinary_source_is_never_rewritten(self):
        rendered, changes = template_source(self.source, "src/main/java/Demo.java")
        self.assertEqual(rendered, self.source)
        self.assertFalse(changes)
        self.assertTrue(declarations(rendered)[2])

    def test_other_template_syntax_errors_are_not_suppressed(self):
        rendered, _ = template_source(self.source.replace(b"void run() {}", b"void run( {"), self.name)
        self.assertTrue(declarations(rendered)[2])


if __name__ == "__main__":
    unittest.main()
