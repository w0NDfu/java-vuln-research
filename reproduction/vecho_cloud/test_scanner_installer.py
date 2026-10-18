import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from apply_scanner_repair import digest, install


class ScannerInstallerTests(unittest.TestCase):
    def test_recognized_previous_patch_upgrades_and_installs_idempotently(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "artifact"
            source = root / "overlay"
            source.mkdir()
            target = artifact / "scaner/client.go"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"previous repair\n")
            (source / "client.go").write_bytes(b"new repair\n")
            manifest = {"artifact_commit": "pinned", "files": {"client.go": {
                "original_sha256": digest(b"original\n"), "patched_sha256": digest(b"new repair\n"),
                "accepted_previous_sha256": [digest(b"previous repair\n")]}}}
            (source / "manifest.json").write_text(json.dumps(manifest))
            with patch("apply_scanner_repair.subprocess.check_output", return_value="pinned\n"):
                record = install(artifact, source)
                self.assertEqual(record["changed_files"], ["client.go"])
                self.assertEqual((Path(record["backup"]) / "client.go").read_bytes(), b"previous repair\n")
                self.assertEqual(install(artifact, source)["changed_files"], [])
                target.write_bytes(b"unrecognized local edit\n")
                with self.assertRaisesRegex(RuntimeError, "Unrecognized"):
                    install(artifact, source)
                self.assertEqual(target.read_bytes(), b"unrecognized local edit\n")


if __name__ == "__main__":
    unittest.main()
