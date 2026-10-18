import tempfile
import unittest
from pathlib import Path

from state_bundle import seal, unseal


class StateBundleTests(unittest.TestCase):
    def test_state_is_exact_and_tampering_creates_no_plaintext(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.exceptions import InvalidTag
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
            (root / "private.pem").write_bytes(private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            (root / "public.pem").write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            original = b"offline secret test fixture\x00" * 5000
            (root / "state.tar.gz").write_bytes(original)
            seal(root / "state.tar.gz", root / "public.pem", root / "state.vechoenc")
            self.assertNotIn(b"offline secret test fixture", (root / "state.vechoenc").read_bytes())
            unseal(root / "state.vechoenc", root / "private.pem", root / "restored.tar.gz")
            self.assertEqual((root / "restored.tar.gz").read_bytes(), original)
            with self.assertRaises(FileExistsError):
                unseal(root / "state.vechoenc", root / "private.pem", root / "restored.tar.gz")
            corrupt = bytearray((root / "state.vechoenc").read_bytes())
            corrupt[-1] ^= 1
            (root / "corrupt.vechoenc").write_bytes(corrupt)
            with self.assertRaises(InvalidTag):
                unseal(root / "corrupt.vechoenc", root / "private.pem", root / "bad.tar.gz")
            self.assertFalse((root / "bad.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
