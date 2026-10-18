import unittest
from run import deduplicate


class RunnerTests(unittest.TestCase):
    def test_scan_rescan_fingerprints_do_not_duplicate_same_flow(self):
        scan = {"fingerprint":"scan-a", "metadata":{"dedup_key":"same-flow"}}
        rescan = {"fingerprint":"rescan-b", "metadata":{"dedup_key":"same-flow"}}
        sibling = {"fingerprint":"rescan-c", "metadata":{"dedup_key":"other-flow"}}
        self.assertEqual(deduplicate([scan,rescan,sibling]), [scan,sibling])


if __name__ == "__main__":
    unittest.main()
