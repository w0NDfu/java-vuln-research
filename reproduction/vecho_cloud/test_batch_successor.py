import unittest

from batch_successor import decision


class SuccessorGatesTests(unittest.TestCase):
    def test_completed_current_sample_can_continue(self):
        self.assertEqual(decision({"current_sample": "one"}, {"one": {}}, 120, [])[0], True)

    def test_failed_or_unfinished_sample_is_never_retried(self):
        self.assertFalse(decision({"current_sample": "two", "status": "stopped_on_failure"}, {"one": {}}, 120, [])[0])

    def test_live_or_orphaned_work_blocks_restart(self):
        self.assertFalse(decision({"current_sample": "one"}, {"one": {}}, 120, [123])[0])

    def test_finished_dataset_needs_no_restart(self):
        self.assertEqual(decision({"current_sample": "one"}, {"one": {}}, 1, [])[1], "all_workflows_complete")


if __name__ == "__main__":
    unittest.main()
