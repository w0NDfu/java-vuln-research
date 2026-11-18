from urllib.error import HTTPError

import pytest

from java_vuln_research.work1_agent.experiment_policy import audited_policy
from java_vuln_research.work1_agent.experiment_policy import BudgetExceeded, RequestJournal, VerificationReserve
from java_vuln_research.work1_agent.experiment_policy import exclusive_run
from java_vuln_research.work1_agent.harness import ModelTurn, PolicyError


class FakeChat:
    system_prompt = "Return a JSON object."

    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)

    def __call__(self, context):
        outcome = next(self.outcomes)
        if isinstance(outcome, int):
            raise PolicyError(f"Model endpoint returned HTTP {outcome}.") from HTTPError(
                "https://example.test", outcome, "test error", {}, None,
            )
        return ModelTurn(outcome, {"prompt_tokens": 30, "completion_tokens": 10})


def test_transient_and_invalid_responses_each_get_a_receipt():
    records, waits = [], []
    policy = audited_policy(FakeChat([503, "invalid", '{"action":"finish"}']),
                            lambda **row: records.append(row), input_rate=0.001, output_rate=0.002,
                            sleep=waits.append)
    assert policy({"role": "reasoning"}).content == '{"action":"finish"}'
    assert [row["state"] for row in records] == ["provider_error", "invalid_response", "received"]
    assert records[0]["http_status"] == 503
    assert records[-1]["estimated_usd"] == pytest.approx(0.05)
    assert waits == [2]


def test_authentication_failure_is_not_retried():
    records = []
    policy = audited_policy(FakeChat([401]), lambda **row: records.append(row),
                            input_rate=0.001, output_rate=0.002)
    with pytest.raises(PolicyError, match="401"):
        policy({"role": "discovery"})
    assert [row["http_status"] for row in records] == [401]


def test_request_journal_replays_completed_calls_and_preserves_shared_budget(tmp_path):
    class Chat:
        system_prompt = "Return JSON."
        max_output_tokens = 200
        endpoint = "https://example.test/v1/chat/completions"
        model = "gpt-6.1-sol"
        calls = 0

        def __call__(self, context):
            self.calls += 1
            return ModelTurn('{"action":"finish"}', {"total_tokens": 100})

    path = tmp_path / "requests.jsonl"
    chat = Chat()
    journal = RequestJournal(path, max_requests=1, max_tokens=20000, max_seconds=60, binding="source-a")
    assert journal.wrap(chat)({"role": "reasoning"}).content == '{"action":"finish"}'
    restored = RequestJournal(path, max_requests=1, max_tokens=20000, max_seconds=60, binding="source-a")
    restored.wrap(chat)({"role": "reasoning"})
    assert chat.calls == 1
    assert restored.requests == 1
    assert restored.tokens == 100
    with pytest.raises(BudgetExceeded):
        restored.wrap(chat)({"role": "verification"})
    with pytest.raises(ValueError, match="different source"):
        RequestJournal(path, max_requests=1, max_tokens=20000, max_seconds=60, binding="source-b")


def test_inflight_request_reservation_survives_restart(tmp_path):
    class BrokenChat:
        system_prompt = "Return JSON."
        max_output_tokens = 200
        endpoint = "https://example.test"
        model = "gpt-6.1-sol"

        def __call__(self, context):
            raise PolicyError("connection lost")

    path = tmp_path / "requests.jsonl"
    journal = RequestJournal(path, max_requests=1, max_tokens=20000, max_seconds=60, binding="a")
    with pytest.raises(PolicyError):
        journal.wrap(BrokenChat())({"role": "reasoning"})
    restored = RequestJournal(path, max_requests=1, max_tokens=20000, max_seconds=60, binding="a")
    assert restored.requests == 1
    assert restored.tokens > 8192
    with pytest.raises(BudgetExceeded):
        restored.wrap(BrokenChat())({"role": "reasoning"})


def test_experiment_lock_rejects_duplicate_writers_and_allows_resume(tmp_path):
    path = tmp_path / "run.lock"
    with exclusive_run(path):
        with pytest.raises(OSError):
            with exclusive_run(path):
                pytest.fail("Duplicate experiment acquired the same writer lock.")
    with exclusive_run(path):
        assert path.exists()


def test_local_budget_stop_is_not_counted_as_a_provider_request(tmp_path):
    chat = FakeChat([])
    chat.endpoint = "https://example.test"
    chat.model = "gpt-6.1-sol"
    chat.max_output_tokens = 100
    journal = RequestJournal(tmp_path / "requests.jsonl", max_requests=1, max_tokens=1,
                             max_seconds=60, binding="source")
    records = []
    policy = audited_policy(journal.wrap(chat), lambda **row: records.append(row),
                            input_rate=0.000002, output_rate=0.000010)
    with pytest.raises(BudgetExceeded):
        policy({"role": "reasoning"})
    assert journal.requests == 0
    assert records == []


def test_dynamic_reserve_releases_zero_candidate_capacity_and_replays_receipts(tmp_path, monkeypatch):
    import json
    import java_vuln_research.work1_agent.experiment_policy as policy_module

    monkeypatch.setattr(policy_module, "request_reserve", lambda *_: (9000, "fixture"))

    class Chat:
        system_prompt = "Return JSON."
        max_output_tokens = 1000
        endpoint = "https://example.test"
        model = "gpt-6.1-sol"

        def __call__(self, context):
            return ModelTurn('{"action":"finish"}', {"total_tokens": 5000})

    path = tmp_path / "journal.jsonl"
    journal = RequestJournal(path, max_requests=16, max_tokens=150000, max_seconds=60,
                             binding="dynamic", verification_reserve=True)
    # The reserve is 12k with no pending review. The old 36k floor would reject this.
    journal.tokens = 125000
    journal.requests = 10
    context = {"role": "reasoning", "round": 4, "final_synthesis": True,
               "verification_budget": {"pending_verification_count": 0}}
    journal.wrap(Chat())(context)
    row = json.loads(path.read_text().splitlines()[0])
    assert row["held_verification_tokens"] == 12000 and row["held_verification_requests"] == 1
    assert journal.tokens == 130000 and journal.requests == 11
    pending = {**context, "verification_budget": {"pending_verification_count": 1}}
    with pytest.raises(VerificationReserve):
        journal.wrap(Chat())(pending)
    # At 15k gross headroom the final synthesis is admitted with a 3k admission reserve.
    journal.tokens = 135000
    journal.wrap(Chat())({**context, "round": 3})
    row = json.loads(path.read_text().splitlines()[-2])
    assert row["reserved_tokens"] == 3000 and row["final_admission_adjusted"]
    assert row["reserve_estimate"] == 9000
    journal.requests = 15
    with pytest.raises(VerificationReserve):
        journal.wrap(Chat())({**context, "round": 2})
    # Verification can consume its reserved last request.
    journal.wrap(Chat())({"role": "verification", "verification_budget": {"pending_verification_count": 1}})
    assert journal.requests == 16
