from scripts.reproduce_paper import aggregate
from exp.config import env_api_key


def test_archived_paper_summary_matches_release_counts():
    summary = aggregate()
    assert summary["recorded_pair_comparison"] == {
        "pairs": 863, "occurrences": 3966, "disagreements": 0,
    }
    assert summary["adaptive"]["ePCA"]["PVMR_from_archived_invariants"] == [0, 108]
    assert summary["pcc"]["gpt-5.5"]["PCC_safe_accepted"] == [148, 180]


def test_legacy_credentials_are_environment_only(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert env_api_key() == ""
    monkeypatch.setenv("OPENAI_API_KEY", "unit-test-placeholder")
    assert env_api_key() == "unit-test-placeholder"
