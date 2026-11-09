from phase4.failure_localization import (
    classify_epca_case,
    collect_actual_pairs,
    episode_has_encoded_violation,
    translate_report_to_chinese,
)


def test_collect_actual_pairs_deduplicates_semantic_pairs() -> None:
    turn = {
        "turn": 1,
        "state_before": {"state_version": 0},
        "principal_id": "agent",
        "action": {"action": "x", "params": {}},
        "oracle_safe": True,
        "decision": "allow",
        "executed": True,
    }
    rows = [
        {"episode_id": "one", "environment": "financial", "guardrail": "ePCA", "trajectory": [turn]},
        {"episode_id": "two", "environment": "financial", "guardrail": "StatefulRuleMonitor", "trajectory": [turn]},
    ]

    pairs = collect_actual_pairs(rows)

    assert len(pairs) == 1
    assert len(next(iter(pairs.values()))["sources"]) == 2


def test_encoded_violation_requires_committed_transition() -> None:
    row = {
        "environment": "financial",
        "trajectory": [
            {
                "state_before": {"state_version": 0},
                "turn": 1,
                "principal_id": "agent",
                "action": {"action": "x", "params": {}},
                "oracle_safe": False,
                "executed": False,
            }
        ],
    }
    key = next(iter(collect_actual_pairs([{**row, "episode_id": "e", "guardrail": "ePCA"}])))
    replayed = {key: {"violated_invariants": ["I1"]}}

    assert episode_has_encoded_violation(row, replayed) is False


def test_epca_cumulative_oracle_gap_is_class_c() -> None:
    row = {
        "environment": "financial",
        "unsafe_effect_materialized": True,
        "trajectory": [
            {
                "state_before": {"state_version": 0},
                "turn": 1,
                "principal_id": "agent",
                "action": {"action": "x", "params": {}},
                "oracle_safe": True,
                "decision": "allow",
                "executed": True,
            }
        ],
    }
    key = next(iter(collect_actual_pairs([{**row, "episode_id": "e", "guardrail": "ePCA"}])))
    replayed = {key: {"violated_invariants": [], "decision_disagreement": False}}

    assert classify_epca_case(row, replayed)[0] == "C"


def test_chinese_report_preserves_canonical_identifiers() -> None:
    report = "# Phase 4.5 — Adaptive Failure Localization\n## Result\n- Final unsafe properties: `F2_UNAPPROVED_HIGH_RISK_TRANSFER_EFFECT`"

    translated = translate_report_to_chinese(report)

    assert "自适应失败定位" in translated
    assert "结论摘要" in translated
    assert "F2_UNAPPROVED_HIGH_RISK_TRANSFER_EFFECT" in translated
