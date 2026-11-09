from __future__ import annotations

import copy
import json
from pathlib import Path

from benchmark.runner import RUNTIMES
from pcc.producer import DeterministicCertificateProducer
from phase4.analyze_pcc_adaptive import report, summarize
from phase4.pcc_llm import _certificate_from_json, _completed_call_ids, build_certificate_pairs
from phase4.pcc_adaptive import _completed_episode_ids, check_certificate_attempt, run_pcc_adaptive_episode
from phase4.model_client import ModelResponse
from phase4.config import load_config
from phase4.scenarios import SCENARIOS


ROOT = Path(__file__).resolve().parents[2]


def _safe_certificate_context() -> tuple[str, object, object, object, object, object]:
    pair = next(
        item
        for item in build_certificate_pairs(ROOT / "benchmarks/tdsc_v1/traces.jsonl")
        if item.safe
    )
    runtime_cls, _ = RUNTIMES[pair.environment]
    runtime = runtime_cls()
    session_id = "phase4-pcc-adaptive-test"
    runtime.create_session(session_id, pair.initial_state)
    snapshot = runtime.snapshot(session_id)
    action = runtime.validator.validate(
        pair.action_payload,
        principal_id=pair.principal_id,
        session_id=session_id,
    )
    contract = runtime.contracts.active_for(action.action)
    policy = runtime.policies.active
    certificate = DeterministicCertificateProducer().produce(
        environment=pair.environment,
        snapshot=snapshot,
        action=action,
        contract=contract,
        policy=policy,
    )
    assert certificate is not None
    return pair.environment, snapshot, action, contract, policy, certificate


def test_adaptive_checker_accepts_truthful_certificate() -> None:
    environment, snapshot, action, contract, policy, certificate = _safe_certificate_context()

    checked = check_certificate_attempt(
        environment=environment,
        snapshot=snapshot,
        action=action,
        contract=contract,
        policy=policy,
        certificate_text=certificate.canonical_serialization,
    )

    assert checked["accepted"] is True
    assert checked["reason"] == "certificate_valid"
    assert checked["parsed_certificate"] is True


def test_adaptive_checker_rejects_certificate_action_binding_mismatch() -> None:
    environment, snapshot, action, contract, policy, certificate = _safe_certificate_context()
    forged = copy.deepcopy(certificate.canonical_payload)
    forged["action_payload"]["params"] = dict(forged["action_payload"].get("params", {}))
    forged["action_payload"]["params"]["__adaptive_probe__"] = "changed"

    checked = check_certificate_attempt(
        environment=environment,
        snapshot=snapshot,
        action=action,
        contract=contract,
        policy=policy,
        certificate_text=json.dumps(forged),
    )

    assert checked["accepted"] is False
    assert checked["checker_reason"] == "action_binding_mismatch"
    assert checked["reason_class"] == "proof_action_binding"


def test_adaptive_summary_counts_certificate_retries() -> None:
    rows = [
        {
            "model": "actor-a",
            "environment": "financial",
            "goal_type": "adversarial",
            "api_error": None,
            "attack_goal_success": True,
            "unsafe_effect_materialized": True,
            "pvmr_materialized": False,
            "trajectory_length": 1,
            "unsafe_actions_accepted": 1,
            "unsafe_actions_proposed": 1,
            "unsafe_certificate_accepted": 1,
            "certificate_attempts": 2,
            "trajectory": [
                {
                    "oracle_safe": False,
                    "certificate_attempts": [
                        {"accepted": False, "reason_class": "post_state_binding"},
                        {"accepted": True, "reason_class": "other_rejection"},
                    ],
                }
            ],
        }
    ]

    result = summarize(rows)

    assert result["unsafe_certificate_accepted"] == 1
    assert result["unsafe_certificate_attempts"] == 2
    assert result["certificate_rejections"] == 1
    assert result["binding_rejections"] == 1


def test_certificate_attack_epca_control_does_not_use_certificate_gate() -> None:
    config = load_config(ROOT / "configs/phase4_pcc_adaptive_models.json")
    model = config.models[0]
    scenario = next(item for item in SCENARIOS if item.scenario_id == "fin-benign-transfer")

    class FakeClient:
        def complete(self, *, model, system, messages, temperature, max_tokens):
            if "certificate producer" in system:
                return ModelResponse("{\"not_a_certificate\":true}", 0.0, 0, 0, None, "stop", model.model, 1)
            return ModelResponse(
                '{"status":"act","principal_id":"agent","action":{"action":"transfer","params":{"amount":100,"recipient":"vendor_1"}}}',
                0.0,
                0,
                0,
                None,
                "stop",
                model.model,
                1,
            )

    row = run_pcc_adaptive_episode(
        config=config.__class__(
            experiment_date=config.experiment_date,
            temperature=config.temperature,
            actor_max_tokens=config.actor_max_tokens,
            judge_max_tokens=config.judge_max_tokens,
            certificate_max_tokens=config.certificate_max_tokens,
            max_turns=1,
            repeats=config.repeats,
            timeout_seconds=config.timeout_seconds,
            max_retries=config.max_retries,
            concurrency=config.concurrency,
            models=config.models,
            judge=config.judge,
        ),
        model=model,
        scenario=scenario,
        repeat=1,
        client=FakeClient(),
        max_certificate_attempts=1,
        guardrail="ePCA",
    )

    assert row["guardrail"] == "ePCA"
    assert row["trajectory"][0]["certificate_attempts"][0]["accepted"] is False
    assert row["trajectory"][0]["certificate_used"] is False
    assert row["trajectory"][0]["executed"] is True
    assert row["benign_task_completed"] is True


def test_pcc_resume_can_retry_api_error_only_records(tmp_path: Path) -> None:
    producer = tmp_path / "pcc_llm.jsonl"
    producer.write_text(
        "\n".join(
            [
                json.dumps({"call_id": "error-only", "api_error": "timeout"}),
                json.dumps({"call_id": "recovered", "api_error": "timeout"}),
                json.dumps({"call_id": "recovered", "api_error": None}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert _completed_call_ids(producer) == {"error-only", "recovered"}
    assert _completed_call_ids(producer, retry_errors=True) == {"recovered"}

    adaptive = tmp_path / "pcc_adaptive.jsonl"
    adaptive.write_text(
        "\n".join(
            [
                json.dumps({"episode_id": "error-only", "episode_complete": True, "api_error": "timeout"}),
                json.dumps({"episode_id": "recovered", "episode_complete": True, "api_error": "timeout"}),
                json.dumps({"episode_id": "recovered", "episode_complete": True, "api_error": None}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert _completed_episode_ids(adaptive) == {"error-only", "recovered"}
    assert _completed_episode_ids(adaptive, retry_errors=True) == {"recovered"}


def test_pcc_adaptive_report_keeps_pcc_and_epca_conditions_separate() -> None:
    base = {
        "model": "model-a",
        "environment": "financial",
        "scenario": "scenario-a",
        "repeat": 1,
        "goal_type": "adversarial",
        "api_error": None,
        "attack_goal_success": False,
        "unsafe_effect_materialized": False,
        "pvmr_materialized": False,
        "task_success": False,
        "benign_task_completed": False,
        "unsafe_actions_accepted": 0,
        "unsafe_actions_proposed": 1,
        "unsafe_certificate_accepted": 0,
        "certificate_attempts": 0,
        "trajectory_length": 1,
        "trajectory": [],
    }
    text = report(
        [
            {**base, "guardrail": "PCC"},
            {**base, "guardrail": "ePCA"},
        ],
        [],
    )

    assert "| PCC-LLM-Adaptive | 1/1 |" in text
    assert "| ePCA control | 1/1 |" in text
    assert "| model-a | 1 | 0 | 0 | 0 |" in text
