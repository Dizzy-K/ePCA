from __future__ import annotations

from collections import Counter
from dataclasses import replace
from pathlib import Path

from benchmark.runner import RUNTIMES
from pcc.producer import DeterministicCertificateProducer
from phase4.pcc_llm import _certificate_from_json, _failure_behavior, build_certificate_pairs


ROOT = Path(__file__).resolve().parents[2]


def test_certificate_pair_benchmark_is_fixed_and_balanced() -> None:
    pairs = build_certificate_pairs(ROOT / "benchmarks/tdsc_v1/traces.jsonl")
    assert len(pairs) == 120
    assert Counter((item.environment, item.safe) for item in pairs) == {
        (environment, safe): 20
        for environment in ("financial", "dataflow", "cloud_iam")
        for safe in (True, False)
    }
    assert all(item.epca_accepted for item in pairs if item.safe)
    assert not any(item.epca_accepted for item in pairs if not item.safe)


def test_llm_certificate_json_parser_preserves_current_schema() -> None:
    pair = next(item for item in build_certificate_pairs(ROOT / "benchmarks/tdsc_v1/traces.jsonl") if item.safe)
    runtime_cls, _ = RUNTIMES[pair.environment]
    runtime = runtime_cls()
    session = "phase4-parser"
    runtime.create_session(session, pair.initial_state)
    snapshot = runtime.snapshot(session)
    action = runtime.validator.validate(pair.action_payload, principal_id=pair.principal_id, session_id=session)
    contract = runtime.contracts.active_for(action.action)
    certificate = DeterministicCertificateProducer().produce(environment=pair.environment, snapshot=snapshot, action=action, contract=contract, policy=runtime.policies.active)
    assert certificate is not None
    parsed = _certificate_from_json(certificate.canonical_payload)
    assert parsed.canonical_payload == certificate.canonical_payload


def test_pcc_failure_behavior_classifies_required_producer_failures() -> None:
    pair = next(item for item in build_certificate_pairs(ROOT / "benchmarks/tdsc_v1/traces.jsonl") if item.safe)
    runtime_cls, _ = RUNTIMES[pair.environment]
    runtime = runtime_cls()
    session = "phase4-failure-classifier"
    runtime.create_session(session, pair.initial_state)
    snapshot = runtime.snapshot(session)
    action = runtime.validator.validate(pair.action_payload, principal_id=pair.principal_id, session_id=session)
    contract = runtime.contracts.active_for(action.action)
    derived_post = contract.transition(snapshot.state, action)
    certificate = DeterministicCertificateProducer().produce(
        environment=pair.environment,
        snapshot=snapshot,
        action=action,
        contract=contract,
        policy=runtime.policies.active,
    )
    assert certificate is not None
    expected = {item.name: item.claimed_satisfied for item in certificate.obligations}

    assert _failure_behavior(None, None, None, snapshot=snapshot, action=action, derived_post=derived_post, expected_obligations=expected) == ["no_proof"]
    assert _failure_behavior("not json", None, None, snapshot=snapshot, action=action, derived_post=derived_post, expected_obligations=expected) == ["invalid_proof"]

    forged = replace(
        certificate,
        pre_state_payload={},
        claimed_post_state={},
        obligations=(),
    )
    assert _failure_behavior(
        "{}", {}, forged,
        snapshot=snapshot,
        action=action,
        derived_post=derived_post,
        expected_obligations=expected,
    ) == ["tampered_claimed_state", "tampered_post_state", "modified_obligation"]
