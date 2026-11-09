from __future__ import annotations

from dataclasses import replace

import pytest

from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.state import FinancialState
from pcc.certificate import CertificateObligation
from pcc.checker import ConcreteCertificateChecker
from pcc.producer import DeterministicCertificateProducer, ProducerMode


def _fixture(amount: int = 300):
    runtime = FinancialRuntime()
    runtime.create_session("pcc", FinancialState(cumulative_outflow=100, daily_limit=500))
    snapshot = runtime.snapshot("pcc")
    action = runtime.validator.validate(
        {"action": "transfer", "params": {"amount": amount}},
        principal_id="agent",
        session_id="pcc",
    )
    contract = runtime.contracts.active_for(action.action)
    policy = runtime.policies.active
    return runtime, snapshot, action, contract, policy


def test_valid_certificate_is_accepted() -> None:
    _, snapshot, action, contract, policy = _fixture()
    certificate = DeterministicCertificateProducer().produce(
        environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy
    )
    result = ConcreteCertificateChecker().check(
        environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy, certificate=certificate
    )
    assert result.accepted
    assert result.reason == "certificate_valid"


def test_unsafe_transition_certificate_is_rejected() -> None:
    _, snapshot, action, contract, policy = _fixture(401)
    certificate = DeterministicCertificateProducer().produce(
        environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy
    )
    result = ConcreteCertificateChecker().check(
        environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy, certificate=certificate
    )
    assert not result.accepted
    assert result.reason == "safety_obligation_failed"


def test_invalid_and_missing_proof_fail_closed() -> None:
    _, snapshot, action, contract, policy = _fixture()
    checker = ConcreteCertificateChecker()
    missing = checker.check(environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy, certificate=None)
    invalid_certificate = DeterministicCertificateProducer(ProducerMode.INVALID).produce(
        environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy
    )
    invalid = checker.check(environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy, certificate=invalid_certificate)
    assert (missing.accepted, missing.reason) == (False, "missing_certificate")
    assert (invalid.accepted, invalid.reason) == (False, "invalid_obligation_witness")


def test_claimed_post_state_mutation_is_rejected() -> None:
    _, snapshot, action, contract, policy = _fixture()
    certificate = DeterministicCertificateProducer().produce(
        environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy
    )
    assert certificate is not None
    forged = replace(certificate, claimed_post_state={**certificate.claimed_post_state, "cumulative_outflow": 0})
    result = ConcreteCertificateChecker().check(environment="financial", snapshot=snapshot, action=action, contract=contract, policy=policy, certificate=forged)
    assert not result.accepted
    assert result.reason == "post_state_transition_mismatch"
