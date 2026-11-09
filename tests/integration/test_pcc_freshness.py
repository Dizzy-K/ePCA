from __future__ import annotations

import pytest

from epca.environments.cloud_iam.environment import CloudIAMRuntime
from epca.environments.cloud_iam.state import CloudIAMState
from epca.environments.dataflow.environment import DataFlowRuntime
from epca.environments.dataflow.state import DataFlowState
from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.state import FinancialState
from pcc.checker import ConcreteCertificateChecker
from pcc.producer import DeterministicCertificateProducer


CASES = (
    (FinancialRuntime, FinancialState(cumulative_outflow=100), {"action": "transfer", "params": {"amount": 300}}, {"action": "transfer", "params": {"amount": 400}}, "agent", {"cumulative_outflow": 300}),
    (DataFlowRuntime, DataFlowState(clearance=2), {"action": "switch_zone", "params": {"zone": "restricted"}}, {"action": "send", "params": {"destination": "public", "resource": "public_report"}}, "analyst", {"session_taint": True}),
    (CloudIAMRuntime, CloudIAMState(roles=("viewer", "analyst"), static_roles=("viewer", "analyst")), {"action": "create_token", "params": {"scopes": ["read:public"]}}, {"action": "create_token", "params": {"scopes": ["*"]}}, "agent", {"roles": ("viewer",)}),
)


@pytest.mark.parametrize(("runtime_cls", "state", "safe_payload", "mutated_payload", "principal", "state_update"), CASES)
def test_action_and_state_mutation_invalidate_certificate(runtime_cls, state, safe_payload, mutated_payload, principal, state_update) -> None:
    runtime = runtime_cls()
    runtime.create_session("pcc", state)
    snapshot = runtime.snapshot("pcc")
    action = runtime.validator.validate(safe_payload, principal_id=principal, session_id="pcc")
    contract = runtime.contracts.active_for(action.action)
    policy = runtime.policies.active
    certificate = DeterministicCertificateProducer().produce(environment=snapshot.environment, snapshot=snapshot, action=action, contract=contract, policy=policy)
    mutated = runtime.validator.validate(mutated_payload, principal_id=principal, session_id="pcc")
    mutation = ConcreteCertificateChecker().check(environment=snapshot.environment, snapshot=snapshot, action=mutated, contract=runtime.contracts.active_for(mutated.action), policy=policy, certificate=certificate)
    assert not mutation.accepted
    assert mutation.reason == "action_binding_mismatch"
    runtime.administrative_update("pcc", **state_update)
    stale = ConcreteCertificateChecker().check(environment=snapshot.environment, snapshot=runtime.snapshot("pcc"), action=action, contract=contract, policy=policy, certificate=certificate)
    assert not stale.accepted
    assert stale.reason == "stale_certificate"
