from __future__ import annotations

import ast
from pathlib import Path

import pytest

from epca.environments.cloud_iam.environment import CloudIAMRuntime
from epca.environments.cloud_iam.state import CloudIAMState
from epca.environments.dataflow.environment import DataFlowRuntime
from epca.environments.dataflow.state import DataFlowState
from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.state import FinancialState
from evaluation.oracles import cloud_iam, dataflow, financial


FORBIDDEN = ("epca.guardrails", "epca.runtime.verifier", "epca.runtime.policy")


def test_oracle_modules_have_no_guardrail_verifier_or_policy_imports() -> None:
    oracle_dir = Path(__file__).parents[2] / "evaluation" / "oracles"
    for path in oracle_dir.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        assert not any(name.startswith(FORBIDDEN) for name in imports), (path, imports)


@pytest.mark.parametrize(
    ("runtime", "state", "oracle", "payload", "principal"),
    [
        (FinancialRuntime(), FinancialState(), financial, {"action": "transfer", "params": {"amount": 200}}, "agent"),
        (DataFlowRuntime(), DataFlowState(clearance=2), dataflow, {"action": "read_resource", "params": {"resource": "secret_data"}}, "analyst"),
        (CloudIAMRuntime(), CloudIAMState(), cloud_iam, {"action": "create_token", "params": {"scopes": ["read:public"]}}, "agent"),
    ],
)
def test_independent_reference_transition_matches_declared_simulator_effect(runtime, state, oracle, payload, principal) -> None:
    runtime.create_session("s", state)
    action = runtime.validator.validate(payload, principal_id=principal, session_id="s")
    contract = runtime.contracts.active_for(action.action)
    assert oracle.reference_transition(state, action) == contract.transition(state, action)


def test_oracle_does_not_read_guardrail_decision() -> None:
    runtime = FinancialRuntime()
    state = FinancialState(daily_limit=500)
    runtime.create_session("s", state)
    action = runtime.validator.validate({"action": "transfer", "params": {"amount": 600}}, principal_id="agent", session_id="s")
    post = financial.reference_transition(state, action)
    result = financial.assess_transition(state, action, post)
    assert result.safe is False
    assert "F1_CUMULATIVE_OUTFLOW_WITHIN_AUTHORIZED_LIMIT" in result.unsafe_properties
