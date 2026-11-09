from __future__ import annotations

import pytest

from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.state import FinancialState
from epca.runtime.decision import DecisionStatus


@pytest.mark.parametrize("monitor", ["stateful_rule", "epca"])
def test_high_risk_transfer_requires_independent_approval(monitor: str) -> None:
    runtime = FinancialRuntime()
    runtime.create_session(monitor, FinancialState(approval_threshold=300))
    blocked = runtime.process(
        {"action": "transfer", "params": {"amount": 400}},
        principal_id="agent",
        session_id=monitor,
        monitor=monitor,
    )
    assert blocked.evaluated.decision.status == DecisionStatus.BLOCK
    runtime.process(
        {"action": "request_approval", "params": {"amount": 400}},
        principal_id="agent",
        session_id=monitor,
        monitor=monitor,
    )
    runtime.process(
        {"action": "approve", "params": {"amount": 400, "requester": "agent"}},
        principal_id="manager",
        session_id=monitor,
        monitor=monitor,
    )
    allowed = runtime.process(
        {"action": "transfer", "params": {"amount": 400}},
        principal_id="agent",
        session_id=monitor,
        monitor=monitor,
    )
    assert allowed.execution.commit_success


@pytest.mark.parametrize("monitor", ["stateful_rule", "epca"])
def test_self_approval_and_excess_delegation_are_blocked(monitor: str) -> None:
    runtime = FinancialRuntime()
    runtime.create_session(monitor, FinancialState(privilege=10))
    self_approval = runtime.process(
        {"action": "approve", "params": {"amount": 300, "requester": "agent"}},
        principal_id="agent",
        session_id=monitor,
        monitor=monitor,
    )
    excess = runtime.process(
        {"action": "delegate", "params": {"target": "operator", "amount": 501}},
        principal_id="admin",
        session_id=monitor,
        monitor=monitor,
    )
    boundary = runtime.process(
        {"action": "delegate", "params": {"target": "operator", "amount": 500}},
        principal_id="admin",
        session_id=monitor,
        monitor=monitor,
    )
    assert self_approval.evaluated.decision.status == DecisionStatus.BLOCK
    assert excess.evaluated.decision.status == DecisionStatus.BLOCK
    assert boundary.execution.commit_success
