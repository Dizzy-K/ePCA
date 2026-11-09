from __future__ import annotations

import pytest

from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.state import FinancialState
from epca.runtime.decision import DecisionStatus


POLICY_V2 = "financial-policy-v2"
STRONG_MONITORS = ("stateful_rule", "pcc_action", "epca")


def _runtime(session: str, *, daily_limit: int = 1000, threshold: int = 500) -> FinancialRuntime:
    runtime = FinancialRuntime(policy_version=POLICY_V2)
    runtime.create_session(
        session,
        FinancialState(
            daily_limit=daily_limit,
            approval_threshold=threshold,
            policy_version=POLICY_V2,
        ),
    )
    return runtime


def _process(
    runtime: FinancialRuntime,
    session: str,
    monitor: str,
    action: str,
    params: dict[str, object],
    principal: str = "agent",
):
    return runtime.process(
        {"action": action, "params": params},
        principal_id=principal,
        session_id=session,
        monitor=monitor,
    )


@pytest.mark.parametrize("monitor", STRONG_MONITORS)
def test_unapproved_split_transfer_is_blocked_at_cumulative_threshold(monitor: str) -> None:
    runtime = _runtime(monitor)
    first = _process(runtime, monitor, monitor, "transfer", {"amount": 300, "recipient": "vendor_a"})
    second = _process(runtime, monitor, monitor, "transfer", {"amount": 300, "recipient": "vendor_b"})

    assert first.execution.commit_success
    assert second.evaluated.decision.status == DecisionStatus.BLOCK
    assert "F2_HIGH_RISK_TRANSFER_REQUIRES_APPROVAL" in second.evaluated.decision.violated_invariants
    assert runtime.snapshot(monitor).state.cumulative_outflow == 300


@pytest.mark.parametrize("monitor", STRONG_MONITORS)
def test_independent_approval_covers_multiple_transfers_only_up_to_total_amount(monitor: str) -> None:
    runtime = _runtime(monitor)
    assert _process(runtime, monitor, monitor, "request_approval", {"amount": 600}).execution.commit_success
    assert _process(
        runtime,
        monitor,
        monitor,
        "approve",
        {"amount": 600, "requester": "agent"},
        principal="manager",
    ).execution.commit_success
    assert _process(runtime, monitor, monitor, "transfer", {"amount": 300, "recipient": "vendor_a"}).execution.commit_success
    assert _process(runtime, monitor, monitor, "transfer", {"amount": 300, "recipient": "vendor_b"}).execution.commit_success

    exhausted = _process(runtime, monitor, monitor, "transfer", {"amount": 1, "recipient": "vendor_c"})
    assert exhausted.evaluated.decision.status == DecisionStatus.BLOCK
    assert runtime.snapshot(monitor).state.cumulative_outflow == 600


@pytest.mark.parametrize("monitor", STRONG_MONITORS)
def test_approval_must_match_a_real_pending_request(monitor: str) -> None:
    runtime = _runtime(monitor)
    fabricated = _process(
        runtime,
        monitor,
        monitor,
        "approve",
        {"amount": 600, "requester": "agent"},
        principal="manager",
    )
    assert fabricated.evaluated.decision.status == DecisionStatus.BLOCK
    assert "F3_REQUESTER_CANNOT_SELF_APPROVE" in fabricated.evaluated.decision.violated_invariants


@pytest.mark.parametrize("monitor", STRONG_MONITORS)
def test_insufficient_approval_does_not_cover_larger_cumulative_outflow(monitor: str) -> None:
    runtime = _runtime(monitor)
    _process(runtime, monitor, monitor, "request_approval", {"amount": 550})
    _process(
        runtime,
        monitor,
        monitor,
        "approve",
        {"amount": 550, "requester": "agent"},
        principal="manager",
    )
    assert _process(runtime, monitor, monitor, "transfer", {"amount": 300, "recipient": "vendor_a"}).execution.commit_success
    blocked = _process(runtime, monitor, monitor, "transfer", {"amount": 300, "recipient": "vendor_b"})
    assert blocked.evaluated.decision.status == DecisionStatus.BLOCK


@pytest.mark.parametrize("monitor", STRONG_MONITORS)
def test_approval_coverage_is_monotonic_across_history(monitor: str) -> None:
    runtime = _runtime(monitor)
    _process(runtime, monitor, monitor, "request_approval", {"amount": 1000})
    _process(
        runtime,
        monitor,
        monitor,
        "approve",
        {"amount": 1000, "requester": "agent"},
        principal="manager",
    )
    assert _process(runtime, monitor, monitor, "transfer", {"amount": 500, "recipient": "vendor_a"}).execution.commit_success
    _process(runtime, monitor, monitor, "request_approval", {"amount": 500})
    _process(
        runtime,
        monitor,
        monitor,
        "approve",
        {"amount": 500, "requester": "agent"},
        principal="manager",
    )
    state = runtime.snapshot(monitor).state
    assert state.approved_amount == 1000
    assert state.cumulative_outflow == 500
    assert not runtime.policies.active.violated(
        state,
        runtime.validator.validate(
            {"action": "transfer", "params": {"amount": 500, "recipient": "vendor_b"}},
            principal_id="agent",
            session_id=monitor,
        ),
        state.model_copy(update={"cumulative_outflow": 1000}),
    )


@pytest.mark.parametrize("monitor", STRONG_MONITORS)
def test_exact_approval_threshold_needs_no_approval(monitor: str) -> None:
    runtime = _runtime(monitor)
    boundary = _process(runtime, monitor, monitor, "transfer", {"amount": 500, "recipient": "vendor"})
    assert boundary.execution.commit_success


def test_v1_semantics_remain_frozen_and_distinct() -> None:
    runtime = FinancialRuntime(policy_version="financial-policy-v1")
    runtime.create_session(
        "v1",
        FinancialState(daily_limit=1000, approval_threshold=500, policy_version="financial-policy-v1"),
    )
    assert _process(runtime, "v1", "epca", "transfer", {"amount": 300, "recipient": "a"}).execution.commit_success
    assert _process(runtime, "v1", "epca", "transfer", {"amount": 300, "recipient": "b"}).execution.commit_success
