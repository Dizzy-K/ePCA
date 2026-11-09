from __future__ import annotations

from epca.environments.financial.environment import FinancialRuntime
from epca.runtime.decision import DecisionStatus
from tests.conftest import transfer_payload


def test_all_phase1_guardrails_share_the_same_action_state_contract_and_executor() -> None:
    for monitor in ("no_guard", "stateless_abac", "stateful_rule", "epca"):
        runtime = FinancialRuntime()
        runtime.create_session(monitor)
        result = runtime.process(
            transfer_payload(300),
            principal_id="agent",
            session_id=monitor,
            monitor=monitor,
        )
        assert result.evaluated.action.action == "transfer"
        assert result.evaluated.contract.action_name == "transfer"
        assert result.execution.commit_success


def test_stateless_baseline_exposes_temporal_split_while_stateful_monitors_block() -> None:
    outcomes: dict[str, DecisionStatus] = {}
    final_outflow: dict[str, int] = {}
    for monitor in ("stateless_abac", "stateful_rule", "epca"):
        runtime = FinancialRuntime()
        runtime.create_session(monitor)
        runtime.process(
            transfer_payload(350),
            principal_id="agent",
            session_id=monitor,
            monitor=monitor,
        )
        second = runtime.process(
            transfer_payload(250),
            principal_id="agent",
            session_id=monitor,
            monitor=monitor,
        )
        outcomes[monitor] = second.evaluated.decision.status
        final_outflow[monitor] = runtime.snapshot(monitor).state.cumulative_outflow

    assert outcomes["stateless_abac"] == DecisionStatus.ALLOW
    assert final_outflow["stateless_abac"] == 600
    assert outcomes["stateful_rule"] == outcomes["epca"] == DecisionStatus.BLOCK
    assert final_outflow["stateful_rule"] == final_outflow["epca"] == 350


def test_no_guard_can_materialize_direct_unsafe_effect_for_feasibility_control() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("unguarded")
    result = runtime.process(
        transfer_payload(600),
        principal_id="agent",
        session_id="unguarded",
        monitor="no_guard",
    )
    assert result.evaluated.decision.status == DecisionStatus.ALLOW
    assert result.execution.commit_success
    assert runtime.snapshot("unguarded").state.cumulative_outflow == 600
