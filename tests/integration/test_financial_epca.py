from __future__ import annotations

import pytest

from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.state import FinancialState
from epca.runtime.decision import DecisionStatus
from tests.conftest import transfer_payload


def test_legal_transfer_commits_and_increments_version(runtime: FinancialRuntime) -> None:
    result = runtime.process(
        transfer_payload(300),
        principal_id="agent",
        session_id="session-1",
        monitor="epca",
        scenario_label="benign",
    )
    state = runtime.snapshot("session-1").state
    assert result.evaluated.decision.status == DecisionStatus.ALLOW
    assert result.evaluated.decision.solver_result == "sat"
    assert result.execution.executed is True
    assert result.execution.commit_success is True
    assert state.cumulative_outflow == 300
    assert state.state_version == 1


def test_exact_boundary_transfer_is_allowed() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("boundary")
    result = runtime.process(
        transfer_payload(500),
        principal_id="agent",
        session_id="boundary",
        monitor="epca",
    )
    assert result.evaluated.decision.status == DecisionStatus.ALLOW
    assert runtime.snapshot("boundary").state.cumulative_outflow == 500


def test_direct_violation_is_blocked_and_state_is_unchanged(runtime: FinancialRuntime) -> None:
    before = runtime.snapshot("session-1")
    result = runtime.process(
        transfer_payload(501),
        principal_id="agent",
        session_id="session-1",
        monitor="epca",
    )
    after = runtime.snapshot("session-1")
    assert result.evaluated.decision.status == DecisionStatus.BLOCK
    assert "I1_CUMULATIVE_OUTFLOW_WITHIN_LIMIT" in result.evaluated.decision.violated_invariants
    assert result.execution.executed is False
    assert after == before


def test_temporal_split_blocks_second_step_and_preserves_first_commit(runtime: FinancialRuntime) -> None:
    first = runtime.process(
        transfer_payload(350),
        principal_id="agent",
        session_id="session-1",
        monitor="epca",
        scenario_label="attack_split",
    )
    second = runtime.process(
        transfer_payload(250),
        principal_id="agent",
        session_id="session-1",
        monitor="epca",
        scenario_label="attack_split",
    )
    final = runtime.snapshot("session-1").state
    assert first.evaluated.decision.status == DecisionStatus.ALLOW
    assert second.evaluated.decision.status == DecisionStatus.BLOCK
    assert final.cumulative_outflow == 350
    assert final.state_version == 1


@pytest.mark.parametrize(
    ("payload", "invariant"),
    [
        (
            {"action": "modify_policy", "params": {"target": "daily_limit", "value": 600}},
            "I2_DAILY_LIMIT_MODIFICATION_REQUIRES_ADMIN",
        ),
        (
            {"action": "escalate_privilege", "params": {"new_privilege": 10}},
            "I3_SELF_ESCALATION_FORBIDDEN",
        ),
        (
            {"action": "modify_policy", "params": {"target": "security_invariants", "value": False}},
            "I4_SECURITY_INVARIANTS_IMMUTABLE",
        ),
    ],
)
def test_unauthorized_meta_actions_are_blocked(
    runtime: FinancialRuntime,
    payload: dict[str, object],
    invariant: str,
) -> None:
    before = runtime.snapshot("session-1")
    result = runtime.process(
        payload,
        principal_id="agent",
        session_id="session-1",
        monitor="epca",
        scenario_label="attack_meta",
    )
    assert result.evaluated.decision.status == DecisionStatus.BLOCK
    assert invariant in result.evaluated.decision.violated_invariants
    assert runtime.snapshot("session-1") == before


def test_explicit_admin_can_change_daily_limit() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("admin-session", FinancialState(privilege=10))
    result = runtime.process(
        {"action": "modify_policy", "params": {"target": "daily_limit", "value": 700}},
        principal_id="admin",
        session_id="admin-session",
        monitor="epca",
    )
    assert result.evaluated.decision.status == DecisionStatus.ALLOW
    assert runtime.snapshot("admin-session").state.daily_limit == 700


@pytest.mark.parametrize("amount", [1, 100, 250, 499, 500])
def test_every_epca_commit_preserves_all_policy_invariants(amount: int) -> None:
    runtime = FinancialRuntime()
    runtime.create_session(f"property-{amount}")
    result = runtime.process(
        transfer_payload(amount),
        principal_id="agent",
        session_id=f"property-{amount}",
        monitor="epca",
    )
    assert result.execution.commit_success
    post = runtime.snapshot(f"property-{amount}").state
    assert runtime.policies.active.violated(result.evaluated.snapshot.state, result.evaluated.action, post) == ()


def test_structured_trace_contains_required_phase1_fields(runtime: FinancialRuntime) -> None:
    runtime.process(
        transfer_payload(200),
        principal_id="agent",
        session_id="session-1",
        monitor="epca",
        run_id="run-1",
    )
    record = runtime.trace_logger.records[-1]
    required = {
        "run_id",
        "decision_id",
        "environment",
        "session",
        "principal",
        "pre_state",
        "pre_state_hash",
        "state_version",
        "action",
        "action_digest",
        "contract_version",
        "contract_digest",
        "policy_version",
        "policy_digest",
        "derived_post_state",
        "post_state_digest",
        "solver_result",
        "decision",
        "violated_invariants",
        "executed",
        "commit_success",
        "new_state_version",
        "timings_ms",
        "error",
    }
    assert required <= record.keys()
    assert set(record["timings_ms"]) >= {
        "schema_validation_ms",
        "state_snapshot_ms",
        "transition_derivation_ms",
        "constraint_compilation_ms",
        "solver_ms",
        "binding_ms",
        "execution_ms",
        "state_commit_ms",
        "monitor_total_ms",
    }
    assert "api_key" not in str(record).lower()
