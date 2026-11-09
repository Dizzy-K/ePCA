from __future__ import annotations

from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.policies import default_financial_policy
from epca.environments.financial.state import FinancialState
from epca.runtime.decision import DecisionStatus
from phase5.experiment import (
    _core_invariant_names,
    _expanded_policy,
    mutate_omission,
    run_portability_audit,
)


def _decision(policy, monitor: str):
    runtime = FinancialRuntime()
    runtime.activate_policy(policy)
    runtime.create_session(
        "mutation",
        FinancialState(daily_limit=500, approval_threshold=1000),
    )
    return runtime.evaluate(
        {"action": "transfer", "params": {"amount": 600}},
        principal_id="agent",
        session_id="mutation",
        monitor=monitor,
        _log_decision=False,
    )


def test_single_encoding_omissions_are_contained_but_common_mode_is_not() -> None:
    policy = default_financial_policy()
    index = next(
        index
        for index, invariant in enumerate(policy.invariants)
        if invariant.name == "I1_CUMULATIVE_OUTFLOW_WITHIN_LIMIT"
    )

    python_omission = mutate_omission(policy, index, "python_omission")
    assert _decision(python_omission, "stateful_rule").decision.status == DecisionStatus.ALLOW
    assert _decision(python_omission, "epca").decision.status == DecisionStatus.BLOCK

    smt_omission = mutate_omission(policy, index, "smt_omission")
    assert _decision(smt_omission, "stateful_rule").decision.status == DecisionStatus.BLOCK
    assert _decision(smt_omission, "epca").decision.status == DecisionStatus.ERROR

    common_omission = mutate_omission(policy, index, "common_mode_omission")
    assert _decision(common_omission, "stateful_rule").decision.status == DecisionStatus.ALLOW
    assert _decision(common_omission, "epca").decision.status == DecisionStatus.ALLOW


def test_unsat_core_names_the_violated_invariant() -> None:
    evaluated = _decision(default_financial_policy(), "epca")
    assert evaluated.decision.status == DecisionStatus.BLOCK
    assert _core_invariant_names(evaluated.decision, evaluated.policy) == (
        "I1_CUMULATIVE_OUTFLOW_WITHIN_LIMIT",
    )


def test_expanded_policy_has_requested_density_and_unique_names() -> None:
    policy = _expanded_policy(default_financial_policy(), 32)
    assert len(policy.invariants) == 32
    assert len({invariant.name for invariant in policy.invariants}) == 32


def test_portability_audit_records_dual_domain_encodings() -> None:
    rows = run_portability_audit()
    policy_rows = [row for row in rows if row["component"] == "dual_policy_definitions"]
    assert {row["environment"] for row in policy_rows} == {"financial", "dataflow", "cloud_iam"}
    assert all(row["python_predicates"] == row["smt_encodings"] == row["invariants"] for row in policy_rows)
