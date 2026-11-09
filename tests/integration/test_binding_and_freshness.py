from __future__ import annotations

from dataclasses import replace

from epca.environments.financial.contracts import TransferContract
from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.policies import default_financial_policy
from epca.runtime.action import SchemaValidator
from epca.runtime.decision import DecisionStatus
from tests.conftest import transfer_payload


def test_action_amount_mutation_invalidates_ticket() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("mutation")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="mutation",
        monitor="epca",
    )
    assert evaluated.decision.ticket is not None
    mutated_action = SchemaValidator().validate(
        transfer_payload(301),
        principal_id="agent",
        session_id="mutation",
    )
    forged = replace(evaluated.decision.ticket, action=mutated_action)
    result = runtime.bound_executor.execute(forged)
    assert result.executed is False
    assert result.reason == "ticket_authentication_failed"
    assert runtime.snapshot("mutation").state.cumulative_outflow == 0


def test_action_type_mutation_invalidates_ticket() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("type-mutation")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="type-mutation",
        monitor="epca",
    )
    assert evaluated.decision.ticket is not None
    mutated_action = SchemaValidator().validate(
        {"action": "escalate_privilege", "params": {"new_privilege": 10}},
        principal_id="agent",
        session_id="type-mutation",
    )
    forged = replace(evaluated.decision.ticket, action=mutated_action)
    result = runtime.bound_executor.execute(forged)
    assert not result.executed
    assert result.reason == "ticket_authentication_failed"


def test_action_recipient_mutation_invalidates_ticket() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("recipient-mutation")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="recipient-mutation",
        monitor="epca",
    )
    assert evaluated.decision.ticket is not None
    mutated_action = SchemaValidator().validate(
        {"action": "transfer", "params": {"amount": 300, "recipient": "account_C"}},
        principal_id="agent",
        session_id="recipient-mutation",
    )
    forged = replace(evaluated.decision.ticket, action=mutated_action)
    result = runtime.bound_executor.execute(forged)
    assert not result.executed
    assert result.reason == "ticket_authentication_failed"


def test_canonical_context_mutation_invalidates_ticket() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("context-mutation")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="context-mutation",
        monitor="epca",
    )
    ticket = evaluated.decision.ticket
    assert ticket is not None
    forged_context = replace(ticket.context, action_digest="0" * 64)
    forged = replace(ticket, context=forged_context)
    result = runtime.bound_executor.execute(forged)
    assert not result.executed
    assert result.reason == "ticket_authentication_failed"


def test_state_change_after_verification_makes_ticket_stale() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("stale")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="stale",
        monitor="epca",
    )
    runtime.administrative_update("stale", daily_limit=450)
    result = runtime.execute(evaluated)
    assert result.executed is False
    assert result.reason == "stale_state"
    state = runtime.snapshot("stale").state
    assert state.cumulative_outflow == 0
    assert state.state_version == 1


def test_policy_version_change_invalidates_old_ticket() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("policy")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="policy",
        monitor="epca",
    )
    runtime.activate_policy(default_financial_policy("financial-policy-v2"))
    result = runtime.execute(evaluated)
    assert not result.executed
    assert result.reason == "policy_version_or_digest_mismatch"


def test_contract_version_change_invalidates_old_ticket() -> None:
    class TransferContractV2(TransferContract):
        contract_version = "financial-transfer-v2"
        semantics_id = "financial.transfer:outflow_plus_amount:state_version_plus_one:v2"

    runtime = FinancialRuntime()
    runtime.create_session("contract")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="contract",
        monitor="epca",
    )
    runtime.activate_contract(TransferContractV2())
    result = runtime.execute(evaluated)
    assert not result.executed
    assert result.reason == "contract_version_or_digest_mismatch"
    assert runtime.snapshot("contract").state.cumulative_outflow == 0


def test_successful_ticket_binds_exact_action_and_post_state() -> None:
    runtime = FinancialRuntime()
    runtime.create_session("bound")
    evaluated = runtime.evaluate(
        transfer_payload(300),
        principal_id="agent",
        session_id="bound",
        monitor="epca",
    )
    ticket = evaluated.decision.ticket
    assert ticket is not None
    assert ticket.context.action_digest == ticket.action.digest
    assert ticket.context.pre_state_digest == ticket.pre_state.digest
    assert ticket.context.post_state_digest == ticket.post_state.digest
    result = runtime.execute(evaluated)
    assert result.commit_success
    assert result.new_state.digest == ticket.context.post_state_digest
