from __future__ import annotations

from dataclasses import dataclass

import z3

from epca.environments.financial.state import FinancialState
from epca.environments.financial.actions import ApproveParams, DelegateParams, RequestApprovalParams
from epca.runtime.action import (
    ActionProposal,
    EscalatePrivilegeParams,
    ModifyPolicyParams,
    TransferParams,
)
from epca.runtime.contract import NamedConstraint


@dataclass(frozen=True)
class FinancialStateSymbols:
    cumulative_outflow: z3.ArithRef
    daily_limit: z3.ArithRef
    privilege: z3.ArithRef
    approval_threshold: z3.ArithRef
    pending_approval_amount: z3.ArithRef
    approval_requester: z3.SeqRef
    approved_amount: z3.ArithRef
    approver: z3.SeqRef
    delegated_limit: z3.ArithRef
    delegate_target: z3.SeqRef
    security_invariants_enabled: z3.BoolRef
    policy_version: z3.SeqRef
    state_version: z3.ArithRef


@dataclass(frozen=True)
class FinancialSymbols:
    pre: FinancialStateSymbols
    post: FinancialStateSymbols
    action_name: z3.SeqRef
    amount: z3.ArithRef
    recipient: z3.SeqRef
    target: z3.SeqRef
    value_int: z3.ArithRef
    value_bool: z3.BoolRef
    new_privilege: z3.ArithRef
    principal_id: z3.SeqRef
    session_id: z3.SeqRef
    active_policy_version: z3.SeqRef
    active_contract_version: z3.SeqRef


def _state_symbols(prefix: str) -> FinancialStateSymbols:
    return FinancialStateSymbols(
        cumulative_outflow=z3.Int(f"{prefix}_cumulative_outflow"),
        daily_limit=z3.Int(f"{prefix}_daily_limit"),
        privilege=z3.Int(f"{prefix}_privilege"),
        approval_threshold=z3.Int(f"{prefix}_approval_threshold"),
        pending_approval_amount=z3.Int(f"{prefix}_pending_approval_amount"),
        approval_requester=z3.String(f"{prefix}_approval_requester"),
        approved_amount=z3.Int(f"{prefix}_approved_amount"),
        approver=z3.String(f"{prefix}_approver"),
        delegated_limit=z3.Int(f"{prefix}_delegated_limit"),
        delegate_target=z3.String(f"{prefix}_delegate_target"),
        security_invariants_enabled=z3.Bool(f"{prefix}_security_invariants_enabled"),
        policy_version=z3.String(f"{prefix}_policy_version"),
        state_version=z3.Int(f"{prefix}_state_version"),
    )


def create_symbols() -> FinancialSymbols:
    return FinancialSymbols(
        pre=_state_symbols("pre"),
        post=_state_symbols("post"),
        action_name=z3.String("action_name"),
        amount=z3.Int("action_amount"),
        recipient=z3.String("action_recipient"),
        target=z3.String("action_target"),
        value_int=z3.Int("action_value_int"),
        value_bool=z3.Bool("action_value_bool"),
        new_privilege=z3.Int("action_new_privilege"),
        principal_id=z3.String("action_principal_id"),
        session_id=z3.String("action_session_id"),
        active_policy_version=z3.String("active_policy_version"),
        active_contract_version=z3.String("active_contract_version"),
    )


def _bind_state(prefix: str, symbols: FinancialStateSymbols, state: FinancialState) -> tuple[NamedConstraint, ...]:
    return (
        NamedConstraint(f"bind::{prefix}::cumulative_outflow", symbols.cumulative_outflow == state.cumulative_outflow, f"{prefix}.cumulative_outflow == {state.cumulative_outflow}"),
        NamedConstraint(f"bind::{prefix}::daily_limit", symbols.daily_limit == state.daily_limit, f"{prefix}.daily_limit == {state.daily_limit}"),
        NamedConstraint(f"bind::{prefix}::privilege", symbols.privilege == state.privilege, f"{prefix}.privilege == {state.privilege}"),
        NamedConstraint(f"bind::{prefix}::approval_threshold", symbols.approval_threshold == state.approval_threshold, f"{prefix}.approval_threshold == {state.approval_threshold}"),
        NamedConstraint(f"bind::{prefix}::pending_approval_amount", symbols.pending_approval_amount == state.pending_approval_amount, f"{prefix}.pending_approval_amount == {state.pending_approval_amount}"),
        NamedConstraint(f"bind::{prefix}::approval_requester", symbols.approval_requester == z3.StringVal(state.approval_requester), "exact approval requester"),
        NamedConstraint(f"bind::{prefix}::approved_amount", symbols.approved_amount == state.approved_amount, f"{prefix}.approved_amount == {state.approved_amount}"),
        NamedConstraint(f"bind::{prefix}::approver", symbols.approver == z3.StringVal(state.approver), "exact approver"),
        NamedConstraint(f"bind::{prefix}::delegated_limit", symbols.delegated_limit == state.delegated_limit, f"{prefix}.delegated_limit == {state.delegated_limit}"),
        NamedConstraint(f"bind::{prefix}::delegate_target", symbols.delegate_target == z3.StringVal(state.delegate_target), "exact delegate target"),
        NamedConstraint(
            f"bind::{prefix}::security_invariants_enabled",
            symbols.security_invariants_enabled == z3.BoolVal(state.security_invariants_enabled),
            f"{prefix}.security_invariants_enabled == {state.security_invariants_enabled}",
        ),
        NamedConstraint(
            f"bind::{prefix}::policy_version",
            symbols.policy_version == z3.StringVal(state.policy_version),
            f"{prefix}.policy_version == {state.policy_version!r}",
        ),
        NamedConstraint(f"bind::{prefix}::state_version", symbols.state_version == state.state_version, f"{prefix}.state_version == {state.state_version}"),
    )


def exact_bindings(
    symbols: FinancialSymbols,
    *,
    pre_state: FinancialState,
    action: ActionProposal,
    post_state: FinancialState,
    policy_version: str,
    contract_version: str,
) -> tuple[NamedConstraint, ...]:
    amount = -1
    recipient = ""
    target = ""
    value_int = -1
    value_bool = False
    new_privilege = -1
    if isinstance(action.params, TransferParams):
        amount = action.params.amount
        recipient = action.params.recipient
    elif isinstance(action.params, ModifyPolicyParams):
        target = action.params.target
        if type(action.params.value) is int:
            value_int = action.params.value
        else:
            value_bool = action.params.value
    elif isinstance(action.params, EscalatePrivilegeParams):
        new_privilege = action.params.new_privilege
    elif isinstance(action.params, RequestApprovalParams):
        amount = action.params.amount
    elif isinstance(action.params, ApproveParams):
        amount = action.params.amount
        target = action.params.requester
    elif isinstance(action.params, DelegateParams):
        amount = action.params.amount
        target = action.params.target

    return (
        *_bind_state("pre", symbols.pre, pre_state),
        *_bind_state("post", symbols.post, post_state),
        NamedConstraint("bind::action_name", symbols.action_name == z3.StringVal(action.action), f"action == {action.action!r}"),
        NamedConstraint("bind::amount", symbols.amount == amount, f"amount == {amount}"),
        NamedConstraint("bind::recipient", symbols.recipient == z3.StringVal(recipient), f"recipient == {recipient!r}"),
        NamedConstraint("bind::target", symbols.target == z3.StringVal(target), f"target == {target!r}"),
        NamedConstraint("bind::value_int", symbols.value_int == value_int, f"value_int == {value_int}"),
        NamedConstraint("bind::value_bool", symbols.value_bool == z3.BoolVal(value_bool), f"value_bool == {value_bool}"),
        NamedConstraint("bind::new_privilege", symbols.new_privilege == new_privilege, f"new_privilege == {new_privilege}"),
        NamedConstraint("bind::principal_id", symbols.principal_id == z3.StringVal(action.principal_id), f"principal == {action.principal_id!r}"),
        NamedConstraint("bind::session_id", symbols.session_id == z3.StringVal(action.session_id), f"session == {action.session_id!r}"),
        NamedConstraint(
            "bind::active_policy_version",
            symbols.active_policy_version == z3.StringVal(policy_version),
            f"active policy version == {policy_version!r}",
        ),
        NamedConstraint(
            "bind::active_contract_version",
            symbols.active_contract_version == z3.StringVal(contract_version),
            f"active contract version == {contract_version!r}",
        ),
        NamedConstraint(
            "bind::state_policy_matches_active",
            symbols.pre.policy_version == symbols.active_policy_version,
            "trusted state policy version matches active policy version",
        ),
    )
