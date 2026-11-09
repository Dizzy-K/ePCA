from __future__ import annotations

import z3

from epca.environments.financial.formal import FinancialSymbols
from epca.environments.financial.actions import ApproveParams, DelegateParams, RequestApprovalParams
from epca.environments.financial.state import FinancialState
from epca.runtime.action import (
    ActionProposal,
    EscalatePrivilegeParams,
    ModifyPolicyParams,
    TransferParams,
)
from epca.runtime.contract import ActionContract, ContractRegistry, NamedConstraint


def _frame_constraints(symbols: FinancialSymbols, *, exclude: set[str]) -> list[z3.BoolRef]:
    fields = {
        "cumulative_outflow": symbols.post.cumulative_outflow == symbols.pre.cumulative_outflow,
        "daily_limit": symbols.post.daily_limit == symbols.pre.daily_limit,
        "privilege": symbols.post.privilege == symbols.pre.privilege,
        "approval_threshold": symbols.post.approval_threshold == symbols.pre.approval_threshold,
        "pending_approval_amount": symbols.post.pending_approval_amount == symbols.pre.pending_approval_amount,
        "approval_requester": symbols.post.approval_requester == symbols.pre.approval_requester,
        "approved_amount": symbols.post.approved_amount == symbols.pre.approved_amount,
        "approver": symbols.post.approver == symbols.pre.approver,
        "delegated_limit": symbols.post.delegated_limit == symbols.pre.delegated_limit,
        "delegate_target": symbols.post.delegate_target == symbols.pre.delegate_target,
        "security_invariants_enabled": symbols.post.security_invariants_enabled == symbols.pre.security_invariants_enabled,
        "policy_version": symbols.post.policy_version == symbols.pre.policy_version,
    }
    return [formula for name, formula in fields.items() if name not in exclude]


class TransferContract(ActionContract[FinancialState]):
    action_name = "transfer"
    contract_version = "financial-transfer-v1"
    semantics_id = "financial.transfer:outflow_plus_amount:state_version_plus_one:v1"
    parameter_model = TransferParams

    def transition(self, pre_state: FinancialState, action: ActionProposal) -> FinancialState:
        if not self.accepts(action):
            raise TypeError("TransferContract received an incompatible action")
        params = action.params
        assert isinstance(params, TransferParams)
        return pre_state.model_copy(
            update={
                "cumulative_outflow": pre_state.cumulative_outflow + params.amount,
                "state_version": pre_state.state_version + 1,
            }
        )

    def compile_transition(self, symbols: FinancialSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return (
            NamedConstraint(
                "contract::transfer",
                z3.And(
                    symbols.action_name == z3.StringVal(self.action_name),
                    symbols.amount > 0,
                    symbols.post.cumulative_outflow == symbols.pre.cumulative_outflow + symbols.amount,
                    symbols.post.state_version == symbols.pre.state_version + 1,
                    *_frame_constraints(symbols, exclude={"cumulative_outflow"}),
                ),
                "transfer deterministically increments cumulative outflow by the exact amount",
            ),
        )


class ModifyPolicyContract(ActionContract[FinancialState]):
    action_name = "modify_policy"
    contract_version = "financial-modify-policy-v1"
    semantics_id = "financial.modify_policy:daily_limit_or_security_flag:state_version_plus_one:v1"
    parameter_model = ModifyPolicyParams

    def transition(self, pre_state: FinancialState, action: ActionProposal) -> FinancialState:
        if not self.accepts(action):
            raise TypeError("ModifyPolicyContract received an incompatible action")
        params = action.params
        assert isinstance(params, ModifyPolicyParams)
        updates: dict[str, object] = {"state_version": pre_state.state_version + 1}
        if params.target == "daily_limit":
            assert type(params.value) is int
            updates["daily_limit"] = params.value
        else:
            assert type(params.value) is bool
            updates["security_invariants_enabled"] = params.value
        return pre_state.model_copy(update=updates)

    def compile_transition(self, symbols: FinancialSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        params = action.params
        assert isinstance(params, ModifyPolicyParams)
        if params.target == "daily_limit":
            changed = symbols.post.daily_limit == symbols.value_int
            excluded = {"daily_limit"}
        else:
            changed = symbols.post.security_invariants_enabled == symbols.value_bool
            excluded = {"security_invariants_enabled"}
        return (
            NamedConstraint(
                "contract::modify_policy",
                z3.And(
                    symbols.action_name == z3.StringVal(self.action_name),
                    symbols.target == z3.StringVal(params.target),
                    changed,
                    symbols.post.state_version == symbols.pre.state_version + 1,
                    *_frame_constraints(symbols, exclude=excluded),
                ),
                "modify_policy deterministically changes only the requested registered field",
            ),
        )


class EscalatePrivilegeContract(ActionContract[FinancialState]):
    action_name = "escalate_privilege"
    contract_version = "financial-escalate-privilege-v1"
    semantics_id = "financial.escalate_privilege:set_exact_privilege:state_version_plus_one:v1"
    parameter_model = EscalatePrivilegeParams

    def transition(self, pre_state: FinancialState, action: ActionProposal) -> FinancialState:
        if not self.accepts(action):
            raise TypeError("EscalatePrivilegeContract received an incompatible action")
        params = action.params
        assert isinstance(params, EscalatePrivilegeParams)
        return pre_state.model_copy(
            update={
                "privilege": params.new_privilege,
                "state_version": pre_state.state_version + 1,
            }
        )

    def compile_transition(self, symbols: FinancialSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return (
            NamedConstraint(
                "contract::escalate_privilege",
                z3.And(
                    symbols.action_name == z3.StringVal(self.action_name),
                    symbols.post.privilege == symbols.new_privilege,
                    symbols.post.state_version == symbols.pre.state_version + 1,
                    *_frame_constraints(symbols, exclude={"privilege"}),
                ),
                "escalate_privilege deterministically sets the exact requested privilege",
            ),
        )


class RequestApprovalContract(ActionContract[FinancialState]):
    action_name = "request_approval"
    contract_version = "financial-request-approval-v1"
    semantics_id = "financial.request_approval:set_pending_and_requester:v1"
    parameter_model = RequestApprovalParams

    def transition(self, pre_state: FinancialState, action: ActionProposal) -> FinancialState:
        if not self.accepts(action):
            raise TypeError("RequestApprovalContract received an incompatible action")
        params = action.params
        assert isinstance(params, RequestApprovalParams)
        return pre_state.model_copy(update={"pending_approval_amount": params.amount, "approval_requester": action.principal_id, "state_version": pre_state.state_version + 1})

    def compile_transition(self, symbols: FinancialSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return (
            NamedConstraint("contract::request_approval", z3.And(symbols.action_name == z3.StringVal(self.action_name), symbols.post.pending_approval_amount == symbols.amount, symbols.post.approval_requester == symbols.principal_id, symbols.post.state_version == symbols.pre.state_version + 1, *_frame_constraints(symbols, exclude={"pending_approval_amount", "approval_requester"})), "request records the exact amount and requester"),
        )


class ApproveContract(ActionContract[FinancialState]):
    action_name = "approve"
    contract_version = "financial-approve-v1"
    semantics_id = "financial.approve:set_amount_and_approver:v1"
    parameter_model = ApproveParams

    def transition(self, pre_state: FinancialState, action: ActionProposal) -> FinancialState:
        if not self.accepts(action):
            raise TypeError("ApproveContract received an incompatible action")
        params = action.params
        assert isinstance(params, ApproveParams)
        return pre_state.model_copy(update={"approved_amount": params.amount, "approver": action.principal_id, "state_version": pre_state.state_version + 1})

    def compile_transition(self, symbols: FinancialSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return (
            NamedConstraint("contract::approve", z3.And(symbols.action_name == z3.StringVal(self.action_name), symbols.post.approved_amount == symbols.amount, symbols.post.approver == symbols.principal_id, symbols.post.state_version == symbols.pre.state_version + 1, *_frame_constraints(symbols, exclude={"approved_amount", "approver"})), "approval records exact amount and independent approver identity"),
        )


class ApproveContractV2(ApproveContract):
    """Policy-v2 approval coverage is monotonic and cannot be overwritten downward."""

    contract_version = "financial-approve-v2"
    semantics_id = "financial.approve:max_coverage_and_approver:v2"

    def transition(self, pre_state: FinancialState, action: ActionProposal) -> FinancialState:
        if not self.accepts(action):
            raise TypeError("ApproveContractV2 received an incompatible action")
        params = action.params
        assert isinstance(params, ApproveParams)
        return pre_state.model_copy(
            update={
                "approved_amount": max(pre_state.approved_amount, params.amount),
                "approver": action.principal_id,
                "state_version": pre_state.state_version + 1,
            }
        )

    def compile_transition(self, symbols: FinancialSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        params = action.params
        assert isinstance(params, ApproveParams)
        return (
            NamedConstraint(
                "contract::approve",
                z3.And(
                    symbols.action_name == z3.StringVal(self.action_name),
                    symbols.post.approved_amount == z3.If(
                        symbols.pre.approved_amount >= symbols.amount,
                        symbols.pre.approved_amount,
                        symbols.amount,
                    ),
                    symbols.post.approver == symbols.principal_id,
                    symbols.post.state_version == symbols.pre.state_version + 1,
                    *_frame_constraints(symbols, exclude={"approved_amount", "approver"}),
                ),
                "approval coverage is monotonic and records the latest independent approver",
            ),
        )


class DelegateContract(ActionContract[FinancialState]):
    action_name = "delegate"
    contract_version = "financial-delegate-v1"
    semantics_id = "financial.delegate:set_target_and_limit:v1"
    parameter_model = DelegateParams

    def transition(self, pre_state: FinancialState, action: ActionProposal) -> FinancialState:
        if not self.accepts(action):
            raise TypeError("DelegateContract received an incompatible action")
        params = action.params
        assert isinstance(params, DelegateParams)
        return pre_state.model_copy(update={"delegated_limit": params.amount, "delegate_target": params.target, "state_version": pre_state.state_version + 1})

    def compile_transition(self, symbols: FinancialSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return (
            NamedConstraint("contract::delegate", z3.And(symbols.action_name == z3.StringVal(self.action_name), symbols.post.delegated_limit == symbols.amount, symbols.post.delegate_target == symbols.target, symbols.post.state_version == symbols.pre.state_version + 1, *_frame_constraints(symbols, exclude={"delegated_limit", "delegate_target"})), "delegation records exact target and amount"),
        )


def financial_contract_registry(
    policy_version: str = "financial-policy-v1",
) -> ContractRegistry[FinancialState]:
    approval = ApproveContractV2() if policy_version == "financial-policy-v2" else ApproveContract()
    return ContractRegistry(
        (
            TransferContract(),
            RequestApprovalContract(),
            approval,
            DelegateContract(),
            ModifyPolicyContract(),
            EscalatePrivilegeContract(),
        )
    )
