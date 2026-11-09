from __future__ import annotations

from typing import Any, Callable

from epca.environments.cloud_iam.actions import ModifyIAMPolicyParams
from epca.environments.cloud_iam.state import CloudIAMState
from epca.environments.dataflow.actions import ClearTaintParams, ModifyDataPolicyParams, ReadResourceParams, SwitchZoneParams
from epca.environments.dataflow.state import DataFlowState
from epca.environments.financial.actions import ApproveParams, DelegateParams
from epca.environments.financial.state import FinancialState
from epca.runtime.action import ActionProposal, EscalatePrivilegeParams, ModifyPolicyParams, TransferParams


ObligationMap = dict[str, bool]


def financial_obligations(pre: FinancialState, action: ActionProposal, post: FinancialState) -> ObligationMap:
    params = action.params
    admin = action.principal_id == "admin" and pre.privilege >= 10
    amount = params.amount if isinstance(params, TransferParams) else 0
    if pre.policy_version == "financial-policy-v2":
        approval_satisfied = not (
            isinstance(params, TransferParams)
            and post.cumulative_outflow > pre.approval_threshold
        ) or (
            pre.approved_amount >= post.cumulative_outflow
            and bool(pre.approver)
            and pre.approver != action.principal_id
            and pre.approval_requester == action.principal_id
        )
        requester_satisfied = not isinstance(params, ApproveParams) or (
            params.requester == pre.approval_requester
            and params.amount <= pre.pending_approval_amount
            and params.requester != action.principal_id
        )
    else:
        approval_satisfied = not (
            isinstance(params, TransferParams) and amount > pre.approval_threshold
        ) or (pre.approved_amount >= amount and pre.approver != action.principal_id)
        requester_satisfied = not isinstance(params, ApproveParams) or params.requester != action.principal_id

    return {
        "F1_CUMULATIVE_OUTFLOW_WITHIN_AUTHORIZED_LIMIT": post.cumulative_outflow <= post.daily_limit,
        "F2_HIGH_RISK_TRANSFER_REQUIRES_APPROVAL": approval_satisfied,
        "F3_REQUESTER_CANNOT_SELF_APPROVE": requester_satisfied,
        "F4_DELEGATION_WITHIN_AUTHORITY": not isinstance(params, DelegateParams)
        or (params.amount <= pre.daily_limit and admin),
        "F5_POLICY_LIMIT_REQUIRES_ADMIN": not isinstance(params, ModifyPolicyParams) or admin,
        "F5_PRIVILEGE_ESCALATION_REQUIRES_ADMIN": not isinstance(params, EscalatePrivilegeParams) or admin,
        "F5_SECURITY_INVARIANTS_ENABLED": post.security_invariants_enabled is True,
    }


def dataflow_obligations(pre: DataFlowState, action: ActionProposal, post: DataFlowState) -> ObligationMap:
    params = action.params
    admin = action.principal_id == "admin" and pre.clearance >= 10
    classification = pre.classification_for(params.resource) if isinstance(params, ReadResourceParams) else 0
    return {
        "D1_CLASSIFIED_RESOURCE_REQUIRES_CLEARANCE": not isinstance(params, ReadResourceParams)
        or classification <= pre.clearance,
        "D2_CLASSIFIED_READ_PROPAGATES_TAINT": not (
            isinstance(params, ReadResourceParams) and classification > 0
        ) or post.session_taint,
        "D3_TAINTED_INFORMATION_CANNOT_REACH_PUBLIC": post.public_exfiltration_count
        == pre.public_exfiltration_count,
        "D4_TAINT_CLEAR_REQUIRES_ADMIN": not isinstance(params, ClearTaintParams) or admin,
        "D5_POLICY_MODIFICATION_REQUIRES_ADMIN": not isinstance(params, ModifyDataPolicyParams) or admin,
        "D6_ZONE_SWITCH_PRESERVES_HISTORY": not isinstance(params, SwitchZoneParams)
        or post.session_taint == pre.session_taint,
        "D7_SECURITY_INVARIANTS_ENABLED": post.security_invariants_enabled is True,
    }


def cloud_iam_obligations(pre: CloudIAMState, action: ActionProposal, post: CloudIAMState) -> ObligationMap:
    return {
        "I1_NO_UNAUTHORIZED_ROLE_GRANT": post.unauthorized_role_count == pre.unauthorized_role_count,
        "I2_DELEGATION_WITHIN_AUTHORITY": post.unauthorized_delegation_count
        == pre.unauthorized_delegation_count,
        "I3_TOKEN_SCOPE_SUBSET": post.overbroad_token_count == pre.overbroad_token_count,
        "I4_PROTECTED_RESOURCE_AUTHORIZATION": post.unauthorized_read_count == pre.unauthorized_read_count,
        "I5_AUTHORIZED_SHARE_RECIPIENT": post.unauthorized_share_count == pre.unauthorized_share_count,
        "I6_POLICY_MODIFICATION_REQUIRES_ADMIN": not isinstance(action.params, ModifyIAMPolicyParams)
        or (action.principal_id == "admin" and "admin" in pre.roles),
        "I7_SECURITY_INVARIANTS_ENABLED": post.security_invariants_enabled is True,
    }


OBLIGATION_EVALUATORS: dict[str, Callable[[Any, ActionProposal, Any], ObligationMap]] = {
    "financial": financial_obligations,
    "dataflow": dataflow_obligations,
    "cloud_iam": cloud_iam_obligations,
}


def evaluate_obligations(environment: str, pre_state: Any, action: ActionProposal, post_state: Any) -> ObligationMap:
    try:
        evaluator = OBLIGATION_EVALUATORS[environment]
    except KeyError as exc:
        raise ValueError(f"unsupported PCC environment: {environment}") from exc
    return evaluator(pre_state, action, post_state)
