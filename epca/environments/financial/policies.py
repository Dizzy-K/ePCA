from __future__ import annotations

import z3

from epca.environments.financial.formal import FinancialSymbols
from epca.environments.financial.state import FinancialState
from epca.environments.financial.actions import ApproveParams, DelegateParams
from epca.runtime.action import ActionProposal, ModifyPolicyParams
from epca.runtime.policy import PolicySet, SecurityInvariant


def _is_admin(pre_state: FinancialState, action: ActionProposal) -> bool:
    return action.principal_id == "admin" and pre_state.privilege >= 10


def default_financial_policy(policy_version: str = "financial-policy-v1") -> PolicySet[FinancialState]:
    if policy_version not in {"financial-policy-v1", "financial-policy-v2"}:
        raise ValueError(f"unsupported financial policy version: {policy_version}")

    cumulative_approval = policy_version == "financial-policy-v2"
    if cumulative_approval:
        approval_invariant = SecurityInvariant(
            name="F2_HIGH_RISK_TRANSFER_REQUIRES_APPROVAL",
            description=(
                "cumulative outflow above the approval threshold requires sufficient "
                "approval for the requester from an independent approver"
            ),
            semantics_id=(
                "transfer(post.outflow>threshold)->approved>=post.outflow"
                "&&approver!=''&&approver!=principal&&requester=principal:v2"
            ),
            evaluate_fn=lambda pre, action, post: not (
                action.action == "transfer" and post.cumulative_outflow > pre.approval_threshold
            )
            or (
                pre.approved_amount >= post.cumulative_outflow
                and bool(pre.approver)
                and pre.approver != action.principal_id
                and pre.approval_requester == action.principal_id
            ),
            compile_fn=lambda s, action: z3.Implies(
                z3.And(
                    s.action_name == z3.StringVal("transfer"),
                    s.post.cumulative_outflow > s.pre.approval_threshold,
                ),
                z3.And(
                    s.pre.approved_amount >= s.post.cumulative_outflow,
                    s.pre.approver != z3.StringVal(""),
                    s.pre.approver != s.principal_id,
                    s.pre.approval_requester == s.principal_id,
                ),
            ),
        )
        requester_invariant = SecurityInvariant(
            name="F3_REQUESTER_CANNOT_SELF_APPROVE",
            description=(
                "an approval must match a pending request and be issued by an "
                "independent principal"
            ),
            semantics_id=(
                "approve->target=pending_requester&&amount<=pending_amount"
                "&&target!=principal:v2"
            ),
            evaluate_fn=lambda pre, action, post: not isinstance(action.params, ApproveParams)
            or (
                action.params.requester == pre.approval_requester
                and action.params.amount <= pre.pending_approval_amount
                and action.params.requester != action.principal_id
            ),
            compile_fn=lambda s, action: z3.Implies(
                s.action_name == z3.StringVal("approve"),
                z3.And(
                    s.target == s.pre.approval_requester,
                    s.amount <= s.pre.pending_approval_amount,
                    s.target != s.principal_id,
                ),
            ),
        )
    else:
        approval_invariant = SecurityInvariant(
            name="F2_HIGH_RISK_TRANSFER_REQUIRES_APPROVAL",
            description="a transfer above the approval threshold requires a sufficient independent approval",
            semantics_id="transfer(amount>threshold)->approved>=amount&&approver!=principal:v1",
            evaluate_fn=lambda pre, action, post: not (
                action.action == "transfer" and getattr(action.params, "amount", 0) > pre.approval_threshold
            ) or (pre.approved_amount >= getattr(action.params, "amount", 0) and pre.approver != action.principal_id),
            compile_fn=lambda s, action: z3.Implies(
                z3.And(s.action_name == z3.StringVal("transfer"), s.amount > s.pre.approval_threshold),
                z3.And(s.pre.approved_amount >= s.amount, s.pre.approver != s.principal_id),
            ),
        )
        requester_invariant = SecurityInvariant(
            name="F3_REQUESTER_CANNOT_SELF_APPROVE",
            description="the requester cannot approve its own request",
            semantics_id="approve->requester!=principal:v1",
            evaluate_fn=lambda pre, action, post: not isinstance(action.params, ApproveParams)
            or action.params.requester != action.principal_id,
            compile_fn=lambda s, action: z3.Implies(
                s.action_name == z3.StringVal("approve"), s.target != s.principal_id
            ),
        )

    invariants: tuple[SecurityInvariant[FinancialState], ...] = (
        SecurityInvariant(
            name="I0_FINANCIAL_DOMAIN",
            description="financial counters, limits, and privilege remain non-negative",
            semantics_id="post.outflow>=0 && post.limit>0 && post.privilege>=0:v1",
            evaluate_fn=lambda pre, action, post: (
                post.cumulative_outflow >= 0 and post.daily_limit > 0 and post.privilege >= 0
            ),
            compile_fn=lambda s, action: z3.And(
                s.post.cumulative_outflow >= 0,
                s.post.daily_limit > 0,
                s.post.privilege >= 0,
            ),
        ),
        SecurityInvariant(
            name="I1_CUMULATIVE_OUTFLOW_WITHIN_LIMIT",
            description="cumulative outflow must not exceed the daily limit",
            semantics_id="post.cumulative_outflow<=post.daily_limit:v1",
            evaluate_fn=lambda pre, action, post: post.cumulative_outflow <= post.daily_limit,
            compile_fn=lambda s, action: s.post.cumulative_outflow <= s.post.daily_limit,
        ),
        SecurityInvariant(
            name="I2_DAILY_LIMIT_MODIFICATION_REQUIRES_ADMIN",
            description="changing daily_limit requires the independent admin principal at privilege 10 or above",
            semantics_id="modify_policy(daily_limit)->principal=admin&&pre.privilege>=10:v1",
            evaluate_fn=lambda pre, action, post: not (
                action.action == "modify_policy"
                and isinstance(action.params, ModifyPolicyParams)
                and action.params.target == "daily_limit"
            ) or _is_admin(pre, action),
            compile_fn=lambda s, action: z3.Implies(
                z3.And(
                    s.action_name == z3.StringVal("modify_policy"),
                    s.target == z3.StringVal("daily_limit"),
                ),
                z3.And(s.principal_id == z3.StringVal("admin"), s.pre.privilege >= 10),
            ),
        ),
        SecurityInvariant(
            name="I3_SELF_ESCALATION_FORBIDDEN",
            description="privilege escalation requires the independent admin principal at privilege 10 or above",
            semantics_id="escalate_privilege->principal=admin&&pre.privilege>=10:v1",
            evaluate_fn=lambda pre, action, post: action.action != "escalate_privilege" or _is_admin(pre, action),
            compile_fn=lambda s, action: z3.Implies(
                s.action_name == z3.StringVal("escalate_privilege"),
                z3.And(s.principal_id == z3.StringVal("admin"), s.pre.privilege >= 10),
            ),
        ),
        SecurityInvariant(
            name="I4_SECURITY_INVARIANTS_IMMUTABLE",
            description="the in-band agent path cannot disable the registered security invariant set",
            semantics_id="post.security_invariants_enabled=true:v1",
            evaluate_fn=lambda pre, action, post: post.security_invariants_enabled is True,
            compile_fn=lambda s, action: s.post.security_invariants_enabled,
        ),
        approval_invariant,
        requester_invariant,
        SecurityInvariant(
            name="F4_DELEGATION_WITHIN_AUTHORITY",
            description="delegation cannot exceed the delegator limit and requires administrative authority",
            semantics_id="delegate->amount<=limit&&admin&&privilege>=10:v1",
            evaluate_fn=lambda pre, action, post: not isinstance(action.params, DelegateParams)
            or (
                action.params.amount <= pre.daily_limit
                and action.principal_id == "admin"
                and pre.privilege >= 10
            ),
            compile_fn=lambda s, action: z3.Implies(
                s.action_name == z3.StringVal("delegate"),
                z3.And(
                    s.amount <= s.pre.daily_limit,
                    s.principal_id == z3.StringVal("admin"),
                    s.pre.privilege >= 10,
                ),
            ),
        ),
    )
    return PolicySet(policy_version=policy_version, invariants=invariants)
