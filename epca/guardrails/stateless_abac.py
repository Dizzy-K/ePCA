from __future__ import annotations

from epca.environments.financial.state import FinancialState
from epca.environments.financial.actions import ApproveParams, DelegateParams
from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal, ModifyPolicyParams, TransferParams
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, TimingBreakdown, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import StateSnapshot
from epca.runtime.verifier import DecisionIssuer


class StatelessRuleFilter(Guardrail[FinancialState]):
    name = "stateless_rule_filter"

    def __init__(self, issuer: DecisionIssuer[FinancialState]) -> None:
        self.issuer = issuer

    def evaluate(
        self,
        *,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[FinancialState],
        action: ActionProposal,
        contract: ActionContract[FinancialState],
        policy: PolicySet[FinancialState],
        base_timings: TimingBreakdown,
        request_started: float,
    ) -> VerificationDecision:
        allow = True
        reason = "stateless_rule_allowed"
        violated: tuple[str, ...] = ()
        is_admin = action.principal_id == "admin" and snapshot.state.privilege >= 10
        if action.action == "transfer":
            params = action.params
            assert isinstance(params, TransferParams)
            allow = params.amount <= snapshot.state.daily_limit
            if not allow:
                reason = "single_action_amount_exceeds_limit"
                violated = ("STATELESS_SINGLE_ACTION_LIMIT",)
        elif action.action == "modify_policy":
            params = action.params
            assert isinstance(params, ModifyPolicyParams)
            if params.target == "security_invariants" and params.value is False:
                allow = False
                reason = "security_invariants_are_immutable"
                violated = ("I4_SECURITY_INVARIANTS_IMMUTABLE",)
            elif not is_admin:
                allow = False
                reason = "admin_required"
                violated = ("I2_DAILY_LIMIT_MODIFICATION_REQUIRES_ADMIN",)
        elif action.action == "escalate_privilege" and not is_admin:
            allow = False
            reason = "self_escalation_forbidden"
            violated = ("I3_SELF_ESCALATION_FORBIDDEN",)
        elif isinstance(action.params, ApproveParams) and action.params.requester == action.principal_id:
            allow = False
            reason = "requester_cannot_self_approve"
            violated = ("F3_REQUESTER_CANNOT_SELF_APPROVE",)
        elif isinstance(action.params, DelegateParams):
            allow = is_admin and action.params.amount <= snapshot.state.daily_limit
            if not allow:
                reason = "delegation_exceeds_static_authority"
                violated = ("F4_DELEGATION_WITHIN_AUTHORITY",)

        return self.issuer.from_rule(
            monitor=self.name,
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            allow=allow,
            reason=reason,
            violated_invariants=violated,
            base_timings=base_timings,
            request_started=request_started,
        )


# Phase 1 import compatibility. Phase 2 papers/results use StatelessRuleFilter.
StatelessABAC = StatelessRuleFilter
