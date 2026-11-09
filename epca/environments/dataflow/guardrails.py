from __future__ import annotations

from epca.environments.dataflow.actions import ReadResourceParams, SendParams
from epca.environments.dataflow.state import DataFlowState
from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, TimingBreakdown, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import StateSnapshot
from epca.runtime.verifier import DecisionIssuer


class DataFlowStatelessRuleFilter(Guardrail[DataFlowState]):
    """Strong single-action rules without taint, zone, or trajectory history."""

    name = "stateless_rule_filter"

    def __init__(self, issuer: DecisionIssuer[DataFlowState]) -> None:
        self.issuer = issuer

    def evaluate(
        self,
        *,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[DataFlowState],
        action: ActionProposal,
        contract: ActionContract[DataFlowState],
        policy: PolicySet[DataFlowState],
        base_timings: TimingBreakdown,
        request_started: float,
    ) -> VerificationDecision:
        allow = True
        reason = "stateless_rule_allowed"
        violated: tuple[str, ...] = ()
        state = snapshot.state
        if action.action == "read_resource":
            params = action.params
            assert isinstance(params, ReadResourceParams)
            if state.classification_for(params.resource) > state.clearance:
                allow, reason = False, "insufficient_static_clearance"
                violated = ("D1_CLASSIFIED_READ_REQUIRES_CLEARANCE",)
        elif action.action == "send":
            params = action.params
            assert isinstance(params, SendParams)
            if params.destination == "public" and state.classification_for(params.resource) > 0:
                allow, reason = False, "classified_resource_to_public"
                violated = ("D3_DIRECT_CLASSIFIED_PUBLIC_SEND",)
        elif action.action in {"clear_taint", "modify_policy"}:
            if not (action.principal_id == "admin" and state.clearance >= 10):
                allow, reason = False, "admin_required"
                violated = (
                    "D4_TAINT_CLEAR_REQUIRES_ADMIN"
                    if action.action == "clear_taint"
                    else "D5_POLICY_MODIFICATION_REQUIRES_ADMIN",
                )
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
