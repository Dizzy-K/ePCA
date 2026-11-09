from __future__ import annotations

from typing import Generic, TypeVar

from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, TimingBreakdown, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import CanonicalState, StateSnapshot
from epca.runtime.verifier import DecisionIssuer


StateT = TypeVar("StateT", bound=CanonicalState)


class StatefulRuleMonitor(Guardrail[StateT], Generic[StateT]):
    name = "stateful_rule"

    def __init__(self, issuer: DecisionIssuer[StateT]) -> None:
        self.issuer = issuer

    def evaluate(
        self,
        *,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[StateT],
        action: ActionProposal,
        contract: ActionContract[StateT],
        policy: PolicySet[StateT],
        base_timings: TimingBreakdown,
        request_started: float,
    ) -> VerificationDecision:
        post_state = contract.transition(snapshot.state, action)
        violated = policy.violated(snapshot.state, action, post_state)
        return self.issuer.from_rule(
            monitor=self.name,
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            allow=not violated,
            reason="stateful_policy_satisfied" if not violated else "stateful_policy_violation",
            violated_invariants=violated,
            base_timings=base_timings,
            request_started=request_started,
        )
