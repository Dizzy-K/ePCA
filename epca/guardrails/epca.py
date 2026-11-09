from __future__ import annotations

from typing import Generic, TypeVar

from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, TimingBreakdown, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import CanonicalState, StateSnapshot
from epca.runtime.verifier import EPCAVerifier


StateT = TypeVar("StateT", bound=CanonicalState)


class EPCAGuardrail(Guardrail[StateT], Generic[StateT]):
    name = "epca"

    def __init__(self, verifier: EPCAVerifier[StateT]) -> None:
        self.verifier = verifier

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
        return self.verifier.verify(
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            base_timings=base_timings,
            request_started=request_started,
        )
