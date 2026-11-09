from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, TimingBreakdown, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import CanonicalState, StateSnapshot


StateT = TypeVar("StateT", bound=CanonicalState)


class Guardrail(ABC, Generic[StateT]):
    name: str

    @abstractmethod
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
        raise NotImplementedError
