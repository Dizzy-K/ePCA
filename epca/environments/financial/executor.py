from __future__ import annotations

from epca.environments.financial.state import FinancialState
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract


class FinancialEffectExecutor:
    """Phase 1 simulator effect adapter; no external financial side effect is performed."""

    def execute(
        self,
        action: ActionProposal,
        pre_state: FinancialState,
        contract: ActionContract[FinancialState],
    ) -> FinancialState:
        return contract.transition(pre_state, action)
