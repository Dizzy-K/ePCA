from __future__ import annotations

from epca.environments.dataflow.state import DataFlowState
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract


class DataFlowEffectExecutor:
    """Deterministic in-memory effect adapter; no file or network effect exists."""

    def execute(
        self,
        action: ActionProposal,
        pre_state: DataFlowState,
        contract: ActionContract[DataFlowState],
    ) -> DataFlowState:
        return contract.transition(pre_state, action)
