from __future__ import annotations

from epca.environments.cloud_iam.state import CloudIAMState
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract


class CloudIAMEffectExecutor:
    """Deterministic IAM simulator adapter; no cloud-provider API is called."""

    def execute(
        self,
        action: ActionProposal,
        pre_state: CloudIAMState,
        contract: ActionContract[CloudIAMState],
    ) -> CloudIAMState:
        return contract.transition(pre_state, action)
