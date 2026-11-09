from __future__ import annotations

import pytest

from epca.environments.cloud_iam.environment import CloudIAMRuntime
from epca.environments.dataflow.environment import DataFlowRuntime


@pytest.mark.parametrize(
    ("runtime", "payload", "principal"),
    [
        (DataFlowRuntime(), {"action": "switch_zone", "params": {"zone": "restricted"}}, "analyst"),
        (CloudIAMRuntime(), {"action": "read_resource", "params": {"resource": "public_doc"}}, "agent"),
    ],
)
def test_phase2_verifiers_remain_scenario_label_independent(runtime, payload, principal) -> None:
    runtime.create_session("labels")
    outputs = [runtime.evaluate(payload, principal_id=principal, session_id="labels", monitor="epca", scenario_label=label) for label in ("benign_standard", "temporal_splitting", "meta_policy_manipulation")]
    assert len({item.decision.status for item in outputs}) == 1
    assert len({item.decision.solver_result for item in outputs}) == 1
    assert len({item.decision.context.post_state_digest for item in outputs}) == 1
