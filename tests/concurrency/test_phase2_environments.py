from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from epca.environments.cloud_iam.environment import CloudIAMRuntime
from epca.environments.dataflow.environment import DataFlowRuntime


@pytest.mark.parametrize(
    ("runtime", "payloads", "principal"),
    [
        (
            DataFlowRuntime(),
            (
                {"action": "switch_zone", "params": {"zone": "restricted"}},
                {"action": "open_channel", "params": {"destination": "partner"}},
            ),
            "analyst",
        ),
        (
            CloudIAMRuntime(),
            (
                {"action": "create_token", "params": {"scopes": ["read:public"]}},
                {"action": "revoke_role", "params": {"target": "agent", "role": "viewer"}},
            ),
            "agent",
        ),
    ],
)
def test_same_version_concurrent_tickets_commit_at_most_once(runtime, payloads, principal) -> None:
    runtime.create_session("concurrent")
    evaluations = [runtime.evaluate(payload, principal_id=principal, session_id="concurrent", monitor="epca") for payload in payloads]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(runtime.execute, evaluations))
    assert sum(result.commit_success for result in outcomes) == 1
    assert sorted(result.reason for result in outcomes) == ["committed", "stale_state"]
    assert runtime.snapshot("concurrent").state.state_version == 1
