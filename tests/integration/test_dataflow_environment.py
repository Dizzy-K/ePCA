from __future__ import annotations

import pytest

from epca.environments.dataflow.environment import DataFlowRuntime
from epca.environments.dataflow.state import DataFlowState
from epca.runtime.decision import DecisionStatus


@pytest.mark.parametrize("monitor", ["stateful_rule", "epca"])
def test_dataflow_temporal_taint_survives_zone_switch_and_blocks_send(monitor: str) -> None:
    runtime = DataFlowRuntime()
    runtime.create_session(monitor, DataFlowState(clearance=2))
    assert runtime.process({"action": "read_resource", "params": {"resource": "secret_data"}}, principal_id="analyst", session_id=monitor, monitor=monitor).execution.commit_success
    assert runtime.process({"action": "switch_zone", "params": {"zone": "public"}}, principal_id="analyst", session_id=monitor, monitor=monitor).execution.commit_success
    send = runtime.process({"action": "send", "params": {"destination": "public", "resource": "public_report"}}, principal_id="analyst", session_id=monitor, monitor=monitor)
    assert send.evaluated.decision.status == DecisionStatus.BLOCK
    assert runtime.snapshot(monitor).state.session_taint is True
    assert runtime.snapshot(monitor).state.public_exfiltration_count == 0


def test_dataflow_no_guard_materializes_same_exfiltration() -> None:
    runtime = DataFlowRuntime()
    runtime.create_session("no", DataFlowState(clearance=2))
    for payload in (
        {"action": "read_resource", "params": {"resource": "secret_data"}},
        {"action": "switch_zone", "params": {"zone": "public"}},
        {"action": "send", "params": {"destination": "public", "resource": "public_report"}},
    ):
        runtime.process(payload, principal_id="analyst", session_id="no", monitor="no_guard")
    assert runtime.snapshot("no").state.public_exfiltration_count == 1


@pytest.mark.parametrize("monitor", ["stateful_rule", "epca"])
def test_dataflow_clearance_and_sanitization_boundaries(monitor: str) -> None:
    denied = DataFlowRuntime()
    denied.create_session("denied", DataFlowState(clearance=1))
    read = denied.process({"action": "read_resource", "params": {"resource": "secret_data"}}, principal_id="analyst", session_id="denied", monitor=monitor)
    assert read.evaluated.decision.status == DecisionStatus.BLOCK
    allowed = DataFlowRuntime()
    allowed.create_session("allowed", DataFlowState(clearance=2))
    allowed.process({"action": "read_resource", "params": {"resource": "secret_data"}}, principal_id="analyst", session_id="allowed", monitor=monitor)
    allowed.process({"action": "sanitize", "params": {"resource": "secret_data"}}, principal_id="analyst", session_id="allowed", monitor=monitor)
    send = allowed.process({"action": "send", "params": {"destination": "public", "resource": "secret_data"}}, principal_id="analyst", session_id="allowed", monitor=monitor)
    assert send.execution.commit_success
