from __future__ import annotations

import ast
from pathlib import Path

import pytest

from epca.environments.cloud_iam.environment import CloudIAMRuntime
from epca.environments.dataflow.environment import DataFlowRuntime
from epca.environments.financial.environment import FinancialRuntime
from epca.runtime.decision import DecisionStatus
from epca.runtime.verifier import EPCAVerifier


def test_pcc_checker_has_no_epca_verifier_import_or_call() -> None:
    path = Path(__file__).parents[2] / "pcc" / "checker.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        if isinstance(node, ast.Attribute):
            assert node.attr != "verify"
    assert "epca.runtime.verifier" not in imported


def test_pcc_still_works_when_epca_verifier_is_unavailable(monkeypatch) -> None:
    def explode(*args, **kwargs):
        raise AssertionError("PCC checker must not call ePCA verifier")

    monkeypatch.setattr(EPCAVerifier, "verify", explode)
    runtime = FinancialRuntime()
    runtime.create_session("independent")
    result = runtime.process({"action": "transfer", "params": {"amount": 300}}, principal_id="agent", session_id="independent", monitor="pcc_action")
    assert result.execution.commit_success


@pytest.mark.parametrize(
    ("runtime", "payload", "principal"),
    [
        (FinancialRuntime(), {"action": "transfer", "params": {"amount": 300}}, "agent"),
        (DataFlowRuntime(), {"action": "switch_zone", "params": {"zone": "restricted"}}, "analyst"),
        (CloudIAMRuntime(), {"action": "read_resource", "params": {"resource": "public_doc"}}, "agent"),
    ],
)
def test_pcc_scenario_label_independence(runtime, payload, principal) -> None:
    runtime.create_session("labels")
    outputs = [runtime.evaluate(payload, principal_id=principal, session_id="labels", monitor="pcc_action", scenario_label=label) for label in ("benign", "attack", "pcc")]
    assert {item.decision.status for item in outputs} == {DecisionStatus.ALLOW}
    assert len({item.decision.reason for item in outputs}) == 1
    assert len({item.decision.context.post_state_digest for item in outputs}) == 1
