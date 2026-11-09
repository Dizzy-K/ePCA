from __future__ import annotations

import pytest

from epca.environments.cloud_iam.actions import CLOUD_IAM_ACTION_SCHEMAS
from epca.environments.dataflow.actions import DATAFLOW_ACTION_SCHEMAS
from epca.environments.financial.actions import FINANCIAL_ACTION_SCHEMAS
from epca.runtime.action import SchemaValidationError, SchemaValidator


@pytest.mark.parametrize(
    ("schemas", "payload", "action_name"),
    [
        (FINANCIAL_ACTION_SCHEMAS, {"action": "request_approval", "params": {"amount": 300}}, "request_approval"),
        (DATAFLOW_ACTION_SCHEMAS, {"action": "switch_zone", "params": {"zone": "public"}}, "switch_zone"),
        (CLOUD_IAM_ACTION_SCHEMAS, {"action": "create_token", "params": {"scopes": ["read:public"]}}, "create_token"),
    ],
)
def test_environment_schema_registries_accept_typed_local_actions(schemas, payload, action_name) -> None:
    action = SchemaValidator(schemas).validate(payload, principal_id="agent", session_id="s")
    assert action.action == action_name
    assert action.params.model_dump()


def test_schema_registries_reject_cross_environment_actions() -> None:
    with pytest.raises(SchemaValidationError, match="Unknown action"):
        SchemaValidator(DATAFLOW_ACTION_SCHEMAS).validate(
            {"action": "grant_role", "params": {"target": "agent", "role": "admin"}},
            principal_id="agent",
            session_id="s",
        )
    with pytest.raises(SchemaValidationError, match="Unknown action"):
        SchemaValidator(CLOUD_IAM_ACTION_SCHEMAS).validate(
            {"action": "transfer", "params": {"amount": 1}},
            principal_id="agent",
            session_id="s",
        )


def test_phase1_default_schema_surface_is_preserved() -> None:
    action = SchemaValidator().validate(
        {"action": "transfer", "params": {"amount": 1}}, principal_id="agent", session_id="s"
    )
    assert action.action == "transfer"
    with pytest.raises(SchemaValidationError):
        SchemaValidator().validate(
            {"action": "switch_zone", "params": {"zone": "public"}}, principal_id="agent", session_id="s"
        )
