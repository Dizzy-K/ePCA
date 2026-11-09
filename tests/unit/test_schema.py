from __future__ import annotations

import pytest
from pydantic import ValidationError

from epca.runtime.action import SchemaValidationError, SchemaValidator
from tests.conftest import transfer_payload


def test_valid_transfer_is_typed_and_immutable() -> None:
    action = SchemaValidator().validate(
        transfer_payload(300),
        principal_id="agent",
        session_id="session-1",
    )
    assert action.action == "transfer"
    assert action.params.amount == 300
    assert len(action.digest) == 64
    with pytest.raises(ValidationError):
        action.params.amount = 301  # type: ignore[misc]


@pytest.mark.parametrize("amount", [-1, 0, 1.5, "300", True, None])
def test_malformed_amount_is_rejected(amount: object) -> None:
    with pytest.raises(SchemaValidationError):
        SchemaValidator().validate(
            transfer_payload(amount),
            principal_id="agent",
            session_id="session-1",
        )


def test_unknown_action_is_rejected() -> None:
    with pytest.raises(SchemaValidationError, match="Unknown action"):
        SchemaValidator().validate(
            {"action": "delete_everything", "params": {}},
            principal_id="agent",
            session_id="session-1",
        )


def test_unknown_root_and_parameter_fields_are_rejected() -> None:
    validator = SchemaValidator()
    with pytest.raises(SchemaValidationError, match="Unknown action fields"):
        validator.validate(
            {**transfer_payload(300), "execute_without_check": True},
            principal_id="agent",
            session_id="session-1",
        )
    with pytest.raises(SchemaValidationError):
        validator.validate(
            {"action": "transfer", "params": {"amount": 300, "recipient": "B", "override": True}},
            principal_id="agent",
            session_id="session-1",
        )


def test_explicit_legacy_proof_fields_are_ignored_before_trusted_action() -> None:
    validator = SchemaValidator()
    plain = validator.validate(
        transfer_payload(300),
        principal_id="agent",
        session_id="session-1",
    )
    decorated = validator.validate(
        {
            **transfer_payload(300),
            "z3_proof_code": "malformed proof",
            "proof": {"safe": True},
            "safe": True,
            "metadata": {"scenario": "attack_meta"},
        },
        principal_id="agent",
        session_id="session-1",
    )
    assert decorated == plain
    assert decorated.digest == plain.digest
    assert "proof" not in decorated.canonical_serialization
