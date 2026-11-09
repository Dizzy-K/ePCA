from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializeAsAny,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

from epca.runtime.hashing import canonical_json, sha256_digest


PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
Identifier = Annotated[StrictStr, Field(min_length=1, max_length=128)]


class TransferParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    amount: PositiveInt
    recipient: Identifier = "account_B"


class ModifyPolicyParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    target: Literal["daily_limit", "security_invariants"]
    value: StrictInt | StrictBool

    @model_validator(mode="after")
    def validate_target_value(self) -> Self:
        if self.target == "daily_limit":
            if type(self.value) is not int or self.value <= 0:
                raise ValueError("daily_limit requires a positive integer value")
        elif type(self.value) is not bool:
            raise ValueError("security_invariants requires a boolean value")
        return self


class EscalatePrivilegeParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    new_privilege: NonNegativeInt


TypedParams = TransferParams | ModifyPolicyParams | EscalatePrivilegeParams


class ActionProposal(BaseModel):
    """Immutable, schema-validated action entering the trusted plane."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Identifier
    params: SerializeAsAny[BaseModel]
    principal_id: Identifier
    session_id: Identifier

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "params": self.params.model_dump(mode="json"),
            "principal_id": self.principal_id,
            "session_id": self.session_id,
        }

    @property
    def canonical_serialization(self) -> str:
        return canonical_json(self.canonical_payload)

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_payload)


class SchemaValidationError(ValueError):
    pass


class SchemaValidator:
    """Strict validator with an explicit ignored legacy-proof compatibility surface."""

    _trusted_root_fields = {"action", "params", "principal_id", "session_id"}
    _ignored_untrusted_fields = {
        "z3_proof_code",
        "proof",
        "certificate",
        "safe",
        "metadata",
        "scenario_label",
    }

    def __init__(self, schemas: Mapping[str, type[BaseModel]] | None = None) -> None:
        self._schemas = dict(
            schemas
            or {
                "transfer": TransferParams,
                "modify_policy": ModifyPolicyParams,
                "escalate_privilege": EscalatePrivilegeParams,
            }
        )

    def validate(
        self,
        payload: dict[str, Any],
        *,
        principal_id: str | None = None,
        session_id: str | None = None,
    ) -> ActionProposal:
        if not isinstance(payload, dict):
            raise SchemaValidationError("Action payload must be an object")

        unknown = set(payload) - self._trusted_root_fields - self._ignored_untrusted_fields
        if unknown:
            raise SchemaValidationError(f"Unknown action fields: {sorted(unknown)}")

        action = payload.get("action")
        raw_params = payload.get("params")
        if not isinstance(action, str):
            raise SchemaValidationError("action must be a string")
        if not isinstance(raw_params, dict):
            raise SchemaValidationError("params must be an object")

        try:
            params_model = self._schemas[action]
        except KeyError:
            raise SchemaValidationError(f"Unknown action: {action!r}")

        trusted = {
            "action": action,
            "params": raw_params,
            "principal_id": principal_id if principal_id is not None else payload.get("principal_id"),
            "session_id": session_id if session_id is not None else payload.get("session_id"),
        }
        try:
            trusted["params"] = params_model.model_validate(raw_params)
            return ActionProposal.model_validate(trusted)
        except ValidationError as exc:
            raise SchemaValidationError(str(exc)) from exc
