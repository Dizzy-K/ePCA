from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, model_validator


Identifier = Annotated[StrictStr, Field(min_length=1, max_length=128)]


class AssumeRoleParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    role: Literal["viewer", "analyst", "admin"]


class GrantRoleParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target: Identifier
    role: Literal["viewer", "analyst", "admin"]


class DelegatePermissionParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target: Identifier
    permission: Identifier


class CreateTokenParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scopes: tuple[Identifier, ...]

    @model_validator(mode="after")
    def validate_scopes(self) -> Self:
        if not self.scopes or len(set(self.scopes)) != len(self.scopes):
            raise ValueError("scopes must be a non-empty unique tuple")
        return self


class IAMReadResourceParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    resource: Identifier


class ShareResourceParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    resource: Identifier
    target: Identifier


class RevokeRoleParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target: Identifier
    role: Literal["viewer", "analyst", "admin"]


class ModifyIAMPolicyParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target: Literal["security_invariants"]
    value: StrictBool


CLOUD_IAM_ACTION_SCHEMAS: dict[str, type[BaseModel]] = {
    "assume_role": AssumeRoleParams,
    "grant_role": GrantRoleParams,
    "delegate_permission": DelegatePermissionParams,
    "create_token": CreateTokenParams,
    "read_resource": IAMReadResourceParams,
    "share_resource": ShareResourceParams,
    "revoke_role": RevokeRoleParams,
    "modify_policy": ModifyIAMPolicyParams,
}
