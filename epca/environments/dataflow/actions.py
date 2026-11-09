from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


Identifier = Annotated[StrictStr, Field(min_length=1, max_length=128)]


class SwitchZoneParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    zone: Literal["internal", "restricted", "public"]


class ReadResourceParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    resource: Identifier


class SanitizeParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    resource: Identifier


class SendParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    destination: Literal["internal", "partner", "public"]
    resource: Identifier


class OpenChannelParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    destination: Literal["internal", "partner", "public"]


class ClearTaintParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ModifyDataPolicyParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target: Literal["security_invariants"]
    value: StrictBool


DATAFLOW_ACTION_SCHEMAS: dict[str, type[BaseModel]] = {
    "switch_zone": SwitchZoneParams,
    "read_resource": ReadResourceParams,
    "sanitize": SanitizeParams,
    "send": SendParams,
    "open_channel": OpenChannelParams,
    "clear_taint": ClearTaintParams,
    "modify_policy": ModifyDataPolicyParams,
}
