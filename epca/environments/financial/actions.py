from epca.runtime.action import (
    ActionProposal,
    EscalatePrivilegeParams,
    ModifyPolicyParams,
    TransferParams,
)
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr


PositiveInt = Annotated[StrictInt, Field(gt=0)]
Identifier = Annotated[StrictStr, Field(min_length=1, max_length=128)]


class RequestApprovalParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    amount: PositiveInt


class ApproveParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    amount: PositiveInt
    requester: Identifier


class DelegateParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target: Identifier
    amount: PositiveInt


FINANCIAL_ACTION_SCHEMAS: dict[str, type[BaseModel]] = {
    "transfer": TransferParams,
    "request_approval": RequestApprovalParams,
    "approve": ApproveParams,
    "delegate": DelegateParams,
    "modify_policy": ModifyPolicyParams,
    "escalate_privilege": EscalatePrivilegeParams,
}

__all__ = [
    "ActionProposal",
    "ApproveParams",
    "DelegateParams",
    "EscalatePrivilegeParams",
    "FINANCIAL_ACTION_SCHEMAS",
    "ModifyPolicyParams",
    "RequestApprovalParams",
    "TransferParams",
]
