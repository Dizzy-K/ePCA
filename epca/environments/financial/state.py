from __future__ import annotations

from typing import Any, Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from epca.runtime.hashing import canonical_json, sha256_digest


NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]


class FinancialState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cumulative_outflow: NonNegativeInt = 0
    daily_limit: PositiveInt = 500
    privilege: NonNegativeInt = 1
    approval_threshold: PositiveInt = 500
    pending_approval_amount: NonNegativeInt = 0
    approval_requester: StrictStr = ""
    approved_amount: NonNegativeInt = 0
    approver: StrictStr = ""
    delegated_limit: NonNegativeInt = 0
    delegate_target: StrictStr = ""
    security_invariants_enabled: StrictBool = True
    policy_version: StrictStr = "financial-policy-v1"
    state_version: NonNegativeInt = 0

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @property
    def canonical_serialization(self) -> str:
        return canonical_json(self.canonical_payload)

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_payload)


def initial_financial_state(*, policy_version: str = "financial-policy-v1") -> FinancialState:
    return FinancialState(policy_version=policy_version)
