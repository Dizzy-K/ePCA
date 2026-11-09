from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from epca.runtime.hashing import canonical_json, sha256_digest


NonNegativeInt = Annotated[StrictInt, Field(ge=0)]


class DataFlowState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    current_zone: Literal["internal", "restricted", "public"] = "internal"
    session_taint: StrictBool = False
    principal: StrictStr = "analyst"
    clearance: NonNegativeInt = 2
    resource_classification: tuple[tuple[str, int], ...] = (
        ("public_report", 0),
        ("internal_report", 1),
        ("secret_data", 2),
    )
    sanitized_resources: tuple[str, ...] = ()
    channel: Literal["none", "internal", "partner", "public"] = "none"
    security_invariants_enabled: StrictBool = True
    public_exfiltration_count: NonNegativeInt = 0
    policy_version: StrictStr = "dataflow-policy-v1"
    state_version: NonNegativeInt = 0

    def classification_for(self, resource: str) -> int:
        return dict(self.resource_classification).get(resource, 0)

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @property
    def canonical_serialization(self) -> str:
        return canonical_json(self.canonical_payload)

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_payload)


def initial_dataflow_state(*, policy_version: str = "dataflow-policy-v1") -> DataFlowState:
    return DataFlowState(policy_version=policy_version)
