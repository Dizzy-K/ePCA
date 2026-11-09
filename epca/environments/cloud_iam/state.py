from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from epca.runtime.hashing import canonical_json, sha256_digest


NonNegativeInt = Annotated[StrictInt, Field(ge=0)]


class CloudIAMState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    principal: StrictStr = "agent"
    roles: tuple[str, ...] = ("viewer",)
    static_roles: tuple[str, ...] = ("viewer",)
    role_hierarchy: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("viewer", ("read:public",)),
        ("analyst", ("read:public", "read:protected", "share:internal")),
        ("admin", ("*",)),
    )
    resource_permissions: tuple[tuple[str, str], ...] = (
        ("public_doc", "read:public"),
        ("protected_doc", "read:protected"),
    )
    delegations: tuple[tuple[str, str], ...] = ()
    token_scopes: tuple[str, ...] = ()
    approval_state: tuple[str, ...] = ("internal_team",)
    role_grants: tuple[tuple[str, str], ...] = (("agent", "viewer"),)
    shared_resources: tuple[tuple[str, str], ...] = ()
    unauthorized_role_count: NonNegativeInt = 0
    unauthorized_delegation_count: NonNegativeInt = 0
    overbroad_token_count: NonNegativeInt = 0
    unauthorized_read_count: NonNegativeInt = 0
    unauthorized_share_count: NonNegativeInt = 0
    security_invariants_enabled: StrictBool = True
    policy_version: StrictStr = "cloud-iam-policy-v1"
    state_version: NonNegativeInt = 0

    def role_permissions(self, role: str) -> set[str]:
        return set(dict(self.role_hierarchy).get(role, ()))

    def effective_permissions(self) -> set[str]:
        permissions: set[str] = set()
        for role in self.roles:
            permissions.update(self.role_permissions(role))
        permissions.update(permission for target, permission in self.delegations if target == self.principal)
        return permissions

    def authorizes(self, permission: str) -> bool:
        permissions = self.effective_permissions()
        return "*" in permissions or permission in permissions

    def required_permission(self, resource: str) -> str:
        return dict(self.resource_permissions).get(resource, "read:public")

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @property
    def canonical_serialization(self) -> str:
        return canonical_json(self.canonical_payload)

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_payload)


def initial_cloud_iam_state(*, policy_version: str = "cloud-iam-policy-v1") -> CloudIAMState:
    return CloudIAMState(policy_version=policy_version)
