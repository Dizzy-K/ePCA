from __future__ import annotations

from dataclasses import dataclass

import z3

from epca.environments.cloud_iam.actions import (
    AssumeRoleParams,
    CreateTokenParams,
    DelegatePermissionParams,
    GrantRoleParams,
    IAMReadResourceParams,
    ModifyIAMPolicyParams,
    RevokeRoleParams,
    ShareResourceParams,
)
from epca.environments.cloud_iam.state import CloudIAMState
from epca.runtime.action import ActionProposal
from epca.runtime.contract import NamedConstraint
from epca.runtime.hashing import canonical_json


COUNTERS = (
    "unauthorized_role_count",
    "unauthorized_delegation_count",
    "overbroad_token_count",
    "unauthorized_read_count",
    "unauthorized_share_count",
)


@dataclass(frozen=True)
class IAMStateSymbols:
    principal: z3.SeqRef
    roles_json: z3.SeqRef
    static_roles_json: z3.SeqRef
    hierarchy_json: z3.SeqRef
    resources_json: z3.SeqRef
    delegations_json: z3.SeqRef
    token_scopes_json: z3.SeqRef
    approval_json: z3.SeqRef
    grants_json: z3.SeqRef
    shares_json: z3.SeqRef
    unauthorized_role_count: z3.ArithRef
    unauthorized_delegation_count: z3.ArithRef
    overbroad_token_count: z3.ArithRef
    unauthorized_read_count: z3.ArithRef
    unauthorized_share_count: z3.ArithRef
    security_invariants_enabled: z3.BoolRef
    policy_version: z3.SeqRef
    state_version: z3.ArithRef


@dataclass(frozen=True)
class IAMSymbols:
    pre: IAMStateSymbols
    post: IAMStateSymbols
    action_name: z3.SeqRef
    role: z3.SeqRef
    target: z3.SeqRef
    permission: z3.SeqRef
    resource: z3.SeqRef
    scopes_json: z3.SeqRef
    value_bool: z3.BoolRef
    principal_id: z3.SeqRef
    session_id: z3.SeqRef
    request_authorized: z3.BoolRef
    active_policy_version: z3.SeqRef
    active_contract_version: z3.SeqRef


def _state(prefix: str) -> IAMStateSymbols:
    return IAMStateSymbols(
        principal=z3.String(f"{prefix}_principal"),
        roles_json=z3.String(f"{prefix}_roles_json"),
        static_roles_json=z3.String(f"{prefix}_static_roles_json"),
        hierarchy_json=z3.String(f"{prefix}_hierarchy_json"),
        resources_json=z3.String(f"{prefix}_resources_json"),
        delegations_json=z3.String(f"{prefix}_delegations_json"),
        token_scopes_json=z3.String(f"{prefix}_token_scopes_json"),
        approval_json=z3.String(f"{prefix}_approval_json"),
        grants_json=z3.String(f"{prefix}_grants_json"),
        shares_json=z3.String(f"{prefix}_shares_json"),
        unauthorized_role_count=z3.Int(f"{prefix}_unauthorized_role_count"),
        unauthorized_delegation_count=z3.Int(f"{prefix}_unauthorized_delegation_count"),
        overbroad_token_count=z3.Int(f"{prefix}_overbroad_token_count"),
        unauthorized_read_count=z3.Int(f"{prefix}_unauthorized_read_count"),
        unauthorized_share_count=z3.Int(f"{prefix}_unauthorized_share_count"),
        security_invariants_enabled=z3.Bool(f"{prefix}_security_invariants_enabled"),
        policy_version=z3.String(f"{prefix}_policy_version"),
        state_version=z3.Int(f"{prefix}_state_version"),
    )


def create_symbols() -> IAMSymbols:
    return IAMSymbols(
        pre=_state("pre"),
        post=_state("post"),
        action_name=z3.String("action_name"),
        role=z3.String("action_role"),
        target=z3.String("action_target"),
        permission=z3.String("action_permission"),
        resource=z3.String("action_resource"),
        scopes_json=z3.String("action_scopes_json"),
        value_bool=z3.Bool("action_value_bool"),
        principal_id=z3.String("action_principal_id"),
        session_id=z3.String("action_session_id"),
        request_authorized=z3.Bool("action_request_authorized"),
        active_policy_version=z3.String("active_policy_version"),
        active_contract_version=z3.String("active_contract_version"),
    )


def _bind_state(prefix: str, s: IAMStateSymbols, state: CloudIAMState) -> tuple[NamedConstraint, ...]:
    scalar = {
        "principal": s.principal == z3.StringVal(state.principal),
        "roles_json": s.roles_json == z3.StringVal(canonical_json(state.roles)),
        "static_roles_json": s.static_roles_json == z3.StringVal(canonical_json(state.static_roles)),
        "hierarchy_json": s.hierarchy_json == z3.StringVal(canonical_json(state.role_hierarchy)),
        "resources_json": s.resources_json == z3.StringVal(canonical_json(state.resource_permissions)),
        "delegations_json": s.delegations_json == z3.StringVal(canonical_json(state.delegations)),
        "token_scopes_json": s.token_scopes_json == z3.StringVal(canonical_json(state.token_scopes)),
        "approval_json": s.approval_json == z3.StringVal(canonical_json(state.approval_state)),
        "grants_json": s.grants_json == z3.StringVal(canonical_json(state.role_grants)),
        "shares_json": s.shares_json == z3.StringVal(canonical_json(state.shared_resources)),
        "security_invariants_enabled": s.security_invariants_enabled == z3.BoolVal(state.security_invariants_enabled),
        "policy_version": s.policy_version == z3.StringVal(state.policy_version),
        "state_version": s.state_version == state.state_version,
    }
    for counter in COUNTERS:
        scalar[counter] = getattr(s, counter) == getattr(state, counter)
    return tuple(NamedConstraint(f"bind::{prefix}::{name}", formula, f"exact {prefix}.{name}") for name, formula in scalar.items())


def _authorized(pre: CloudIAMState, action: ActionProposal) -> bool:
    params = action.params
    permissions = pre.effective_permissions()
    if "*" in permissions:
        return True
    if isinstance(params, AssumeRoleParams):
        return params.role in pre.roles
    if isinstance(params, GrantRoleParams):
        return pre.role_permissions(params.role) <= permissions
    if isinstance(params, DelegatePermissionParams):
        return params.permission in permissions
    if isinstance(params, CreateTokenParams):
        return set(params.scopes) <= permissions
    if isinstance(params, IAMReadResourceParams):
        return pre.required_permission(params.resource) in permissions
    if isinstance(params, ShareResourceParams):
        return params.target in pre.approval_state and pre.authorizes("share:internal")
    if isinstance(params, RevokeRoleParams):
        return params.target == action.principal_id or "admin" in pre.roles
    if isinstance(params, ModifyIAMPolicyParams):
        return action.principal_id == "admin" and "admin" in pre.roles
    return False


def exact_bindings(
    symbols: IAMSymbols,
    *,
    pre_state: CloudIAMState,
    action: ActionProposal,
    post_state: CloudIAMState,
    policy_version: str,
    contract_version: str,
) -> tuple[NamedConstraint, ...]:
    role = target = permission = resource = ""
    scopes: tuple[str, ...] = ()
    value_bool = False
    params = action.params
    if isinstance(params, AssumeRoleParams):
        role = params.role
    elif isinstance(params, (GrantRoleParams, RevokeRoleParams)):
        target, role = params.target, params.role
    elif isinstance(params, DelegatePermissionParams):
        target, permission = params.target, params.permission
    elif isinstance(params, CreateTokenParams):
        scopes = params.scopes
    elif isinstance(params, IAMReadResourceParams):
        resource = params.resource
    elif isinstance(params, ShareResourceParams):
        resource, target = params.resource, params.target
    elif isinstance(params, ModifyIAMPolicyParams):
        target, value_bool = params.target, params.value
    return (
        *_bind_state("pre", symbols.pre, pre_state),
        *_bind_state("post", symbols.post, post_state),
        NamedConstraint("bind::action_name", symbols.action_name == z3.StringVal(action.action), "exact action name"),
        NamedConstraint("bind::role", symbols.role == z3.StringVal(role), "exact role"),
        NamedConstraint("bind::target", symbols.target == z3.StringVal(target), "exact target"),
        NamedConstraint("bind::permission", symbols.permission == z3.StringVal(permission), "exact permission"),
        NamedConstraint("bind::resource", symbols.resource == z3.StringVal(resource), "exact resource"),
        NamedConstraint("bind::scopes_json", symbols.scopes_json == z3.StringVal(canonical_json(scopes)), "exact scopes"),
        NamedConstraint("bind::value_bool", symbols.value_bool == z3.BoolVal(value_bool), "exact policy value"),
        NamedConstraint("bind::principal_id", symbols.principal_id == z3.StringVal(action.principal_id), "exact principal"),
        NamedConstraint("bind::session_id", symbols.session_id == z3.StringVal(action.session_id), "exact session"),
        NamedConstraint("bind::request_authorized", symbols.request_authorized == z3.BoolVal(_authorized(pre_state, action)), "independent exact authorization fact"),
        NamedConstraint("bind::active_policy_version", symbols.active_policy_version == z3.StringVal(policy_version), "exact policy version"),
        NamedConstraint("bind::active_contract_version", symbols.active_contract_version == z3.StringVal(contract_version), "exact contract version"),
        NamedConstraint("bind::state_policy_matches_active", symbols.pre.policy_version == symbols.active_policy_version, "state policy is active"),
    )
