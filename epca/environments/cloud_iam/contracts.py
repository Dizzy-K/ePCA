from __future__ import annotations

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
from epca.environments.cloud_iam.formal import IAMSymbols, _authorized
from epca.environments.cloud_iam.state import CloudIAMState
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract, ContractRegistry, NamedConstraint


def _frame(symbols: IAMSymbols, *, exclude: set[str]) -> list[z3.BoolRef]:
    names = (
        "principal",
        "roles_json",
        "static_roles_json",
        "hierarchy_json",
        "resources_json",
        "delegations_json",
        "token_scopes_json",
        "approval_json",
        "grants_json",
        "shares_json",
        "unauthorized_role_count",
        "unauthorized_delegation_count",
        "overbroad_token_count",
        "unauthorized_read_count",
        "unauthorized_share_count",
        "security_invariants_enabled",
        "policy_version",
    )
    return [getattr(symbols.post, name) == getattr(symbols.pre, name) for name in names if name not in exclude]


def _compiled(
    action_name: str,
    description: str,
    symbols: IAMSymbols,
    *,
    exclude: set[str],
    terms: tuple[z3.BoolRef, ...] = (),
) -> tuple[NamedConstraint, ...]:
    return (
        NamedConstraint(
            f"contract::{action_name}",
            z3.And(
                symbols.action_name == z3.StringVal(action_name),
                symbols.post.state_version == symbols.pre.state_version + 1,
                *terms,
                *_frame(symbols, exclude=exclude),
            ),
            description,
        ),
    )


def _increment(symbols: IAMSymbols, counter: str) -> z3.BoolRef:
    return getattr(symbols.post, counter) == getattr(symbols.pre, counter) + z3.If(symbols.request_authorized, 0, 1)


class AssumeRoleContract(ActionContract[CloudIAMState]):
    action_name = "assume_role"
    contract_version = "cloud-iam-assume-role-v1"
    semantics_id = "iam.assume_role:add_role_and_record_unauthorized:v1"
    parameter_model = AssumeRoleParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        params = action.params
        assert isinstance(params, AssumeRoleParams)
        roles = tuple(sorted(set((*pre_state.roles, params.role))))
        return pre_state.model_copy(update={"roles": roles, "unauthorized_role_count": pre_state.unauthorized_role_count + int(not _authorized(pre_state, action)), "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "assume_role adds the exact role and records unauthorized elevation", s, exclude={"roles_json", "unauthorized_role_count"}, terms=(_increment(s, "unauthorized_role_count"),))


class GrantRoleContract(ActionContract[CloudIAMState]):
    action_name = "grant_role"
    contract_version = "cloud-iam-grant-role-v1"
    semantics_id = "iam.grant_role:add_grant_and_record_excess:v1"
    parameter_model = GrantRoleParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        params = action.params
        assert isinstance(params, GrantRoleParams)
        grants = tuple(sorted(set((*pre_state.role_grants, (params.target, params.role)))))
        roles = pre_state.roles
        if params.target == pre_state.principal:
            roles = tuple(sorted(set((*roles, params.role))))
        return pre_state.model_copy(update={"role_grants": grants, "roles": roles, "unauthorized_role_count": pre_state.unauthorized_role_count + int(not _authorized(pre_state, action)), "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "grant_role records the exact grant and excess-authority effect", s, exclude={"roles_json", "grants_json", "unauthorized_role_count"}, terms=(_increment(s, "unauthorized_role_count"),))


class DelegatePermissionContract(ActionContract[CloudIAMState]):
    action_name = "delegate_permission"
    contract_version = "cloud-iam-delegate-permission-v1"
    semantics_id = "iam.delegate:add_permission_and_record_excess:v1"
    parameter_model = DelegatePermissionParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        params = action.params
        assert isinstance(params, DelegatePermissionParams)
        delegations = tuple(sorted(set((*pre_state.delegations, (params.target, params.permission)))))
        return pre_state.model_copy(update={"delegations": delegations, "unauthorized_delegation_count": pre_state.unauthorized_delegation_count + int(not _authorized(pre_state, action)), "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "delegation records the exact permission and excess-authority effect", s, exclude={"delegations_json", "unauthorized_delegation_count"}, terms=(_increment(s, "unauthorized_delegation_count"),))


class CreateTokenContract(ActionContract[CloudIAMState]):
    action_name = "create_token"
    contract_version = "cloud-iam-create-token-v1"
    semantics_id = "iam.create_token:set_scopes_and_record_overbreadth:v1"
    parameter_model = CreateTokenParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        params = action.params
        assert isinstance(params, CreateTokenParams)
        return pre_state.model_copy(update={"token_scopes": tuple(sorted(params.scopes)), "overbroad_token_count": pre_state.overbroad_token_count + int(not _authorized(pre_state, action)), "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "token creation binds exact scopes and records overbreadth", s, exclude={"token_scopes_json", "overbroad_token_count"}, terms=(_increment(s, "overbroad_token_count"),))


class ReadResourceContract(ActionContract[CloudIAMState]):
    action_name = "read_resource"
    contract_version = "cloud-iam-read-resource-v1"
    semantics_id = "iam.read_resource:record_unauthorized_read:v1"
    parameter_model = IAMReadResourceParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        return pre_state.model_copy(update={"unauthorized_read_count": pre_state.unauthorized_read_count + int(not _authorized(pre_state, action)), "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "read records an unauthorized protected-resource effect", s, exclude={"unauthorized_read_count"}, terms=(_increment(s, "unauthorized_read_count"),))


class ShareResourceContract(ActionContract[CloudIAMState]):
    action_name = "share_resource"
    contract_version = "cloud-iam-share-resource-v1"
    semantics_id = "iam.share_resource:add_share_and_record_unauthorized_recipient:v1"
    parameter_model = ShareResourceParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        params = action.params
        assert isinstance(params, ShareResourceParams)
        shares = tuple(sorted(set((*pre_state.shared_resources, (params.resource, params.target)))))
        return pre_state.model_copy(update={"shared_resources": shares, "unauthorized_share_count": pre_state.unauthorized_share_count + int(not _authorized(pre_state, action)), "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "sharing records the exact recipient and unauthorized effect", s, exclude={"shares_json", "unauthorized_share_count"}, terms=(_increment(s, "unauthorized_share_count"),))


class RevokeRoleContract(ActionContract[CloudIAMState]):
    action_name = "revoke_role"
    contract_version = "cloud-iam-revoke-role-v1"
    semantics_id = "iam.revoke_role:remove_exact_grant:v1"
    parameter_model = RevokeRoleParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        params = action.params
        assert isinstance(params, RevokeRoleParams)
        grants = tuple(item for item in pre_state.role_grants if item != (params.target, params.role))
        roles = pre_state.roles
        if params.target == pre_state.principal:
            roles = tuple(role for role in roles if role != params.role)
        return pre_state.model_copy(update={"role_grants": grants, "roles": roles, "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "revoke_role removes only the exact role grant", s, exclude={"roles_json", "grants_json"})


class ModifyIAMPolicyContract(ActionContract[CloudIAMState]):
    action_name = "modify_policy"
    contract_version = "cloud-iam-modify-policy-v1"
    semantics_id = "iam.modify_policy:set_security_invariants_flag:v1"
    parameter_model = ModifyIAMPolicyParams

    def transition(self, pre_state: CloudIAMState, action: ActionProposal) -> CloudIAMState:
        if not self.accepts(action):
            raise TypeError("incompatible action")
        params = action.params
        assert isinstance(params, ModifyIAMPolicyParams)
        return pre_state.model_copy(update={"security_invariants_enabled": params.value, "state_version": pre_state.state_version + 1})

    def compile_transition(self, s: IAMSymbols, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return _compiled(self.action_name, "modify_policy changes only the security flag", s, exclude={"security_invariants_enabled"}, terms=(s.post.security_invariants_enabled == s.value_bool,))


def cloud_iam_contract_registry() -> ContractRegistry[CloudIAMState]:
    return ContractRegistry(
        (
            AssumeRoleContract(),
            GrantRoleContract(),
            DelegatePermissionContract(),
            CreateTokenContract(),
            ReadResourceContract(),
            ShareResourceContract(),
            RevokeRoleContract(),
            ModifyIAMPolicyContract(),
        )
    )
