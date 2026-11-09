from __future__ import annotations

from epca.environments.cloud_iam.actions import (
    AssumeRoleParams,
    CreateTokenParams,
    DelegatePermissionParams,
    GrantRoleParams,
    IAMReadResourceParams,
    ShareResourceParams,
)
from epca.environments.cloud_iam.state import CloudIAMState
from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, TimingBreakdown, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import StateSnapshot
from epca.runtime.verifier import DecisionIssuer


class CloudIAMStatelessRuleFilter(Guardrail[CloudIAMState]):
    """Strong request-local IAM checks using only static principal/resource attributes."""

    name = "stateless_rule_filter"

    def __init__(self, issuer: DecisionIssuer[CloudIAMState]) -> None:
        self.issuer = issuer

    @staticmethod
    def _static_permissions(state: CloudIAMState, principal: str) -> set[str]:
        permissions: set[str] = set()
        for role in state.static_roles:
            permissions.update(state.role_permissions(role))
        return permissions

    def evaluate(
        self,
        *,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[CloudIAMState],
        action: ActionProposal,
        contract: ActionContract[CloudIAMState],
        policy: PolicySet[CloudIAMState],
        base_timings: TimingBreakdown,
        request_started: float,
    ) -> VerificationDecision:
        state = snapshot.state
        permissions = self._static_permissions(state, action.principal_id)
        wildcard = "*" in permissions
        allow = True
        reason = "stateless_rule_allowed"
        violated: tuple[str, ...] = ()
        params = action.params
        if isinstance(params, AssumeRoleParams):
            allow = params.role == ("admin" if action.principal_id == "admin" else "viewer")
            violated = () if allow else ("I1_NO_UNAUTHORIZED_ROLE_GRANT",)
        elif isinstance(params, GrantRoleParams):
            allow = wildcard or state.role_permissions(params.role) <= permissions
            violated = () if allow else ("I1_NO_UNAUTHORIZED_ROLE_GRANT",)
        elif isinstance(params, DelegatePermissionParams):
            allow = wildcard or params.permission in permissions
            violated = () if allow else ("I2_DELEGATION_WITHIN_AUTHORITY",)
        elif isinstance(params, CreateTokenParams):
            allow = wildcard or set(params.scopes) <= permissions
            violated = () if allow else ("I3_TOKEN_SCOPE_SUBSET",)
        elif isinstance(params, IAMReadResourceParams):
            allow = wildcard or state.required_permission(params.resource) in permissions
            violated = () if allow else ("I4_PROTECTED_RESOURCE_AUTHORIZATION",)
        elif isinstance(params, ShareResourceParams):
            allow = (wildcard or "share:internal" in permissions) and params.target in state.approval_state
            violated = () if allow else ("I5_AUTHORIZED_SHARE_RECIPIENT",)
        elif action.action == "modify_policy":
            allow = action.principal_id == "admin"
            violated = () if allow else ("I6_POLICY_MODIFICATION_REQUIRES_ADMIN",)
        if not allow:
            reason = "stateless_direct_policy_violation"
        return self.issuer.from_rule(
            monitor=self.name,
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            allow=allow,
            reason=reason,
            violated_invariants=violated,
            base_timings=base_timings,
            request_started=request_started,
        )
