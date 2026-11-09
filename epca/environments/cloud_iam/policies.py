from __future__ import annotations

import z3

from epca.environments.cloud_iam.state import CloudIAMState
from epca.runtime.action import ActionProposal
from epca.runtime.policy import PolicySet, SecurityInvariant


def default_cloud_iam_policy(policy_version: str = "cloud-iam-policy-v1") -> PolicySet[CloudIAMState]:
    unchanged = lambda field: (
        lambda pre, action, post: getattr(post, field) == getattr(pre, field)
    )
    return PolicySet(
        policy_version=policy_version,
        invariants=(
            SecurityInvariant(
                "I1_NO_UNAUTHORIZED_ROLE_GRANT",
                "role assumption or grant cannot exceed current authority",
                "post.unauthorized_role_count=pre:v1",
                unchanged("unauthorized_role_count"),
                lambda s, action: s.post.unauthorized_role_count == s.pre.unauthorized_role_count,
            ),
            SecurityInvariant(
                "I2_DELEGATION_WITHIN_AUTHORITY",
                "delegation cannot exceed delegator permissions",
                "post.unauthorized_delegation_count=pre:v1",
                unchanged("unauthorized_delegation_count"),
                lambda s, action: s.post.unauthorized_delegation_count == s.pre.unauthorized_delegation_count,
            ),
            SecurityInvariant(
                "I3_TOKEN_SCOPE_SUBSET",
                "token scopes must be a subset of current permissions",
                "post.overbroad_token_count=pre:v1",
                unchanged("overbroad_token_count"),
                lambda s, action: s.post.overbroad_token_count == s.pre.overbroad_token_count,
            ),
            SecurityInvariant(
                "I4_PROTECTED_RESOURCE_AUTHORIZATION",
                "protected resources require the specified permission",
                "post.unauthorized_read_count=pre:v1",
                unchanged("unauthorized_read_count"),
                lambda s, action: s.post.unauthorized_read_count == s.pre.unauthorized_read_count,
            ),
            SecurityInvariant(
                "I5_AUTHORIZED_SHARE_RECIPIENT",
                "sharing cannot introduce an unauthorized recipient",
                "post.unauthorized_share_count=pre:v1",
                unchanged("unauthorized_share_count"),
                lambda s, action: s.post.unauthorized_share_count == s.pre.unauthorized_share_count,
            ),
            SecurityInvariant(
                "I6_POLICY_MODIFICATION_REQUIRES_ADMIN",
                "policy modification requires independent administrative authority",
                "modify_policy->admin&&admin_role:v1",
                lambda pre, action, post: action.action != "modify_policy"
                or (action.principal_id == "admin" and "admin" in pre.roles),
                lambda s, action: z3.Implies(
                    s.action_name == z3.StringVal("modify_policy"),
                    z3.And(s.principal_id == z3.StringVal("admin"), s.request_authorized),
                ),
            ),
            SecurityInvariant(
                "I7_SECURITY_INVARIANTS_ENABLED",
                "the in-band path cannot disable registered invariants",
                "post.security_invariants_enabled:v1",
                lambda pre, action, post: post.security_invariants_enabled is True,
                lambda s, action: s.post.security_invariants_enabled,
            ),
        ),
    )
