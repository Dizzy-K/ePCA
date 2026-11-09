from __future__ import annotations

import z3

from epca.environments.dataflow.state import DataFlowState
from epca.runtime.action import ActionProposal
from epca.runtime.policy import PolicySet, SecurityInvariant


def _admin(pre: DataFlowState, action: ActionProposal) -> bool:
    return action.principal_id == "admin" and pre.clearance >= 10


def default_dataflow_policy(policy_version: str = "dataflow-policy-v1") -> PolicySet[DataFlowState]:
    return PolicySet(
        policy_version=policy_version,
        invariants=(
            SecurityInvariant(
                "D0_DOMAIN",
                "clearance and effect counters remain non-negative",
                "post.clearance>=0&&post.exfiltration>=0:v1",
                lambda pre, action, post: post.clearance >= 0 and post.public_exfiltration_count >= 0,
                lambda s, action: z3.And(s.post.clearance >= 0, s.post.public_exfiltration_count >= 0),
            ),
            SecurityInvariant(
                "D1_CLASSIFIED_READ_REQUIRES_CLEARANCE",
                "classified resource reads require sufficient clearance",
                "read->classification<=clearance:v1",
                lambda pre, action, post: action.action != "read_resource"
                or pre.classification_for(getattr(action.params, "resource", "")) <= pre.clearance,
                lambda s, action: z3.Implies(
                    s.action_name == z3.StringVal("read_resource"),
                    s.resource_classification <= s.pre.clearance,
                ),
            ),
            SecurityInvariant(
                "D2_CLASSIFIED_READ_PROPAGATES_TAINT",
                "reading classified data propagates session taint",
                "read(classified)->post.taint:v1",
                lambda pre, action, post: not (
                    action.action == "read_resource"
                    and pre.classification_for(getattr(action.params, "resource", "")) > 0
                )
                or post.session_taint,
                lambda s, action: z3.Implies(
                    z3.And(s.action_name == z3.StringVal("read_resource"), s.resource_classification > 0),
                    s.post.session_taint,
                ),
            ),
            SecurityInvariant(
                "D3_NO_PUBLIC_TAINT_FLOW",
                "a transition cannot materialize new public tainted output",
                "post.exfiltration==pre.exfiltration:v1",
                lambda pre, action, post: post.public_exfiltration_count == pre.public_exfiltration_count,
                lambda s, action: s.post.public_exfiltration_count == s.pre.public_exfiltration_count,
            ),
            SecurityInvariant(
                "D4_TAINT_CLEAR_REQUIRES_ADMIN",
                "ordinary principals cannot clear security taint",
                "clear_taint->admin:v1",
                lambda pre, action, post: action.action != "clear_taint" or _admin(pre, action),
                lambda s, action: z3.Implies(
                    s.action_name == z3.StringVal("clear_taint"),
                    z3.And(s.principal_id == z3.StringVal("admin"), s.pre.clearance >= 10),
                ),
            ),
            SecurityInvariant(
                "D5_POLICY_MODIFICATION_REQUIRES_ADMIN",
                "ordinary principals cannot modify data-flow policy",
                "modify_policy->admin:v1",
                lambda pre, action, post: action.action != "modify_policy" or _admin(pre, action),
                lambda s, action: z3.Implies(
                    s.action_name == z3.StringVal("modify_policy"),
                    z3.And(s.principal_id == z3.StringVal("admin"), s.pre.clearance >= 10),
                ),
            ),
            SecurityInvariant(
                "D6_ZONE_SWITCH_PRESERVES_TAINT",
                "switching zone cannot erase information-flow history",
                "switch_zone->post.taint=pre.taint:v1",
                lambda pre, action, post: action.action != "switch_zone" or post.session_taint == pre.session_taint,
                lambda s, action: z3.Implies(
                    s.action_name == z3.StringVal("switch_zone"),
                    s.post.session_taint == s.pre.session_taint,
                ),
            ),
            SecurityInvariant(
                "D7_SECURITY_INVARIANTS_ENABLED",
                "the in-band path cannot disable registered invariants",
                "post.security_invariants_enabled:v1",
                lambda pre, action, post: post.security_invariants_enabled is True,
                lambda s, action: s.post.security_invariants_enabled,
            ),
        ),
    )
