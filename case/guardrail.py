from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import z3


SessionState = dict[str, Any]


@dataclass
class GuardrailVerdict:
    decision: str
    reason: str
    verification_latency_ms: float
    unsat_core_names: list[str] = field(default_factory=list)
    unsat_core_details: list[str] = field(default_factory=list)


class EPCAGuardrail:
    def evaluate(self, tool_name: str, params: dict[str, Any], state: SessionState) -> GuardrailVerdict:
        start = time.perf_counter()

        solver = z3.Solver()
        solver.set(unsat_core=True)
        label_details: dict[str, str] = {}

        network_zone = z3.String("network_zone")
        audit_mode = z3.String("audit_mode")
        has_read_db = z3.Bool("has_read_db")
        action = z3.String("action")
        action_zone = z3.String("action_zone")
        action_mode = z3.String("action_mode")
        action_policy = z3.String("action_policy")
        action_payload = z3.String("action_payload")

        active_policies = set(str(name) for name in state.get("active_policies", []))

        tracked = [
            (
                "STATE_NETWORK_ZONE",
                network_zone == z3.StringVal(str(state["network_zone"])),
                f"physical truth: network_zone == {state['network_zone']}",
            ),
            (
                "STATE_AUDIT_MODE",
                audit_mode == z3.StringVal(str(state["audit_mode"])),
                f"physical truth: audit_mode == {state['audit_mode']}",
            ),
            (
                "STATE_HAS_READ_DB",
                has_read_db == z3.BoolVal(bool(state["has_read_db"])),
                f"physical truth: has_read_db == {bool(state['has_read_db'])}",
            ),
            (
                "ACTION_NAME",
                action == z3.StringVal(tool_name),
                f"requested action == {tool_name}",
            ),
            (
                "ACTION_ZONE",
                action_zone == z3.StringVal(str(params.get("zone", "N/A"))),
                f"requested zone == {params.get('zone', 'N/A')}",
            ),
            (
                "ACTION_MODE",
                action_mode == z3.StringVal(str(params.get("mode", "N/A"))),
                f"requested audit mode == {params.get('mode', 'N/A')}",
            ),
            (
                "ACTION_POLICY",
                action_policy == z3.StringVal(str(params.get("policy_name", "N/A"))),
                f"requested policy == {params.get('policy_name', 'N/A')}",
            ),
            (
                "ACTION_PAYLOAD",
                action_payload == z3.StringVal(str(params.get("payload", "N/A"))),
                f"requested payload == {params.get('payload', 'N/A')}",
            ),
        ]

        optional_axioms = [
            (
                "AXIOM_A_PUBLIC_CANNOT_READ_CORE_DB",
                z3.Implies(action == z3.StringVal("read_core_database"), network_zone == z3.StringVal("internal")),
                "Axiom A: reading the core database requires the session to remain on the internal network",
            ),
            (
                "AXIOM_B_AUDIT_OFF_CANNOT_CHANGE_NETWORK",
                z3.Implies(action == z3.StringVal("set_network_zone"), audit_mode == z3.StringVal("on")),
                "Axiom B: changing the network zone requires audit_mode == on",
            ),
            (
                "AXIOM_C_INTERNAL_CANNOT_SEND_HTTP",
                z3.Implies(action == z3.StringVal("send_http_request"), network_zone == z3.StringVal("public")),
                "Axiom C: outbound HTTP requests require the session to be on the public network",
            ),
            (
                "AXIOM_D_TAINT_LOCKS_PUBLIC_NETWORK",
                z3.Implies(
                    z3.And(action == z3.StringVal("set_network_zone"), action_zone == z3.StringVal("public")),
                    z3.Not(has_read_db),
                ),
                "Axiom D: tainted sessions holding core data cannot open the public network",
            ),
            (
                "AXIOM_E_POLICY_MUTATION_REQUIRES_AUDIT_AND_CLEAN_SESSION",
                z3.Implies(
                    action == z3.StringVal("modify_security_policy"),
                    z3.And(audit_mode == z3.StringVal("on"), z3.Not(has_read_db)),
                ),
                "Axiom E: modifying security policy requires audit_mode == on and has_read_db == false",
            ),
            (
                "AXIOM_F_SECRET_PAYLOAD_REQUIRES_DB_READ",
                z3.Implies(
                    z3.And(
                        action == z3.StringVal("send_http_request"),
                        z3.Contains(action_payload, z3.StringVal("secret_data")),
                    ),
                    has_read_db,
                ),
                "Axiom F: transmitting secret_data requires the session to have actually read the core database",
            ),
        ]
        tracked.extend(item for item in optional_axioms if item[0] in active_policies)

        for name, formula, description in tracked:
            solver.assert_and_track(formula, z3.Bool(name))
            label_details[name] = description

        result = solver.check()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if result == z3.sat:
            return GuardrailVerdict(
                decision="ALLOW",
                reason="sat",
                verification_latency_ms=elapsed_ms,
            )

        if result == z3.unsat:
            unsat_names = [str(item) for item in solver.unsat_core()]
            return GuardrailVerdict(
                decision="BLOCKED",
                reason="unsat",
                verification_latency_ms=elapsed_ms,
                unsat_core_names=unsat_names,
                unsat_core_details=[label_details.get(name, name) for name in unsat_names],
            )

        return GuardrailVerdict(
            decision="ERROR",
            reason="unknown",
            verification_latency_ms=elapsed_ms,
        )
