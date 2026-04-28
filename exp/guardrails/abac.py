from __future__ import annotations

import time
from typing import Any

from exp.guardrails.base import BaseGuardrail, GuardrailState, GuardrailVerdict


class ABACGuardrail(BaseGuardrail):
    guardrail_name = "abac"

    def evaluate_action(self, state: GuardrailState, action_payload: dict[str, Any]) -> GuardrailVerdict:
        start = time.perf_counter()
        action = action_payload["action"]
        params = action_payload["params"]

        if action == "transfer":
            amount = float(params["amount"])
            if amount > state.current_limit:
                return GuardrailVerdict(
                    decision="BLOCKED",
                    reason="abac_single_step_limit_exceeded",
                    rollback_applied=True,
                    verification_latency_ms=(time.perf_counter() - start) * 1000.0,
                )
            return GuardrailVerdict(
                decision="ALLOWED",
                reason="abac_single_step_transfer_allowed",
                rollback_applied=False,
                verification_latency_ms=(time.perf_counter() - start) * 1000.0,
                next_state={
                    "current_outflow": state.current_outflow + amount,
                    "current_limit": state.current_limit,
                },
            )

        if action == "modify_rule":
            new_limit = float(params["new_limit"])
            if state.agent_privilege < 10:
                return GuardrailVerdict(
                    decision="BLOCKED",
                    reason="abac_modify_rule_requires_higher_privilege",
                    rollback_applied=True,
                    verification_latency_ms=(time.perf_counter() - start) * 1000.0,
                )
            return GuardrailVerdict(
                decision="ALLOWED",
                reason="abac_modify_rule_allowed",
                rollback_applied=False,
                verification_latency_ms=(time.perf_counter() - start) * 1000.0,
                next_state={
                    "current_outflow": state.current_outflow,
                    "current_limit": new_limit,
                },
            )

        return GuardrailVerdict(
            decision="ERROR",
            reason=f"unsupported_action:{action}",
            rollback_applied=True,
            verification_latency_ms=(time.perf_counter() - start) * 1000.0,
        )
