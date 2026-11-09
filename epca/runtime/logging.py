from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, ExecutionResult, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import CanonicalState, StateSnapshot


class StructuredTraceLogger:
    """Thread-safe JSONL logger for one complete monitor/execution decision record."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.records: list[dict[str, Any]] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[CanonicalState],
        action: ActionProposal,
        post_state: CanonicalState,
        contract: ActionContract[Any],
        policy: PolicySet[Any],
        decision: VerificationDecision,
        execution: ExecutionResult,
    ) -> dict[str, Any]:
        context = decision.context
        timings = decision.timings.canonical_payload
        timings.update(
            {
                "binding_ms": timings["binding_ms"] + execution.binding_ms,
                "execution_ms": execution.execution_ms,
                "state_commit_ms": execution.state_commit_ms,
            }
        )
        record = {
            "run_id": evaluation.run_id,
            "decision_id": context.decision_id if context is not None else execution.decision_id,
            "environment": evaluation.environment,
            "session": action.session_id,
            "principal": action.principal_id,
            "pre_state": snapshot.state.canonical_payload,
            "pre_state_hash": snapshot.state_digest,
            "state_version": snapshot.state_version,
            "action": action.canonical_payload,
            "action_digest": action.digest,
            "contract_version": contract.contract_version,
            "contract_digest": contract.contract_digest,
            "policy_version": policy.policy_version,
            "policy_digest": policy.policy_digest,
            "derived_post_state": post_state.canonical_payload,
            "post_state_digest": post_state.digest,
            "solver_result": decision.solver_result,
            "decision": decision.status.value,
            "decision_reason": decision.reason,
            "violated_invariants": list(decision.violated_invariants),
            "executed": execution.executed,
            "commit_success": execution.commit_success,
            "new_state_version": execution.new_state_version,
            "timings_ms": timings,
            "error": decision.error or execution.error,
            "api_error": None,
            "metadata": {
                "monitor": context.monitor if context is not None else None,
                "scenario_label": evaluation.scenario_label,
                "evaluation_metadata": dict(evaluation.metadata),
                "execution_reason": execution.reason,
            },
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False)
        with self._lock:
            self.records.append(record)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        return record
