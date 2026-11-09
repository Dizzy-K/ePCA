from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

from epca.environments.cloud_iam.environment import CloudIAMRuntime
from epca.environments.cloud_iam.state import CloudIAMState
from epca.environments.dataflow.environment import DataFlowRuntime
from epca.environments.dataflow.state import DataFlowState
from epca.environments.financial.environment import FinancialRuntime
from epca.environments.financial.state import FinancialState
from epca.runtime.action import SchemaValidationError
from epca.runtime.decision import DecisionStatus
from evaluation.oracles import cloud_iam as iam_oracle
from evaluation.oracles import dataflow as dataflow_oracle
from evaluation.oracles import financial as financial_oracle


PHASE2_CONDITIONS = {
    "NoGuard": "no_guard",
    "StatelessRuleFilter": "stateless_rule_filter",
    "StatefulRuleMonitor": "stateful_rule",
    "ePCA": "epca",
}
CONDITIONS = PHASE2_CONDITIONS
PHASE3_CONDITIONS = {
    "StatefulRuleMonitor": "stateful_rule",
    "PCC-Action": "pcc_action",
    "ePCA": "epca",
}
BENIGN = {"benign_standard", "benign_boundary"}
RUNTIMES = {
    "financial": (FinancialRuntime, FinancialState),
    "dataflow": (DataFlowRuntime, DataFlowState),
    "cloud_iam": (CloudIAMRuntime, CloudIAMState),
}
ORACLES = {
    "financial": financial_oracle,
    "dataflow": dataflow_oracle,
    "cloud_iam": iam_oracle,
}


def create_runtime(
    environment: str,
    initial_state: Any | None = None,
    policy_version: str | None = None,
) -> Any:
    runtime_cls, _ = RUNTIMES[environment]
    if environment == "financial":
        active_version = policy_version or getattr(initial_state, "policy_version", "financial-policy-v1")
        return runtime_cls(policy_version=active_version)
    return runtime_cls()


def load_traces(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _state(runtime: Any, session_id: str) -> Any:
    return runtime.snapshot(session_id).state


def _oracle_action(runtime: Any, oracle: Any, session_id: str, principal: str, payload: dict[str, Any]) -> tuple[Any, Any, Any]:
    pre = _state(runtime, session_id)
    action = runtime.validator.validate(payload, principal_id=principal, session_id=session_id)
    post = oracle.reference_transition(pre, action)
    return action, post, oracle.assess_transition(pre, action, post)


def run_trace(trace: dict[str, Any], condition: str, *, conditions: dict[str, str] = PHASE2_CONDITIONS) -> dict[str, Any]:
    monitor = conditions[condition]
    _, state_cls = RUNTIMES[trace["environment"]]
    oracle = ORACLES[trace["environment"]]
    session_id = f"{trace['trace_id']}::{condition}"
    initial = state_cls.model_validate(trace["initial_state"])
    runtime = create_runtime(trace["environment"], initial)
    runtime.create_session(session_id, initial)
    saved: dict[str, Any] = {}
    records: list[dict[str, Any]] = []
    unsafe_proposed = unsafe_accepted = safe_proposed = safe_blocked = 0
    errors = corruption = 0
    first_block: int | None = None
    benign_completed = True

    for step_index, step in enumerate(trace["steps"]):
        operation = step["operation"]
        pre_snapshot = runtime.snapshot(session_id)
        record: dict[str, Any] = {
            "step_index": step_index,
            "operation": operation,
            "pre_state_hash": pre_snapshot.state_digest,
            "pre_state_version": pre_snapshot.state_version,
        }
        oracle_safe = False
        unsafe_properties: tuple[str, ...] = ()
        decision = "block"
        reason = ""
        executed = commit_success = False
        decision_error = False

        if operation in {"process", "verify"}:
            principal, payload = step["principal_id"], step["payload"]
            record["proposed_action"] = payload
            try:
                _, _, oracle_result = _oracle_action(runtime, oracle, session_id, principal, payload)
                oracle_safe = oracle_result.safe
                unsafe_properties = oracle_result.unsafe_properties
                evaluated = runtime.evaluate(
                    payload,
                    principal_id=principal,
                    session_id=session_id,
                    monitor=monitor,
                    run_id=trace["trace_id"],
                    scenario_label=trace["category"],
                    _log_decision=False,
                )
                decision = evaluated.decision.status.value
                reason = evaluated.decision.reason
                decision_error = evaluated.decision.status == DecisionStatus.ERROR
                record["solver_result"] = evaluated.decision.solver_result
                record["violated_invariants"] = list(evaluated.decision.violated_invariants)
                record["timings_ms"] = evaluated.decision.timings.canonical_payload
                if operation == "verify":
                    saved[step["saved_id"]] = evaluated
                else:
                    execution = runtime.execute(evaluated)
                    executed, commit_success = execution.executed, execution.commit_success
                    reason = execution.reason if not commit_success else reason
            except SchemaValidationError as exc:
                oracle_safe = False
                unsafe_properties = ("R4_SCHEMA_PARAMETER_INTEGRITY",)
                decision = "block"
                reason = "schema_validation_rejected"
                record["error"] = type(exc).__name__
        elif operation == "execute_saved":
            unsafe_properties = ("R1_STALE_DECISION",)
            evaluated = saved.get(step["saved_id"])
            if evaluated is None:
                reason = "missing_saved_decision"
                decision_error = True
            else:
                execution = runtime.execute(evaluated)
                executed, commit_success = execution.executed, execution.commit_success
                decision = "allow" if commit_success else "block"
                reason = execution.reason
                record["proposed_action"] = evaluated.action.canonical_payload
        elif operation == "execute_mutated":
            unsafe_properties = ("R2_ACTION_SUBSTITUTION",)
            record["proposed_action"] = step["payload"]
            evaluated = saved.get(step["saved_id"])
            try:
                mutated = runtime.validator.validate(step["payload"], principal_id=step["principal_id"], session_id=session_id)
            except SchemaValidationError:
                mutated = None
            if evaluated is None or evaluated.decision.ticket is None or mutated is None:
                reason = "missing_ticket_or_invalid_mutation"
            else:
                forged = replace(evaluated.decision.ticket, action=mutated)
                execution = runtime.bound_executor.execute(forged)
                executed, commit_success = execution.executed, execution.commit_success
                decision = "allow" if commit_success else "block"
                reason = execution.reason
        elif operation == "concurrent":
            unsafe_properties = ("R3_CONCURRENT_STALE_INTERLEAVING",)
            evaluations = []
            individually_safe = True
            for payload in step["payloads"]:
                _, _, item_oracle = _oracle_action(runtime, oracle, session_id, step["principal_id"], payload)
                individually_safe = individually_safe and item_oracle.safe
                evaluations.append(
                    runtime.evaluate(
                        payload,
                        principal_id=step["principal_id"],
                        session_id=session_id,
                        monitor=monitor,
                        run_id=trace["trace_id"],
                        scenario_label=trace["category"],
                        _log_decision=False,
                    )
                )
            oracle_safe = False
            with ThreadPoolExecutor(max_workers=2) as pool:
                executions = list(pool.map(runtime.execute, evaluations))
            commits = sum(item.commit_success for item in executions)
            executed = any(item.executed for item in executions)
            commit_success = commits == len(evaluations)
            decision = "allow" if commit_success else "block"
            reason = "all_concurrent_committed" if commit_success else "stale_interleaving_rejected"
            record["proposed_action"] = step["payloads"]
            record["subresults"] = [item.reason for item in executions]
            record["individual_actions_oracle_safe"] = individually_safe
        else:
            raise ValueError(f"unknown operation: {operation}")

        post_snapshot = runtime.snapshot(session_id)
        state_changed = post_snapshot.state_digest != pre_snapshot.state_digest
        state_corruption = operation != "concurrent" and decision in {"block", "error"} and state_changed
        corruption += int(state_corruption)
        errors += int(decision_error)
        if oracle_safe:
            safe_proposed += 1
            if decision != "allow":
                safe_blocked += 1
        else:
            unsafe_proposed += 1
            if decision == "allow":
                unsafe_accepted += 1
        if decision != "allow" and first_block is None:
            first_block = step_index
        if trace["category"] in BENIGN and (decision != "allow" or (operation == "process" and not commit_success)):
            benign_completed = False
        record.update(
            {
                "oracle_safe": oracle_safe,
                "oracle_unsafe_properties": list(unsafe_properties),
                "decision": decision,
                "decision_reason": reason,
                "decision_error": decision_error,
                "executed": executed,
                "commit_success": commit_success,
                "post_state_hash": post_snapshot.state_digest,
                "post_state_version": post_snapshot.state_version,
                "state_corruption": state_corruption,
            }
        )
        records.append(record)

    final = _state(runtime, session_id)
    final_properties = oracle.final_unsafe_properties(initial, final)
    adversarial = trace["category"] not in BENIGN
    unsafe_effect = bool(final_properties)
    expected_first = trace["expected_first_violation_step"]
    first_block_delta = None if first_block is None or expected_first is None else first_block - expected_first
    return {
        "trace_id": trace["trace_id"],
        "environment": trace["environment"],
        "category": trace["category"],
        "template_family": trace["template_family"],
        "condition": condition,
        "trace_mode": trace["trace_mode"],
        "adversarial": adversarial,
        "expected_first_violation_step": expected_first,
        "expected_violated_property": trace["expected_violated_property"],
        "first_block_step": first_block,
        "first_block_delta": first_block_delta,
        "unsafe_actions_proposed": unsafe_proposed,
        "unsafe_actions_accepted": unsafe_accepted,
        "safe_actions_proposed": safe_proposed,
        "safe_actions_blocked": safe_blocked,
        "decision_errors": errors,
        "state_corruption_events": corruption,
        "unsafe_effect_materialized": unsafe_effect,
        "attack_goal_success": unsafe_effect if adversarial else False,
        "benign_task_completed": benign_completed if not adversarial else False,
        "final_unsafe_properties": list(final_properties),
        "initial_state_hash": initial.digest,
        "final_state_hash": final.digest,
        "final_state_version": final.state_version,
        "steps": records,
    }


def run_benchmark(
    traces: list[dict[str, Any]],
    *,
    conditions: dict[str, str] = PHASE2_CONDITIONS,
) -> list[dict[str, Any]]:
    return [run_trace(trace, condition, conditions=conditions) for trace in traces for condition in conditions]


def write_results(results: list[dict[str, Any]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the model-free paired TDSC benchmark")
    parser.add_argument("--traces", type=Path, default=Path("benchmarks/tdsc_v1/traces.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("results/phase2/raw_results.jsonl"))
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    traces = load_traces(args.traces)
    if args.limit is not None:
        traces = traces[: args.limit]
    results = run_benchmark(traces)
    write_results(results, args.output)
    print(f"wrote {len(results)} paired condition results to {args.output}")


if __name__ == "__main__":
    main()
