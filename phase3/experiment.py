from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from benchmark.runner import (
    ORACLES,
    PHASE3_CONDITIONS,
    RUNTIMES,
    create_runtime,
    load_traces,
    run_benchmark,
)
from epca.environments.cloud_iam.state import CloudIAMState
from epca.environments.dataflow.state import DataFlowState
from epca.environments.financial.state import FinancialState
from epca.runtime.decision import DecisionStatus
from epca.runtime.action import SchemaValidationError
from pcc.checker import ConcreteCertificateChecker
from pcc.producer import DeterministicCertificateProducer, ProducerMode


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")


def run_equivalence(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return run_benchmark(traces, conditions=PHASE3_CONDITIONS)


FRESHNESS_CASES = {
    "financial": {
        "initial": FinancialState(cumulative_outflow=100, daily_limit=500),
        "safe": {"action": "transfer", "params": {"amount": 300}},
        "mutated": {"action": "transfer", "params": {"amount": 400}},
        "state_update": {"cumulative_outflow": 300},
        "principal": "agent",
    },
    "dataflow": {
        "initial": DataFlowState(clearance=2),
        "safe": {"action": "switch_zone", "params": {"zone": "restricted"}},
        "mutated": {"action": "send", "params": {"destination": "public", "resource": "public_report"}},
        "state_update": {"session_taint": True},
        "principal": "analyst",
    },
    "cloud_iam": {
        "initial": CloudIAMState(roles=("viewer", "analyst"), static_roles=("viewer", "analyst"), role_grants=(("agent", "viewer"), ("agent", "analyst"))),
        "safe": {"action": "create_token", "params": {"scopes": ["read:public"]}},
        "mutated": {"action": "create_token", "params": {"scopes": ["*"]}},
        "state_update": {"roles": ("viewer",), "role_grants": (("agent", "viewer"),)},
        "principal": "agent",
    },
}


def run_freshness() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    checker = ConcreteCertificateChecker()
    for environment, case in FRESHNESS_CASES.items():
        runtime = create_runtime(environment, case["initial"])
        runtime.create_session("freshness", case["initial"])
        snapshot = runtime.snapshot("freshness")
        action = runtime.validator.validate(case["safe"], principal_id=case["principal"], session_id="freshness")
        contract = runtime.contracts.active_for(action.action)
        policy = runtime.policies.active
        certificate = DeterministicCertificateProducer().produce(environment=environment, snapshot=snapshot, action=action, contract=contract, policy=policy)
        assert certificate is not None

        mutated = runtime.validator.validate(case["mutated"], principal_id=case["principal"], session_id="freshness")
        mutated_contract = runtime.contracts.active_for(mutated.action)
        action_check = checker.check(environment=environment, snapshot=snapshot, action=mutated, contract=mutated_contract, policy=policy, certificate=certificate)
        rows.append({"environment": environment, "case": "action_mutation", "certificate_action_digest": certificate.action_digest, "actual_action_digest": mutated.digest, "accepted": action_check.accepted, "reason": action_check.reason})

        runtime.administrative_update("freshness", **case["state_update"])
        changed = runtime.snapshot("freshness")
        state_check = checker.check(environment=environment, snapshot=changed, action=action, contract=contract, policy=policy, certificate=certificate)
        rows.append({"environment": environment, "case": "state_mutation", "certificate_state_version": certificate.pre_state_version, "actual_state_version": changed.state_version, "accepted": state_check.accepted, "reason": state_check.reason})
    return rows


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))]


def stats(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values) if values else 0.0,
        "median": statistics.median(values) if values else 0.0,
        "p95": _percentile(values, 0.95),
    }


def _valid_workload(traces: list[dict[str, Any]]) -> list[tuple[str, Any, str, dict[str, Any]]]:
    workload = []
    for trace in traces:
        for step in trace["steps"]:
            if step["operation"] in {"process", "verify"}:
                _, state_cls = RUNTIMES[trace["environment"]]
                initial = state_cls.model_validate(trace["initial_state"])
                runtime = create_runtime(trace["environment"], initial)
                runtime.create_session("workload-validation", initial)
                try:
                    runtime.validator.validate(
                        step["payload"],
                        principal_id=step["principal_id"],
                        session_id="workload-validation",
                    )
                except SchemaValidationError:
                    continue
                workload.append((trace["environment"], initial, step["principal_id"], step["payload"]))
                break
    return workload


def run_overhead(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample_index, (environment, initial, principal, payload) in enumerate(_valid_workload(traces)):
        for condition, monitor in PHASE3_CONDITIONS.items():
            runtime = create_runtime(environment, initial)
            session = f"overhead-{sample_index}-{condition}"
            runtime.create_session(session, initial)
            started = time.perf_counter()
            evaluated = runtime.evaluate(payload, principal_id=principal, session_id=session, monitor=monitor, _log_decision=False)
            wall_ms = (time.perf_counter() - started) * 1000.0
            timing = evaluated.decision.timings
            row = {
                "sample_index": sample_index,
                "environment": environment,
                "condition": condition,
                "decision": evaluated.decision.status.value,
                "wall_verification_ms": wall_ms,
                "rule_evaluation_ms": timing.monitor_total_ms if condition == "StatefulRuleMonitor" else 0.0,
                "certificate_generation_ms": 0.0,
                "certificate_checking_ms": 0.0,
                "certificate_total_verification_ms": 0.0,
                "certificate_size_bytes": 0,
                "epca_compilation_ms": timing.constraint_compilation_ms if condition == "ePCA" else 0.0,
                "epca_solver_ms": timing.solver_ms if condition == "ePCA" else 0.0,
                "epca_total_verification_ms": timing.monitor_total_ms if condition == "ePCA" else 0.0,
            }
            if condition == "PCC-Action":
                guardrail = runtime.guardrails["pcc_action"]
                row.update(
                    certificate_generation_ms=guardrail.last_generation_ms,
                    certificate_checking_ms=guardrail.last_checking_ms,
                    certificate_total_verification_ms=timing.monitor_total_ms,
                    certificate_size_bytes=guardrail.last_certificate_size,
                )
            rows.append(row)
    return rows


def _regeneration_case(environment: str, sample: int) -> tuple[Any, dict[str, Any], str, dict[str, Any]]:
    case = FRESHNESS_CASES[environment]
    initial = case["initial"].model_copy(update={"state_version": 0})
    return initial, case["safe"], case["principal"], case["state_update"]


def run_state_change(samples_per_probability: int = 100) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    probabilities = (0.0, 0.10, 0.25, 0.50)
    for probability in probabilities:
        for environment in FRESHNESS_CASES:
            rng = random.Random(20260812 + int(probability * 1000) + sum(map(ord, environment)))
            for sample in range(samples_per_probability):
                changed = rng.random() < probability
                initial, payload, principal, update = _regeneration_case(environment, sample)
                for condition in ("PCC-Action", "ePCA"):
                    runtime = create_runtime(environment, initial)
                    session = f"state-change-{probability}-{sample}-{condition}"
                    runtime.create_session(session, initial)
                    if condition == "PCC-Action":
                        snapshot = runtime.snapshot(session)
                        action = runtime.validator.validate(payload, principal_id=principal, session_id=session)
                        contract = runtime.contracts.active_for(action.action)
                        policy = runtime.policies.active
                        producer = DeterministicCertificateProducer()
                        started = time.perf_counter()
                        certificate = producer.produce(environment=environment, snapshot=snapshot, action=action, contract=contract, policy=policy)
                        generations = 1
                        stale_certificate = False
                        if changed:
                            runtime.administrative_update(session, **update)
                            snapshot = runtime.snapshot(session)
                            stale_check = ConcreteCertificateChecker().check(
                                environment=environment,
                                snapshot=snapshot,
                                action=action,
                                contract=contract,
                                policy=policy,
                                certificate=certificate,
                            )
                            stale_certificate = (
                                not stale_check.accepted and stale_check.reason == "stale_certificate"
                            )
                            certificate = producer.produce(environment=environment, snapshot=snapshot, action=action, contract=contract, policy=policy)
                            generations += 1
                        checked = ConcreteCertificateChecker().check(environment=environment, snapshot=snapshot, action=action, contract=contract, policy=policy, certificate=certificate)
                        latency = (time.perf_counter() - started) * 1000.0
                        rows.append({"environment": environment, "state_change_probability": probability, "sample": sample, "condition": condition, "state_changed": changed, "stale_certificate": stale_certificate, "regeneration_count": generations - 1, "reverification_count": 0, "accepted": checked.accepted, "total_verification_ms": latency})
                    else:
                        started = time.perf_counter()
                        evaluated = runtime.evaluate(
                            payload,
                            principal_id=principal,
                            session_id=session,
                            monitor="epca",
                            _log_decision=False,
                        )
                        if changed:
                            runtime.administrative_update(session, **update)
                            evaluated = runtime.evaluate(
                                payload,
                                principal_id=principal,
                                session_id=session,
                                monitor="epca",
                                _log_decision=False,
                            )
                        latency = (time.perf_counter() - started) * 1000.0
                        rows.append({"environment": environment, "state_change_probability": probability, "sample": sample, "condition": condition, "state_changed": changed, "stale_certificate": False, "regeneration_count": 0, "reverification_count": int(changed), "accepted": evaluated.decision.status == DecisionStatus.ALLOW, "total_verification_ms": latency})
    return rows


def run_producer_failure(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    benign = [trace for trace in traces if trace["category"] in {"benign_standard", "benign_boundary"}]
    rows: list[dict[str, Any]] = []
    for mode in ProducerMode:
        completed = 0
        decisions = 0
        accepted = 0
        for trace in benign:
            _, state_cls = RUNTIMES[trace["environment"]]
            session = f"failure-{mode.value}-{trace['trace_id']}"
            initial = state_cls.model_validate(trace["initial_state"])
            runtime = create_runtime(trace["environment"], initial)
            runtime.create_session(session, initial)
            pcc = runtime.guardrails["pcc_action"]
            pcc.producer = DeterministicCertificateProducer(mode)
            trace_complete = True
            for step in trace["steps"]:
                if step["operation"] != "process":
                    continue
                result = runtime.process(step["payload"], principal_id=step["principal_id"], session_id=session, monitor="pcc_action")
                decisions += 1
                accepted += int(result.evaluated.decision.status == DecisionStatus.ALLOW)
                trace_complete = trace_complete and result.execution.commit_success
            completed += int(trace_complete)
        rows.append({"producer_mode": mode.value, "benign_traces": len(benign), "benign_completed": completed, "btcr": completed / len(benign), "decisions": decisions, "accepted_decisions": accepted, "fail_closed": accepted == 0 if mode != ProducerMode.NORMAL else True})
    return rows


def run_all(traces_path: Path, output_dir: Path) -> None:
    traces = load_traces(traces_path)
    equivalence = run_equivalence(traces)
    freshness = run_freshness()
    overhead = run_overhead(traces)
    state_change = run_state_change()
    producer_failure = run_producer_failure(traces)
    _write_jsonl(output_dir / "pcc_equivalence.jsonl", equivalence)
    _write_jsonl(output_dir / "pcc_freshness.jsonl", freshness)
    _write_jsonl(output_dir / "pcc_overhead.jsonl", overhead)
    _write_jsonl(output_dir / "pcc_state_change.jsonl", state_change)
    _write_jsonl(output_dir / "pcc_producer_failure.jsonl", producer_failure)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic Phase 3 PCC comparison experiments")
    parser.add_argument("--traces", type=Path, default=Path("benchmarks/tdsc_v1/traces.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("results/phase3"))
    args = parser.parse_args()
    run_all(args.traces, args.output_dir)
    print(f"generated Phase 3 raw results in {args.output_dir}")


if __name__ == "__main__":
    main()
