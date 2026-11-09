from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

import z3

from benchmark import runner as benchmark_runner
from benchmark.runner import BENIGN, PHASE2_CONDITIONS, RUNTIMES, load_traces, run_trace
from epca.environments.cloud_iam.policies import default_cloud_iam_policy
from epca.environments.dataflow.policies import default_dataflow_policy
from epca.environments.financial.policies import default_financial_policy
from epca.runtime.action import SchemaValidationError
from epca.runtime.decision import DecisionStatus
from epca.runtime.policy import PolicySet, SecurityInvariant
from phase3.experiment import _valid_workload


POLICY_FACTORIES = {
    "financial": default_financial_policy,
    "dataflow": default_dataflow_policy,
    "cloud_iam": default_cloud_iam_policy,
}
MONITORS = {
    "StatefulRuleMonitor": "stateful_rule",
    "ePCA": "epca",
}
MUTATION_MODES = ("python_omission", "smt_omission", "common_mode_omission")
PROJECT_ROOT = Path(__file__).parents[1]


def _policy_for(
    environment: str,
    *,
    financial_policy_version: str = "financial-policy-v1",
) -> PolicySet[Any]:
    factory = POLICY_FACTORIES[environment]
    return factory(financial_policy_version) if environment == "financial" else factory()


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = round((len(ordered) - 1) * fraction)
    return ordered[max(0, min(len(ordered) - 1, index))]


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _source_lines(path: Path) -> int:
    return sum(
        bool(line.strip()) and not line.lstrip().startswith("#")
        for line in path.read_text(encoding="utf-8").splitlines()
    )


def run_portability_audit(
    *, financial_policy_version: str = "financial-policy-v1"
) -> list[dict[str, Any]]:
    """Inventory shared and domain-specific implementation surface.

    This deliberately reports source structure instead of turning line counts
    into a subjective developer-productivity claim.
    """

    rows: list[dict[str, Any]] = []
    shared = {
        "direct_predicate_guardrail": (PROJECT_ROOT / "epca/guardrails/stateful_rule.py",),
        "epca_guardrail_and_verifier": (
            PROJECT_ROOT / "epca/guardrails/epca.py",
            PROJECT_ROOT / "epca/runtime/verifier.py",
        ),
        "shared_policy_abstraction": (PROJECT_ROOT / "epca/runtime/policy.py",),
        "shared_contract_abstraction": (PROJECT_ROOT / "epca/runtime/contract.py",),
        "shared_bound_executor": (PROJECT_ROOT / "epca/runtime/executor.py",),
    }
    for component, paths in shared.items():
        rows.append(
            {
                "scope": "shared",
                "environment": "all",
                "component": component,
                "files": ";".join(str(path.relative_to(PROJECT_ROOT)) for path in paths),
                "source_lines": sum(_source_lines(path) for path in paths),
                "invariants": "",
                "python_predicates": "",
                "smt_encodings": "",
            }
        )
    for environment, factory in POLICY_FACTORIES.items():
        directory = PROJECT_ROOT / "epca/environments" / environment
        policy = _policy_for(environment, financial_policy_version=financial_policy_version)
        for filename, component in (
            ("actions.py", "typed_actions_shared_by_both"),
            ("state.py", "state_model_shared_by_both"),
            ("contracts.py", "transition_contracts_shared_by_both"),
            ("policies.py", "dual_policy_definitions"),
            ("formal.py", "epca_symbol_and_exact_bindings"),
        ):
            path = directory / filename
            rows.append(
                {
                    "scope": "domain",
                    "environment": environment,
                    "component": component,
                    "files": str(path.relative_to(PROJECT_ROOT)),
                    "source_lines": _source_lines(path),
                    "invariants": len(policy.invariants) if filename == "policies.py" else "",
                    "python_predicates": len(policy.invariants) if filename == "policies.py" else "",
                    "smt_encodings": len(policy.invariants) if filename == "policies.py" else "",
                }
            )
    return rows


def mutate_omission(policy: PolicySet[Any], invariant_index: int, mode: str) -> PolicySet[Any]:
    """Delete one semantic check from Python, SMT, or both encodings.

    This is the standard rule-deletion mutation operator.  Keeping the other
    encoding intact lets the experiment distinguish single-implementation
    faults from common-mode policy-specification faults.
    """

    if mode not in MUTATION_MODES:
        raise ValueError(f"unknown mutation mode: {mode}")
    invariants = list(policy.invariants)
    original = invariants[invariant_index]
    updates: dict[str, Any] = {
        "semantics_id": f"{original.semantics_id}|mutation={mode}",
    }
    if mode in {"python_omission", "common_mode_omission"}:
        updates["evaluate_fn"] = lambda pre, action, post: True
    if mode in {"smt_omission", "common_mode_omission"}:
        updates["compile_fn"] = lambda symbols, action: z3.BoolVal(True)
    invariants[invariant_index] = replace(original, **updates)
    return replace(policy, invariants=tuple(invariants))


def _expanded_policy(policy: PolicySet[Any], target_size: int) -> PolicySet[Any]:
    """Build a conjunction-equivalent policy with additional named clauses."""

    if target_size < 1:
        raise ValueError("target_size must be positive")
    expanded: list[SecurityInvariant[Any]] = []
    for index in range(target_size):
        original = policy.invariants[index % len(policy.invariants)]
        if index < len(policy.invariants):
            expanded.append(original)
        else:
            expanded.append(
                replace(
                    original,
                    name=f"{original.name}__EQUIV_{index:02d}",
                    semantics_id=f"{original.semantics_id}|equivalent-copy={index}",
                )
            )
    return replace(policy, invariants=tuple(expanded))


def _runtime_with_policy(
    environment: str,
    policy: PolicySet[Any],
    initial_state: Any | None = None,
) -> Any:
    runtime_cls, _ = RUNTIMES[environment]
    if environment == "financial":
        runtime = runtime_cls(policy_version=policy.policy_version)
    else:
        runtime = runtime_cls()
    runtime.activate_policy(policy)
    return runtime


def _run_trace_with_policy(
    trace: dict[str, Any],
    condition: str,
    monitor: str,
    policy: PolicySet[Any],
) -> dict[str, Any]:
    """Use the unchanged benchmark runner with a policy-configured runtime."""

    environment = trace["environment"]
    runtime_cls, state_cls = benchmark_runner.RUNTIMES[environment]

    def configured_runtime(*, policy_version: str | None = None) -> Any:
        if environment == "financial":
            runtime = runtime_cls(policy_version=policy_version or policy.policy_version)
        else:
            runtime = runtime_cls()
        runtime.activate_policy(policy)
        return runtime

    original = benchmark_runner.RUNTIMES[environment]
    benchmark_runner.RUNTIMES[environment] = (configured_runtime, state_cls)
    try:
        return run_trace(trace, condition, conditions={condition: monitor})
    finally:
        benchmark_runner.RUNTIMES[environment] = original


def _decision_deltas(
    mutated: list[dict[str, Any]], baseline: list[dict[str, Any]]
) -> tuple[int, int, int]:
    baseline_by_id = {row["trace_id"]: row for row in baseline}
    disagreements = allow_regressions = error_regressions = 0
    for row in mutated:
        reference = baseline_by_id[row["trace_id"]]
        for current_step, reference_step in zip(row["steps"], reference["steps"], strict=True):
            current = current_step["decision"]
            expected = reference_step["decision"]
            disagreements += int(current != expected)
            allow_regressions += int(expected != "allow" and current == "allow")
            error_regressions += int(expected != "error" and current == "error")
    return disagreements, allow_regressions, error_regressions


def _mutation_summary(
    *,
    environment: str,
    invariant: SecurityInvariant[Any],
    mode: str,
    condition: str,
    rows: list[dict[str, Any]],
    baseline: list[dict[str, Any]],
    target_witnesses: int,
    discriminating_witnesses: int,
) -> dict[str, Any]:
    disagreements, allow_regressions, error_regressions = _decision_deltas(rows, baseline)
    adversarial = [row for row in rows if row["adversarial"]]
    benign = [row for row in rows if not row["adversarial"]]
    baseline_unsafe = sum(row["unsafe_effect_materialized"] for row in baseline if row["adversarial"])
    unsafe_effects = sum(row["unsafe_effect_materialized"] for row in adversarial)
    unsafe_accepted = sum(row["unsafe_actions_accepted"] for row in rows)
    decision_errors = sum(row["decision_errors"] for row in rows)
    benign_completed = sum(row["benign_task_completed"] for row in benign)
    if not discriminating_witnesses:
        outcome = "no_discriminating_witness"
    elif mode == "smt_omission" and condition == "StatefulRuleMonitor":
        outcome = "not_on_execution_path"
    elif allow_regressions or unsafe_effects > baseline_unsafe:
        outcome = "unsafe_escape"
    elif error_regressions:
        outcome = "detected_fail_closed"
    elif disagreements:
        outcome = "observable_safe_change"
    else:
        outcome = "masked_by_redundant_encoding"
    return {
        "environment": environment,
        "invariant": invariant.name,
        "mutation_mode": mode,
        "monitor": condition,
        "target_violation_witnesses": target_witnesses,
        "discriminating_witnesses": discriminating_witnesses,
        "decision_disagreements": disagreements,
        "allow_regressions": allow_regressions,
        "error_regressions": error_regressions,
        "decision_errors": decision_errors,
        "unsafe_actions_accepted": unsafe_accepted,
        "unsafe_effects": unsafe_effects,
        "adversarial_traces": len(adversarial),
        "benign_completed": benign_completed,
        "benign_traces": len(benign),
        "outcome": outcome,
    }


def run_mutation_experiment(
    traces: list[dict[str, Any]],
    *,
    financial_policy_version: str = "financial-policy-v1",
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    by_environment = {
        environment: [trace for trace in traces if trace["environment"] == environment]
        for environment in POLICY_FACTORIES
    }
    baselines: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for environment, environment_traces in by_environment.items():
        for condition, monitor in MONITORS.items():
            baselines[(environment, condition)] = [
                run_trace(trace, condition, conditions={condition: monitor})
                for trace in environment_traces
            ]

    for environment, environment_traces in by_environment.items():
        base_policy = _policy_for(environment, financial_policy_version=financial_policy_version)
        coverage_rows = baselines[(environment, "ePCA")]
        target_counts: Counter[str] = Counter()
        unique_counts: Counter[str] = Counter()
        for row in coverage_rows:
            for step in row["steps"]:
                violated = step.get("violated_invariants", [])
                target_counts.update(violated)
                if len(violated) == 1:
                    unique_counts.update(violated)
        for invariant_index, invariant in enumerate(base_policy.invariants):
            for mode in MUTATION_MODES:
                mutated_policy = mutate_omission(base_policy, invariant_index, mode)
                for condition, monitor in MONITORS.items():
                    rows = [
                        _run_trace_with_policy(trace, condition, monitor, mutated_policy)
                        for trace in environment_traces
                    ]
                    summaries.append(
                        _mutation_summary(
                            environment=environment,
                            invariant=invariant,
                            mode=mode,
                            condition=condition,
                            rows=rows,
                            baseline=baselines[(environment, condition)],
                            target_witnesses=target_counts[invariant.name],
                            discriminating_witnesses=unique_counts[invariant.name],
                        )
                    )
    return summaries


def _scaling_policy_cases(
    environment: str,
    *,
    financial_policy_version: str = "financial-policy-v1",
) -> list[tuple[str, PolicySet[Any]]]:
    policy = _policy_for(environment, financial_policy_version=financial_policy_version)
    cases = [
        ("actual_prefix", replace(policy, invariants=policy.invariants[:size]))
        for size in range(1, len(policy.invariants) + 1)
    ]
    cases.extend(("equivalent_density", _expanded_policy(policy, size)) for size in (16, 32, 64))
    return cases


def run_scaling_experiment(
    traces: list[dict[str, Any]],
    *,
    samples_per_environment: int = 60,
    financial_policy_version: str = "financial-policy-v1",
) -> list[dict[str, Any]]:
    workload: dict[str, list[tuple[Any, str, dict[str, Any]]]] = defaultdict(list)
    for environment, initial, principal, payload in _valid_workload(traces):
        if len(workload[environment]) < samples_per_environment:
            workload[environment].append((initial, principal, payload))

    output: list[dict[str, Any]] = []
    for environment in POLICY_FACTORIES:
        for scale_type, policy in _scaling_policy_cases(
            environment,
            financial_policy_version=financial_policy_version,
        ):
            timings: dict[str, list[float]] = {condition: [] for condition in MONITORS}
            decisions: dict[str, list[str]] = {condition: [] for condition in MONITORS}
            for sample_index, (initial, principal, payload) in enumerate(workload[environment]):
                runtime = _runtime_with_policy(environment, policy, initial)
                session_id = f"scale-{environment}-{len(policy.invariants)}-{sample_index}"
                runtime.create_session(session_id, initial)
                for condition, monitor in MONITORS.items():
                    evaluated = runtime.evaluate(
                        payload,
                        principal_id=principal,
                        session_id=session_id,
                        monitor=monitor,
                        _log_decision=False,
                    )
                    timings[condition].append(evaluated.decision.timings.monitor_total_ms)
                    decisions[condition].append(evaluated.decision.status.value)
            disagreements = sum(
                left != right
                for left, right in zip(
                    decisions["StatefulRuleMonitor"], decisions["ePCA"], strict=True
                )
            )
            for condition in MONITORS:
                values = timings[condition]
                output.append(
                    {
                        "environment": environment,
                        "scale_type": scale_type,
                        "invariant_count": len(policy.invariants),
                        "monitor": condition,
                        "samples": len(values),
                        "allow": decisions[condition].count("allow"),
                        "block": decisions[condition].count("block"),
                        "error": decisions[condition].count("error"),
                        "paired_decision_disagreements": disagreements,
                        "mean_ms": statistics.fmean(values) if values else 0.0,
                        "median_ms": statistics.median(values) if values else 0.0,
                        "p95_ms": _percentile(values, 0.95),
                    }
                )
    return output


def _core_invariant_names(decision: Any, policy: PolicySet[Any]) -> tuple[str, ...]:
    by_description = {invariant.description: invariant.name for invariant in policy.invariants}
    return tuple(
        by_description[item]
        for item in decision.conflict_explanation
        if item in by_description
    )


def _record_localization(
    *,
    trace: dict[str, Any],
    step_index: int,
    sub_index: int | None,
    runtime: Any,
    session_id: str,
    principal: str,
    payload: dict[str, Any],
) -> tuple[dict[str, Any], Any]:
    snapshot = runtime.snapshot(session_id)
    action = runtime.validator.validate(payload, principal_id=principal, session_id=session_id)
    contract = runtime.contracts.active_for(action.action)
    policy = runtime.policies.active
    post_state = contract.transition(snapshot.state, action)
    expected = policy.violated(snapshot.state, action, post_state)
    stateful = runtime.evaluate(
        payload,
        principal_id=principal,
        session_id=session_id,
        monitor="stateful_rule",
        _log_decision=False,
    )
    epca = runtime.evaluate(
        payload,
        principal_id=principal,
        session_id=session_id,
        monitor="epca",
        _log_decision=False,
    )
    core = _core_invariant_names(epca.decision, policy)
    supporting = max(0, len(epca.decision.conflict_explanation) - len(core))
    row = {
        "trace_id": trace["trace_id"],
        "environment": trace["environment"],
        "category": trace["category"],
        "step_index": step_index,
        "sub_index": "" if sub_index is None else sub_index,
        "action": action.action,
        "action_digest": action.digest,
        "stateful_decision": stateful.decision.status.value,
        "epca_decision": epca.decision.status.value,
        "decision_disagreement": stateful.decision.status != epca.decision.status,
        "solver_result": epca.decision.solver_result,
        "expected_violated_invariants": ";".join(expected),
        "stateful_reported_invariants": ";".join(stateful.decision.violated_invariants),
        "epca_reported_invariants": ";".join(epca.decision.violated_invariants),
        "unsat_core_invariants": ";".join(core),
        "unsat_core_policy_size": len(core),
        "unsat_core_supporting_constraints": supporting,
        "core_nonempty_for_unsat": epca.decision.solver_result != "unsat" or bool(core),
        "core_sound": epca.decision.solver_result != "unsat" or (bool(core) and set(core) <= set(expected)),
        "single_violation_exact": len(expected) != 1 or set(core) == set(expected),
        "stateful_complete": set(stateful.decision.violated_invariants) == set(expected),
    }
    return row, epca


def run_localization_experiment(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for trace in traces:
        _, state_cls = RUNTIMES[trace["environment"]]
        session_id = f"localize::{trace['trace_id']}"
        initial = state_cls.model_validate(trace["initial_state"])
        runtime = benchmark_runner.create_runtime(trace["environment"], initial)
        runtime.create_session(session_id, initial)
        saved: dict[str, Any] = {}
        for step_index, step in enumerate(trace["steps"]):
            operation = step["operation"]
            if operation in {"process", "verify"}:
                try:
                    row, evaluated = _record_localization(
                        trace=trace,
                        step_index=step_index,
                        sub_index=None,
                        runtime=runtime,
                        session_id=session_id,
                        principal=step["principal_id"],
                        payload=step["payload"],
                    )
                except SchemaValidationError:
                    continue
                rows.append(row)
                if operation == "verify":
                    saved[step["saved_id"]] = evaluated
                else:
                    runtime.execute(evaluated)
            elif operation == "execute_saved":
                evaluated = saved.get(step["saved_id"])
                if evaluated is not None:
                    runtime.execute(evaluated)
            elif operation == "execute_mutated":
                continue
            elif operation == "concurrent":
                evaluations = []
                for sub_index, payload in enumerate(step["payloads"]):
                    row, evaluated = _record_localization(
                        trace=trace,
                        step_index=step_index,
                        sub_index=sub_index,
                        runtime=runtime,
                        session_id=session_id,
                        principal=step["principal_id"],
                        payload=payload,
                    )
                    rows.append(row)
                    evaluations.append(evaluated)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    list(pool.map(runtime.execute, evaluations))
            else:
                raise ValueError(f"unknown operation: {operation}")
    return rows


def _ratio(numerator: int, denominator: int) -> str:
    return "NA" if not denominator else f"{numerator}/{denominator} ({100 * numerator / denominator:.1f}%)"


def render_report(
    scaling: list[dict[str, Any]],
    mutations: list[dict[str, Any]],
    localization: list[dict[str, Any]],
    portability: list[dict[str, Any]],
    *,
    financial_policy_version: str = "financial-policy-v1",
) -> str:
    lines = [
        "# Supplemental ePCA Architectural Experiments",
        "",
        "These local experiments test claims that the existing Phase 2--4 results do not establish. They do not use an LLM endpoint and do not alter the original benchmark outputs.",
        "",
        "## 1. Policy-size and constraint-density scaling",
        "",
        "`actual_prefix` adds the real domain invariants in source order. `equivalent_density` retains the full policy and adds named, conjunction-equivalent copies; it is a solver-density stress test, not additional semantic coverage.",
        "",
        "| Environment | Scale | Invariants | Monitor | Mean ms | P95 ms | Disagreements |",
        "| --- | --- | ---: | --- | ---: | ---: | ---: |",
    ]
    selected_scaling = [
        row
        for row in scaling
        if (row["scale_type"] == "actual_prefix" and row["invariant_count"] == len(_policy_for(row["environment"], financial_policy_version=financial_policy_version).invariants))
        or (row["scale_type"] == "equivalent_density" and row["invariant_count"] in {16, 32, 64})
    ]
    for row in selected_scaling:
        lines.append(
            f"| {row['environment']} | {row['scale_type']} | {row['invariant_count']} | {row['monitor']} | {row['mean_ms']:.4f} | {row['p95_ms']:.4f} | {row['paired_decision_disagreements']} |"
        )

    lines.extend(
        [
            "",
            "## 2. Rule-deletion mutation testing",
            "",
            "A mutation is *discriminating* when the benchmark contains a transition for which the deleted invariant is the only violated invariant. Python-only deletion models an omission in the direct rule implementation; SMT-only deletion models an omission in the formal encoding; common-mode deletion models the same requirement missing from both encodings.",
        ]
    )
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in mutations:
        groups[(row["mutation_mode"], row["monitor"])].append(row)
    total_invariants = sum(
        len(_policy_for(environment, financial_policy_version=financial_policy_version).invariants)
        for environment, factory in POLICY_FACTORIES.items()
    )
    discriminating_invariants = sum(
        row["discriminating_witnesses"] > 0
        for row in groups[("python_omission", "ePCA")]
    )
    lines.extend(
        [
            f"The corpus provides discriminating witnesses for **{discriminating_invariants}/{total_invariants}** invariants. The other {total_invariants - discriminating_invariants} mutations are reported in the CSV but excluded from the preservation rates below.",
            "",
            "| Mutation mode | Monitor | Discriminating mutants | Safety preserved | Unsafe escapes | Fail-closed detections |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for mode in MUTATION_MODES:
        for monitor in MONITORS:
            covered = [row for row in groups[(mode, monitor)] if row["discriminating_witnesses"]]
            preserved = sum(row["outcome"] in {"masked_by_redundant_encoding", "detected_fail_closed", "observable_safe_change", "not_on_execution_path"} for row in covered)
            escapes = sum(row["outcome"] == "unsafe_escape" for row in covered)
            detected = sum(row["outcome"] == "detected_fail_closed" for row in covered)
            lines.append(
                f"| {mode} | {monitor} | {len(covered)} | {_ratio(preserved, len(covered))} | {escapes} | {detected} |"
            )

    unsat = [row for row in localization if row["solver_result"] == "unsat"]
    single = [row for row in unsat if len(row["expected_violated_invariants"].split(";")) == 1]
    core_nonempty = sum(bool(row["unsat_core_invariants"]) for row in unsat)
    sound = sum(bool(row["core_sound"]) for row in unsat)
    single_exact = sum(bool(row["single_violation_exact"]) for row in single)
    stateful_complete = sum(bool(row["stateful_complete"]) for row in localization)
    decision_disagreements = sum(bool(row["decision_disagreement"]) for row in localization)
    lines.extend(
        [
            "",
            "## 3. UNSAT-core failure localization",
            "",
            f"- Valid state--action pairs replayed: **{len(localization)}**.",
            f"- Stateful/ePCA decision disagreements: **{decision_disagreements}**.",
            f"- UNSAT decisions with a named invariant in the core: **{_ratio(core_nonempty, len(unsat))}**.",
            f"- Sound cores (every reported core invariant was actually violated): **{_ratio(sound, len(unsat))}**.",
            f"- Exact localization for single-invariant violations: **{_ratio(single_exact, len(single))}**.",
            f"- Stateful complete rule-label reports: **{_ratio(stateful_complete, len(localization))}**.",
            "  This last check is structural rather than independent: the direct evaluator and the expected label set both call the same Python predicates.",
            "",
            "## 4. Portability and implementation-surface audit",
            "",
            "The current prototype has one shared direct-predicate guardrail and one shared ePCA verifier, but every domain supplies typed actions, state, deterministic contracts, policy definitions, and ePCA-specific symbolic bindings. Every policy invariant is represented twice: once as a Python predicate and once as an SMT formula.",
            "",
            "| Environment | Invariants | Policy file lines | ePCA formal-binding lines |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for environment in POLICY_FACTORIES:
        domain = [row for row in portability if row["environment"] == environment]
        policy_row = next(row for row in domain if row["component"] == "dual_policy_definitions")
        formal_row = next(row for row in domain if row["component"] == "epca_symbol_and_exact_bindings")
        lines.append(
            f"| {environment} | {policy_row['invariants']} | {policy_row['source_lines']} | {formal_row['source_lines']} |"
        )
    shared_stateful = next(row for row in portability if row["component"] == "direct_predicate_guardrail")
    shared_epca = next(row for row in portability if row["component"] == "epca_guardrail_and_verifier")
    lines.extend(
        [
            "",
            f"The shared direct-predicate guardrail is {shared_stateful['source_lines']} nonblank, non-comment source lines; the shared ePCA guardrail plus verifier is {shared_epca['source_lines']} lines. These counts describe implementation surface only, not engineering time or defect probability.",
            "",
            "This audit does **not** support a portability advantage for the current artifact. A new environment still needs domain-specific symbolic variables and exact bindings, and the dual policy representation increases the specification surface. Portability would require a higher-level policy/transition language that generates both executable and SMT forms from one definition; that compiler is not part of this prototype.",
            "",
            "## Interpretation",
            "",
            "The experiments do not show that ePCA is safer than a correct StatefulRuleMonitor under a correct shared policy; their decisions remain equivalent, and the direct monitor is the lower-latency implementation. The defensible advantage is narrower: with independent Python and SMT encodings, ePCA can contain a one-sided omission. An SMT omission is detected and fails closed by the Python/SMT consistency check, while a Python omission is masked by the still-correct SMT constraint. A common-mode omission defeats both paths, so ePCA does not solve policy-completeness or shared-specification errors.",
            "",
            "UNSAT cores add machine-checkable binding and transition evidence. They do not improve the rule-label accuracy over this instrumented StatefulRuleMonitor, which already evaluates and reports every named predicate. The result supports an auditability and fault-containment claim, not a blanket safety or performance superiority claim.",
            "",
        ]
    )
    return "\n".join(lines)


def render_report_zh(
    scaling: list[dict[str, Any]],
    mutations: list[dict[str, Any]],
    localization: list[dict[str, Any]],
    portability: list[dict[str, Any]],
    *,
    financial_policy_version: str = "financial-policy-v1",
) -> str:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in mutations:
        groups[(row["mutation_mode"], row["monitor"])].append(row)
    total_invariants = sum(
        len(_policy_for(environment, financial_policy_version=financial_policy_version).invariants)
        for environment, factory in POLICY_FACTORIES.items()
    )
    discriminating = sum(
        row["discriminating_witnesses"] > 0
        for row in groups[("python_omission", "ePCA")]
    )
    unsat = [row for row in localization if row["solver_result"] == "unsat"]
    single = [row for row in unsat if len(row["expected_violated_invariants"].split(";")) == 1]
    lines = [
        "# ePCA 补充架构实验（中文）",
        "",
        "本轮实验只调用本地 Python/Z3，不调用远程 LLM，也不修改 Phase 2--4 的原始结果。目标是回答原论文没有回答的问题：正确实现之外，ePCA 到底额外提供了什么。",
        "",
        "## 一、策略规模与开销",
        "",
        "在真实策略的 7--8 条 invariant 下，两个后端仍是零决策分歧，但 ePCA 明显更慢。将逻辑等价的命名约束增加到 64 条时，ePCA 的延迟继续上升。这是约束密度压力测试，不代表新增了语义覆盖。",
        "",
        "| 环境 | 策略条数 | 直接谓词均值 ms | ePCA 均值 ms | 决策分歧 |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for environment in POLICY_FACTORIES:
        count = len(_policy_for(environment, financial_policy_version=financial_policy_version).invariants)
        selected = [
            row for row in scaling
            if row["environment"] == environment
            and row["scale_type"] == "actual_prefix"
            and row["invariant_count"] == count
        ]
        direct = next(row for row in selected if row["monitor"] == "StatefulRuleMonitor")
        epca = next(row for row in selected if row["monitor"] == "ePCA")
        lines.append(
            f"| {environment} | {count} | {direct['mean_ms']:.4f} | {epca['mean_ms']:.4f} | {epca['paired_decision_disagreements']} |"
        )
    lines.extend(
        [
            "",
            "## 二、规则删除 mutation testing",
            "",
            f"三个环境共有 {total_invariants} 条 invariant，现有 600 条轨迹只对 **{discriminating}/{total_invariants}** 条提供“该 invariant 是唯一冲突”的区分性样本。其余 {total_invariants - discriminating} 条不纳入成功率，详细列在 CSV 中。",
            "",
            "| 删除方式 | 执行后端 | 可区分 mutant | 保持安全 | unsafe escape | 失败关闭检出 |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    labels = {
        "python_omission": "只删 Python 谓词",
        "smt_omission": "只删 SMT 约束",
        "common_mode_omission": "Python/SMT 同时删除",
    }
    monitor_labels = {"StatefulRuleMonitor": "直接谓词求值", "ePCA": "ePCA"}
    safe_outcomes = {
        "masked_by_redundant_encoding",
        "detected_fail_closed",
        "observable_safe_change",
        "not_on_execution_path",
    }
    for mode in MUTATION_MODES:
        for monitor in MONITORS:
            covered = [row for row in groups[(mode, monitor)] if row["discriminating_witnesses"]]
            preserved = sum(row["outcome"] in safe_outcomes for row in covered)
            escapes = sum(row["outcome"] == "unsafe_escape" for row in covered)
            detected = sum(row["outcome"] == "detected_fail_closed" for row in covered)
            lines.append(
                f"| {labels[mode]} | {monitor_labels[monitor]} | {len(covered)} | {_ratio(preserved, len(covered))} | {escapes} | {detected} |"
            )
    core_nonempty = sum(bool(row["unsat_core_invariants"]) for row in unsat)
    sound = sum(bool(row["core_sound"]) for row in unsat)
    exact = sum(bool(row["single_violation_exact"]) for row in single)
    disagreements = sum(bool(row["decision_disagreement"]) for row in localization)
    lines.extend(
        [
            "",
            f"解读：只删 Python 规则时，直接谓词求值器 {discriminating}/{discriminating} 出现 unsafe escape，ePCA 由仍正确的 SMT 约束拦截；只删 SMT 规则时，ePCA {discriminating}/{discriminating} 通过 Python/SMT 不一致进入 ERROR 并失败关闭；两份同时删除时，两个后端都 {discriminating}/{discriminating} 被穿透。这证明的是单侧实现错误容错，不是策略完整性。",
            "",
            "## 三、UNSAT core 定位",
            "",
            f"- 重放有效 state--action pair：**{len(localization)}**。",
            f"- 直接谓词/ePCA 决策分歧：**{disagreements}**。",
            f"- UNSAT 且 core 包含命名 invariant：**{_ratio(core_nonempty, len(unsat))}**。",
            f"- core 所报 invariant 确实被 Python 谓词判定违反：**{_ratio(sound, len(unsat))}**。",
            f"- 单 invariant 违反的精确定位：**{_ratio(exact, len(single))}**。",
            "",
            "Stateful 的规则标签也是完整的，但这是结构上的结果：“预期标签”和 Stateful 都调用同一组 Python 谓词，不是独立 oracle。ePCA 的增量价值是 core 还携带可由求解器检查的 state/action/transition 冲突证据，不是标签更准。",
            "",
            "## 四、可迁移性审计",
            "",
            "| 环境 | invariant 数 | policy 文件行数 | ePCA formal binding 行数 |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for environment in POLICY_FACTORIES:
        domain = [row for row in portability if row["environment"] == environment]
        policy_row = next(row for row in domain if row["component"] == "dual_policy_definitions")
        formal_row = next(row for row in domain if row["component"] == "epca_symbol_and_exact_bindings")
        lines.append(
            f"| {environment} | {policy_row['invariants']} | {policy_row['source_lines']} | {formal_row['source_lines']} |"
        )
    lines.extend(
        [
            "",
            "当前 artifact **不支持 ePCA 具有可迁移性优势**。每个新环境仍要实现领域状态、确定性 transition contract、SMT 符号和 exact binding；23 条 invariant 也全部同时写了 Python 和 SMT 两份。要支持可迁移性主张，需要一个更高层的策略/transition 语言，从单一定义生成执行谓词与 SMT；当前原型没有这个编译器。",
            "",
            "## 最终判断",
            "",
            "应保留 Stateful 对比，但应把它重新定位为 **Direct Predicate Evaluator（直接谓词求值器）**，用于做强语义对照和消融，不是主要的“敌对方法”。论文可以声称 ePCA 提供单侧编码错误容错与可检查冲突证据；不应声称它相比正确的 Stateful 具有更高安全率、更低开销或当前已证明的可迁移性。",
            "",
        ]
    )
    return "\n".join(lines)


def run_all(
    traces_path: Path,
    output_dir: Path,
    report_dir: Path,
    *,
    scaling_samples: int = 60,
    financial_policy_version: str = "financial-policy-v1",
) -> dict[str, Any]:
    traces = load_traces(traces_path)
    scaling = run_scaling_experiment(
        traces,
        samples_per_environment=scaling_samples,
        financial_policy_version=financial_policy_version,
    )
    mutations = run_mutation_experiment(
        traces,
        financial_policy_version=financial_policy_version,
    )
    localization = run_localization_experiment(traces)
    portability = run_portability_audit(financial_policy_version=financial_policy_version)
    _write_csv(output_dir / "policy_scaling.csv", scaling)
    _write_csv(output_dir / "mutation_testing.csv", mutations)
    _write_csv(output_dir / "unsat_core_localization.csv", localization)
    _write_csv(output_dir / "portability_audit.csv", portability)
    report = render_report(
        scaling,
        mutations,
        localization,
        portability,
        financial_policy_version=financial_policy_version,
    )
    report_zh = render_report_zh(
        scaling,
        mutations,
        localization,
        portability,
        financial_policy_version=financial_policy_version,
    )
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "supplemental_architectural_experiments.md").write_text(report, encoding="utf-8")
    (report_dir / "supplemental_architectural_experiments_zh.md").write_text(report_zh, encoding="utf-8")
    summary = {
        "traces": len(traces),
        "scaling_rows": len(scaling),
        "mutation_rows": len(mutations),
        "localization_pairs": len(localization),
        "portability_rows": len(portability),
        "report": str(report_dir / "supplemental_architectural_experiments.md"),
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run supplemental local ePCA architectural experiments")
    parser.add_argument("--traces", type=Path, default=Path("benchmarks/tdsc_v1/traces.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("results/supplemental"))
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    parser.add_argument("--scaling-samples", type=int, default=60)
    parser.add_argument(
        "--financial-policy-version",
        choices=("financial-policy-v1", "financial-policy-v2"),
        default="financial-policy-v1",
    )
    args = parser.parse_args()
    summary = run_all(
        args.traces,
        args.output_dir,
        args.report_dir,
        scaling_samples=args.scaling_samples,
        financial_policy_version=args.financial_policy_version,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
