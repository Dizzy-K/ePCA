from __future__ import annotations

import time
import uuid
from typing import Any, Callable, Generic, TypeVar

import z3

from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract, NamedConstraint
from epca.runtime.decision import (
    DecisionStatus,
    EvaluationContext,
    TicketAuthority,
    TimingBreakdown,
    VerificationContext,
    VerificationDecision,
)
from epca.runtime.policy import PolicySet
from epca.runtime.state import CanonicalState, StateSnapshot


StateT = TypeVar("StateT", bound=CanonicalState)
SymbolsFactory = Callable[[], Any]
BindingsFactory = Callable[..., tuple[NamedConstraint, ...]]


def _context(
    *,
    monitor: str,
    evaluation: EvaluationContext,
    action: ActionProposal,
    snapshot: StateSnapshot[StateT],
    post_state: StateT,
    policy: PolicySet[StateT],
    contract: ActionContract[StateT],
) -> VerificationContext:
    return VerificationContext(
        run_id=evaluation.run_id,
        environment=evaluation.environment,
        monitor=monitor,
        action_digest=action.digest,
        pre_state_digest=snapshot.state_digest,
        pre_state_version=snapshot.state_version,
        post_state_digest=post_state.digest,
        policy_digest=policy.policy_digest,
        policy_version=policy.policy_version,
        contract_digest=contract.contract_digest,
        contract_version=contract.contract_version,
        session_id=action.session_id,
        principal_id=action.principal_id,
        decision_id=uuid.uuid4().hex,
    )


class DecisionIssuer(Generic[StateT]):
    """Shared binding/ticket issuer used by all monitor conditions."""

    def __init__(self, authority: TicketAuthority) -> None:
        self.authority = authority

    def from_rule(
        self,
        *,
        monitor: str,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[StateT],
        action: ActionProposal,
        contract: ActionContract[StateT],
        policy: PolicySet[StateT],
        allow: bool,
        reason: str,
        violated_invariants: tuple[str, ...] = (),
        base_timings: TimingBreakdown = TimingBreakdown(),
        request_started: float | None = None,
    ) -> VerificationDecision:
        transition_start = time.perf_counter()
        post_state = contract.transition(snapshot.state, action)
        transition_ms = (time.perf_counter() - transition_start) * 1000.0
        context = _context(
            monitor=monitor,
            evaluation=evaluation,
            action=action,
            snapshot=snapshot,
            post_state=post_state,
            policy=policy,
            contract=contract,
        )
        binding_start = time.perf_counter()
        ticket = None
        if allow:
            ticket = self.authority.issue(
                action=action,
                pre_state=snapshot.state,
                post_state=post_state,
                context=context,
            )
        binding_ms = (time.perf_counter() - binding_start) * 1000.0
        monitor_total_ms = (
            (time.perf_counter() - request_started) * 1000.0
            if request_started is not None
            else base_timings.schema_validation_ms + base_timings.state_snapshot_ms + transition_ms + binding_ms
        )
        timings = base_timings.merged(
            transition_derivation_ms=transition_ms,
            binding_ms=binding_ms,
            monitor_total_ms=monitor_total_ms,
        )
        return VerificationDecision(
            status=DecisionStatus.ALLOW if allow else DecisionStatus.BLOCK,
            reason=reason,
            context=context,
            violated_invariants=violated_invariants,
            solver_result="not_run",
            conflict_explanation=(),
            timings=timings,
            ticket=ticket,
        )


class EPCAVerifier(Generic[StateT]):
    """Deterministic exact-transition Z3 verifier for a registered environment."""

    monitor_name = "epca"

    def __init__(
        self,
        *,
        authority: TicketAuthority,
        symbols_factory: SymbolsFactory,
        bindings_factory: BindingsFactory,
    ) -> None:
        self.authority = authority
        self.symbols_factory = symbols_factory
        self.bindings_factory = bindings_factory

    def verify(
        self,
        *,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[StateT],
        action: ActionProposal,
        contract: ActionContract[StateT],
        policy: PolicySet[StateT],
        base_timings: TimingBreakdown = TimingBreakdown(),
        request_started: float | None = None,
    ) -> VerificationDecision:
        try:
            if evaluation.environment != snapshot.environment:
                raise ValueError("evaluation environment does not match state snapshot")
            if action.session_id != snapshot.session_id:
                raise ValueError("action session does not match state snapshot")
            if snapshot.state.policy_version != policy.policy_version:
                raise ValueError("trusted state policy version does not match active policy")
            if not contract.accepts(action):
                raise ValueError("action does not match the registered contract")

            transition_start = time.perf_counter()
            post_state = contract.transition(snapshot.state, action)
            transition_ms = (time.perf_counter() - transition_start) * 1000.0

            compile_start = time.perf_counter()
            symbols = self.symbols_factory()
            bindings = self.bindings_factory(
                symbols,
                pre_state=snapshot.state,
                action=action,
                post_state=post_state,
                policy_version=policy.policy_version,
                contract_version=contract.contract_version,
            )
            transition_constraints = contract.compile_transition(symbols, action)
            invariant_constraints = policy.compile(symbols, action)
            compile_ms = (time.perf_counter() - compile_start) * 1000.0

            solver = z3.Solver()
            solver.set(unsat_core=True)
            descriptions: dict[str, str] = {}
            for item in (*bindings, *transition_constraints, *invariant_constraints):
                label = z3.Bool(item.name)
                solver.assert_and_track(item.formula, label)
                descriptions[item.name] = item.description

            solver_start = time.perf_counter()
            solver_result = solver.check()
            solver_ms = (time.perf_counter() - solver_start) * 1000.0

            context = _context(
                monitor=self.monitor_name,
                evaluation=evaluation,
                action=action,
                snapshot=snapshot,
                post_state=post_state,
                policy=policy,
                contract=contract,
            )

            binding_start = time.perf_counter()
            ticket = None
            status: DecisionStatus
            reason: str
            violated = policy.violated(snapshot.state, action, post_state)
            conflict: tuple[str, ...] = ()
            error: str | None = None
            if solver_result == z3.sat:
                if violated:
                    raise RuntimeError("Python policy evaluator and SMT encoding disagree on a SAT transition")
                ticket = self.authority.issue(
                    action=action,
                    pre_state=snapshot.state,
                    post_state=post_state,
                    context=context,
                )
                status = DecisionStatus.ALLOW
                reason = "exact_transition_satisfies_policy"
            elif solver_result == z3.unsat:
                core_names = tuple(str(item) for item in solver.unsat_core())
                conflict = tuple(descriptions.get(name, name) for name in core_names)
                core_invariants = tuple(
                    name.split("invariant::", 1)[1]
                    for name in core_names
                    if name.startswith("invariant::")
                )
                violated = tuple(dict.fromkeys((*violated, *core_invariants)))
                if violated:
                    status = DecisionStatus.BLOCK
                    reason = "policy_invariant_conflict"
                else:
                    status = DecisionStatus.ERROR
                    reason = "formal_contract_or_binding_conflict"
                    error = "UNSAT without a violated policy invariant"
            else:
                status = DecisionStatus.ERROR
                reason = "solver_unknown"
                error = solver.reason_unknown()
            binding_ms = (time.perf_counter() - binding_start) * 1000.0
            monitor_total_ms = (
                (time.perf_counter() - request_started) * 1000.0
                if request_started is not None
                else base_timings.schema_validation_ms
                + base_timings.state_snapshot_ms
                + transition_ms
                + compile_ms
                + solver_ms
                + binding_ms
            )
            timings = base_timings.merged(
                transition_derivation_ms=transition_ms,
                constraint_compilation_ms=compile_ms,
                solver_ms=solver_ms,
                binding_ms=binding_ms,
                monitor_total_ms=monitor_total_ms,
            )
            return VerificationDecision(
                status=status,
                reason=reason,
                context=context,
                violated_invariants=violated,
                solver_result=str(solver_result),
                conflict_explanation=conflict,
                timings=timings,
                ticket=ticket,
                error=error,
            )
        except Exception as exc:
            monitor_total_ms = (
                (time.perf_counter() - request_started) * 1000.0
                if request_started is not None
                else base_timings.monitor_total_ms
            )
            return VerificationDecision(
                status=DecisionStatus.ERROR,
                reason="verification_error",
                context=None,
                violated_invariants=(),
                solver_result="error",
                conflict_explanation=(),
                timings=base_timings.merged(monitor_total_ms=monitor_total_ms),
                error=f"{type(exc).__name__}: {exc}",
            )
