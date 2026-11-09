from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from epca.environments.financial.contracts import financial_contract_registry
from epca.environments.financial.actions import FINANCIAL_ACTION_SCHEMAS
from epca.environments.financial.executor import FinancialEffectExecutor
from epca.environments.financial.formal import create_symbols, exact_bindings
from epca.environments.financial.legacy_adapter import adapt_legacy_action
from epca.environments.financial.policies import default_financial_policy
from epca.environments.financial.state import FinancialState, initial_financial_state
from epca.guardrails import EPCAGuardrail, NoGuard, StatefulRuleMonitor, StatelessRuleFilter
from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal, SchemaValidator
from epca.runtime.contract import ActionContract
from epca.runtime.decision import (
    DecisionStatus,
    EvaluationContext,
    ExecutionResult,
    TicketAuthority,
    TimingBreakdown,
    VerificationDecision,
)
from epca.runtime.executor import BoundExecutor
from epca.runtime.logging import StructuredTraceLogger
from epca.runtime.policy import PolicyRegistry, PolicySet
from epca.runtime.state import StateSnapshot, VersionedStateStore
from epca.runtime.verifier import DecisionIssuer, EPCAVerifier
from pcc.guardrail import PCCActionGuardrail


FINANCIAL_ENVIRONMENT = "financial"


@dataclass(frozen=True)
class EvaluatedAction:
    evaluation: EvaluationContext
    snapshot: StateSnapshot[FinancialState]
    action: ActionProposal
    contract: ActionContract[FinancialState]
    policy: PolicySet[FinancialState]
    derived_post_state: FinancialState
    decision: VerificationDecision


@dataclass(frozen=True)
class ProcessResult:
    evaluated: EvaluatedAction
    execution: ExecutionResult


class FinancialRuntime:
    """One shared Financial environment for all Phase 1 monitor conditions."""

    def __init__(
        self,
        *,
        trace_path: Path | None = None,
        policy_version: str = "financial-policy-v1",
    ) -> None:
        self.configuration_lock = threading.RLock()
        self.validator = SchemaValidator(FINANCIAL_ACTION_SCHEMAS)
        self.state_store: VersionedStateStore[FinancialState] = VersionedStateStore(FINANCIAL_ENVIRONMENT)
        self.contracts = financial_contract_registry(policy_version)
        self.policies = PolicyRegistry(default_financial_policy(policy_version))
        self.ticket_authority = TicketAuthority()
        self.issuer: DecisionIssuer[FinancialState] = DecisionIssuer(self.ticket_authority)
        self.verifier: EPCAVerifier[FinancialState] = EPCAVerifier(
            authority=self.ticket_authority,
            symbols_factory=create_symbols,
            bindings_factory=exact_bindings,
        )
        self.guardrails: dict[str, Guardrail[FinancialState]] = {
            "no_guard": NoGuard(self.issuer),
            "stateless_rule_filter": StatelessRuleFilter(self.issuer),
            "stateless_abac": StatelessRuleFilter(self.issuer),
            "stateful_rule": StatefulRuleMonitor(self.issuer),
            "pcc_action": PCCActionGuardrail(environment=FINANCIAL_ENVIRONMENT, issuer=self.issuer),
            "epca": EPCAGuardrail(self.verifier),
        }
        self.effect_executor = FinancialEffectExecutor()
        self.bound_executor = BoundExecutor(
            environment=FINANCIAL_ENVIRONMENT,
            state_store=self.state_store,
            contracts=self.contracts,
            policies=self.policies,
            authority=self.ticket_authority,
            effect_executor=self.effect_executor,
            configuration_lock=self.configuration_lock,
        )
        self.trace_logger = StructuredTraceLogger(trace_path)

    def create_session(self, session_id: str, initial_state: FinancialState | None = None) -> None:
        state = initial_state or initial_financial_state(policy_version=self.policies.active.policy_version)
        if state.policy_version != self.policies.active.policy_version:
            raise ValueError("Initial state policy version must match the active policy")
        self.state_store.create(session_id, state)

    def snapshot(self, session_id: str) -> StateSnapshot[FinancialState]:
        return self.state_store.snapshot(session_id)

    def evaluate(
        self,
        payload: dict[str, Any],
        *,
        principal_id: str,
        session_id: str,
        monitor: str = "epca",
        run_id: str | None = None,
        scenario_label: str | None = None,
        metadata: dict[str, Any] | None = None,
        _log_decision: bool = True,
    ) -> EvaluatedAction:
        request_started = time.perf_counter()
        validation_start = time.perf_counter()
        action = self.validator.validate(payload, principal_id=principal_id, session_id=session_id)
        schema_ms = (time.perf_counter() - validation_start) * 1000.0

        snapshot_start = time.perf_counter()
        snapshot = self.state_store.snapshot(session_id)
        snapshot_ms = (time.perf_counter() - snapshot_start) * 1000.0
        base_timings = TimingBreakdown(
            schema_validation_ms=schema_ms,
            state_snapshot_ms=snapshot_ms,
        )
        evaluation = EvaluationContext.create(
            run_id=run_id or uuid.uuid4().hex,
            environment=FINANCIAL_ENVIRONMENT,
            scenario_label=scenario_label,
            metadata=metadata,
        )
        try:
            guardrail = self.guardrails[monitor]
        except KeyError as exc:
            raise ValueError(f"Unknown monitor: {monitor}") from exc

        with self.configuration_lock:
            contract = self.contracts.active_for(action.action)
            policy = self.policies.active
        derived_post_state = contract.transition(snapshot.state, action)
        decision = guardrail.evaluate(
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            base_timings=base_timings,
            request_started=request_started,
        )
        evaluated = EvaluatedAction(
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            derived_post_state=derived_post_state,
            decision=decision,
        )
        if _log_decision:
            self._log(
                evaluated,
                ExecutionResult(
                    executed=False,
                    commit_success=False,
                    reason="verification_only_not_executed",
                    decision_id=(decision.context.decision_id if decision.context else None),
                    new_state=None,
                    new_state_version=None,
                ),
            )
        return evaluated

    def evaluate_legacy(
        self,
        payload: dict[str, Any],
        *,
        principal_id: str,
        session_id: str,
        monitor: str = "epca",
        **kwargs: Any,
    ) -> EvaluatedAction:
        canonical = adapt_legacy_action(payload, principal_id=principal_id, session_id=session_id)
        return self.evaluate(
            canonical,
            principal_id=principal_id,
            session_id=session_id,
            monitor=monitor,
            **kwargs,
        )

    def execute(self, evaluated: EvaluatedAction) -> ExecutionResult:
        if evaluated.decision.status != DecisionStatus.ALLOW or evaluated.decision.ticket is None:
            result = ExecutionResult(
                executed=False,
                commit_success=False,
                reason="decision_not_allowed",
                decision_id=(evaluated.decision.context.decision_id if evaluated.decision.context else None),
                new_state=None,
                new_state_version=None,
            )
        else:
            result = self.bound_executor.execute(evaluated.decision.ticket)
        self._log(evaluated, result)
        return result

    def process(self, payload: dict[str, Any], **kwargs: Any) -> ProcessResult:
        kwargs.pop("_log_decision", None)
        evaluated = self.evaluate(payload, _log_decision=False, **kwargs)
        execution = self.execute(evaluated)
        return ProcessResult(evaluated=evaluated, execution=execution)

    def _log(self, evaluated: EvaluatedAction, execution: ExecutionResult) -> None:
        self.trace_logger.record(
            evaluation=evaluated.evaluation,
            snapshot=evaluated.snapshot,
            action=evaluated.action,
            post_state=evaluated.derived_post_state,
            contract=evaluated.contract,
            policy=evaluated.policy,
            decision=evaluated.decision,
            execution=execution,
        )

    def administrative_update(self, session_id: str, **updates: Any) -> FinancialState:
        def apply(current: FinancialState) -> FinancialState:
            safe_updates = dict(updates)
            safe_updates["state_version"] = current.state_version + 1
            return FinancialState.model_validate({**current.canonical_payload, **safe_updates})

        return self.state_store.administrative_update(session_id, apply)

    def activate_policy(self, policy: PolicySet[FinancialState]) -> None:
        with self.configuration_lock:
            self.policies.activate(policy)
            for session_id in self.state_store.sessions():
                self.administrative_update(session_id, policy_version=policy.policy_version)

    def activate_contract(self, contract: ActionContract[FinancialState]) -> None:
        with self.configuration_lock:
            self.contracts.activate(contract)
