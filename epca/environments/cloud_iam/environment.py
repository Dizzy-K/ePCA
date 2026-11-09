from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from epca.environments.cloud_iam.actions import CLOUD_IAM_ACTION_SCHEMAS
from epca.environments.cloud_iam.contracts import cloud_iam_contract_registry
from epca.environments.cloud_iam.executor import CloudIAMEffectExecutor
from epca.environments.cloud_iam.formal import create_symbols, exact_bindings
from epca.environments.cloud_iam.guardrails import CloudIAMStatelessRuleFilter
from epca.environments.cloud_iam.policies import default_cloud_iam_policy
from epca.environments.cloud_iam.state import CloudIAMState, initial_cloud_iam_state
from epca.guardrails import EPCAGuardrail, NoGuard, StatefulRuleMonitor
from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal, SchemaValidator
from epca.runtime.contract import ActionContract
from epca.runtime.decision import DecisionStatus, EvaluationContext, ExecutionResult, TicketAuthority, TimingBreakdown, VerificationDecision
from epca.runtime.executor import BoundExecutor
from epca.runtime.logging import StructuredTraceLogger
from epca.runtime.policy import PolicyRegistry, PolicySet
from epca.runtime.state import StateSnapshot, VersionedStateStore
from epca.runtime.verifier import DecisionIssuer, EPCAVerifier
from pcc.guardrail import PCCActionGuardrail


CLOUD_IAM_ENVIRONMENT = "cloud_iam"


@dataclass(frozen=True)
class EvaluatedIAMAction:
    evaluation: EvaluationContext
    snapshot: StateSnapshot[CloudIAMState]
    action: ActionProposal
    contract: ActionContract[CloudIAMState]
    policy: PolicySet[CloudIAMState]
    derived_post_state: CloudIAMState
    decision: VerificationDecision


@dataclass(frozen=True)
class IAMProcessResult:
    evaluated: EvaluatedIAMAction
    execution: ExecutionResult


class CloudIAMRuntime:
    def __init__(self, *, trace_path: Path | None = None) -> None:
        self.configuration_lock = threading.RLock()
        self.validator = SchemaValidator(CLOUD_IAM_ACTION_SCHEMAS)
        self.state_store: VersionedStateStore[CloudIAMState] = VersionedStateStore(CLOUD_IAM_ENVIRONMENT)
        self.contracts = cloud_iam_contract_registry()
        self.policies = PolicyRegistry(default_cloud_iam_policy())
        self.ticket_authority = TicketAuthority()
        self.issuer: DecisionIssuer[CloudIAMState] = DecisionIssuer(self.ticket_authority)
        self.verifier: EPCAVerifier[CloudIAMState] = EPCAVerifier(authority=self.ticket_authority, symbols_factory=create_symbols, bindings_factory=exact_bindings)
        self.guardrails: dict[str, Guardrail[CloudIAMState]] = {
            "no_guard": NoGuard(self.issuer),
            "stateless_rule_filter": CloudIAMStatelessRuleFilter(self.issuer),
            "stateful_rule": StatefulRuleMonitor(self.issuer),
            "pcc_action": PCCActionGuardrail(environment=CLOUD_IAM_ENVIRONMENT, issuer=self.issuer),
            "epca": EPCAGuardrail(self.verifier),
        }
        self.effect_executor = CloudIAMEffectExecutor()
        self.bound_executor = BoundExecutor(
            environment=CLOUD_IAM_ENVIRONMENT,
            state_store=self.state_store,
            contracts=self.contracts,
            policies=self.policies,
            authority=self.ticket_authority,
            effect_executor=self.effect_executor,
            configuration_lock=self.configuration_lock,
        )
        self.trace_logger = StructuredTraceLogger(trace_path)

    def create_session(self, session_id: str, initial_state: CloudIAMState | None = None) -> None:
        state = initial_state or initial_cloud_iam_state(policy_version=self.policies.active.policy_version)
        if state.policy_version != self.policies.active.policy_version:
            raise ValueError("Initial state policy version must match active policy")
        self.state_store.create(session_id, state)

    def snapshot(self, session_id: str) -> StateSnapshot[CloudIAMState]:
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
    ) -> EvaluatedIAMAction:
        request_started = time.perf_counter()
        started = time.perf_counter()
        action = self.validator.validate(payload, principal_id=principal_id, session_id=session_id)
        schema_ms = (time.perf_counter() - started) * 1000.0
        started = time.perf_counter()
        snapshot = self.state_store.snapshot(session_id)
        snapshot_ms = (time.perf_counter() - started) * 1000.0
        evaluation = EvaluationContext.create(run_id=run_id or uuid.uuid4().hex, environment=CLOUD_IAM_ENVIRONMENT, scenario_label=scenario_label, metadata=metadata)
        try:
            guardrail = self.guardrails[monitor]
        except KeyError as exc:
            raise ValueError(f"Unknown monitor: {monitor}") from exc
        with self.configuration_lock:
            contract = self.contracts.active_for(action.action)
            policy = self.policies.active
        post = contract.transition(snapshot.state, action)
        decision = guardrail.evaluate(
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            base_timings=TimingBreakdown(schema_validation_ms=schema_ms, state_snapshot_ms=snapshot_ms),
            request_started=request_started,
        )
        evaluated = EvaluatedIAMAction(evaluation, snapshot, action, contract, policy, post, decision)
        if _log_decision:
            self._log(evaluated, ExecutionResult(False, False, "verification_only_not_executed", decision.context.decision_id if decision.context else None, None, None))
        return evaluated

    def execute(self, evaluated: EvaluatedIAMAction) -> ExecutionResult:
        if evaluated.decision.status != DecisionStatus.ALLOW or evaluated.decision.ticket is None:
            result = ExecutionResult(False, False, "decision_not_allowed", evaluated.decision.context.decision_id if evaluated.decision.context else None, None, None)
        else:
            result = self.bound_executor.execute(evaluated.decision.ticket)
        self._log(evaluated, result)
        return result

    def process(self, payload: dict[str, Any], **kwargs: Any) -> IAMProcessResult:
        kwargs.pop("_log_decision", None)
        evaluated = self.evaluate(payload, _log_decision=False, **kwargs)
        return IAMProcessResult(evaluated, self.execute(evaluated))

    def _log(self, evaluated: EvaluatedIAMAction, execution: ExecutionResult) -> None:
        self.trace_logger.record(evaluation=evaluated.evaluation, snapshot=evaluated.snapshot, action=evaluated.action, post_state=evaluated.derived_post_state, contract=evaluated.contract, policy=evaluated.policy, decision=evaluated.decision, execution=execution)

    def administrative_update(self, session_id: str, **updates: Any) -> CloudIAMState:
        def apply(current: CloudIAMState) -> CloudIAMState:
            return CloudIAMState.model_validate({**current.canonical_payload, **updates, "state_version": current.state_version + 1})
        return self.state_store.administrative_update(session_id, apply)

    def activate_policy(self, policy: PolicySet[CloudIAMState]) -> None:
        with self.configuration_lock:
            self.policies.activate(policy)
            for session_id in self.state_store.sessions():
                self.administrative_update(session_id, policy_version=policy.policy_version)

    def activate_contract(self, contract: ActionContract[CloudIAMState]) -> None:
        with self.configuration_lock:
            self.contracts.activate(contract)
