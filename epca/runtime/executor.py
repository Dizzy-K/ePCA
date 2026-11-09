from __future__ import annotations

import threading
import time
from typing import Generic, Protocol, TypeVar

from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract, ContractRegistry
from epca.runtime.decision import ExecutionResult, ExecutionTicket, TicketAuthority
from epca.runtime.policy import PolicyRegistry
from epca.runtime.state import CanonicalState, StateVersionError, VersionedStateStore


StateT = TypeVar("StateT", bound=CanonicalState)


class EffectExecutor(Protocol[StateT]):
    def execute(
        self,
        action: ActionProposal,
        pre_state: StateT,
        contract: ActionContract[StateT],
    ) -> StateT: ...


class BoundExecutor(Generic[StateT]):
    """Only execution path: authenticated ticket + atomic freshness checks + commit."""

    def __init__(
        self,
        *,
        environment: str,
        state_store: VersionedStateStore[StateT],
        contracts: ContractRegistry[StateT],
        policies: PolicyRegistry[StateT],
        authority: TicketAuthority,
        effect_executor: EffectExecutor[StateT],
        configuration_lock: threading.RLock,
    ) -> None:
        self.environment = environment
        self.state_store = state_store
        self.contracts = contracts
        self.policies = policies
        self.authority = authority
        self.effect_executor = effect_executor
        self.configuration_lock = configuration_lock

    def execute(self, ticket: ExecutionTicket) -> ExecutionResult:
        binding_start = time.perf_counter()
        try:
            if not self.authority.verify(ticket):
                return self._reject(ticket, "ticket_authentication_failed", binding_start)
            context = ticket.context
            if context.environment != self.environment:
                return self._reject(ticket, "environment_binding_mismatch", binding_start)
            if ticket.action.session_id != context.session_id or ticket.action.principal_id != context.principal_id:
                return self._reject(ticket, "identity_binding_mismatch", binding_start)
            if ticket.action.digest != context.action_digest:
                return self._reject(ticket, "action_digest_mismatch", binding_start)
            if ticket.pre_state.digest != context.pre_state_digest:
                return self._reject(ticket, "pre_state_digest_mismatch", binding_start)
            if ticket.pre_state.state_version != context.pre_state_version:
                return self._reject(ticket, "pre_state_version_mismatch", binding_start)
            if ticket.post_state.digest != context.post_state_digest:
                return self._reject(ticket, "post_state_digest_mismatch", binding_start)
            if ticket.post_state.state_version != ticket.pre_state.state_version + 1:
                return self._reject(ticket, "post_state_version_mismatch", binding_start)

            with self.configuration_lock:
                policy = self.policies.active
                contract = self.contracts.active_for(ticket.action.action)
                if policy.policy_version != context.policy_version or policy.policy_digest != context.policy_digest:
                    return self._reject(ticket, "policy_version_or_digest_mismatch", binding_start)
                if (
                    contract.contract_version != context.contract_version
                    or contract.contract_digest != context.contract_digest
                ):
                    return self._reject(ticket, "contract_version_or_digest_mismatch", binding_start)

                with self.state_store.locked(context.session_id) as locked:
                    current = locked.current
                    if current.state_version != context.pre_state_version or current.digest != context.pre_state_digest:
                        return self._reject(ticket, "stale_state", binding_start)
                    if current.policy_version != context.policy_version:
                        return self._reject(ticket, "state_policy_version_mismatch", binding_start)

                    derived = contract.transition(current, ticket.action)
                    if derived.digest != context.post_state_digest or derived != ticket.post_state:
                        return self._reject(ticket, "derived_post_state_binding_mismatch", binding_start)
                    binding_ms = (time.perf_counter() - binding_start) * 1000.0

                    execution_start = time.perf_counter()
                    executed_state = self.effect_executor.execute(ticket.action, current, contract)
                    execution_ms = (time.perf_counter() - execution_start) * 1000.0
                    if executed_state != ticket.post_state or executed_state.digest != context.post_state_digest:
                        return ExecutionResult(
                            executed=False,
                            commit_success=False,
                            reason="executor_effect_mismatch",
                            decision_id=context.decision_id,
                            new_state=None,
                            new_state_version=None,
                            binding_ms=binding_ms,
                            execution_ms=execution_ms,
                        )

                    commit_start = time.perf_counter()
                    committed = locked.commit(executed_state, expected_version=context.pre_state_version)
                    commit_ms = (time.perf_counter() - commit_start) * 1000.0
                    return ExecutionResult(
                        executed=True,
                        commit_success=True,
                        reason="committed",
                        decision_id=context.decision_id,
                        new_state=committed,
                        new_state_version=committed.state_version,
                        binding_ms=binding_ms,
                        execution_ms=execution_ms,
                        state_commit_ms=commit_ms,
                    )
        except StateVersionError as exc:
            return ExecutionResult(
                executed=False,
                commit_success=False,
                reason="stale_state",
                decision_id=ticket.context.decision_id,
                new_state=None,
                new_state_version=None,
                binding_ms=(time.perf_counter() - binding_start) * 1000.0,
                error=str(exc),
            )
        except Exception as exc:
            return ExecutionResult(
                executed=False,
                commit_success=False,
                reason="execution_error",
                decision_id=getattr(ticket.context, "decision_id", None),
                new_state=None,
                new_state_version=None,
                binding_ms=(time.perf_counter() - binding_start) * 1000.0,
                error=f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _reject(ticket: ExecutionTicket, reason: str, binding_start: float) -> ExecutionResult:
        return ExecutionResult(
            executed=False,
            commit_success=False,
            reason=reason,
            decision_id=ticket.context.decision_id,
            new_state=None,
            new_state_version=None,
            binding_ms=(time.perf_counter() - binding_start) * 1000.0,
        )
