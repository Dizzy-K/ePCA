from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from epca.runtime.action import ActionProposal
from epca.runtime.hashing import canonical_json, sha256_digest
from epca.runtime.state import CanonicalState


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ERROR = "error"


@dataclass(frozen=True)
class TimingBreakdown:
    schema_validation_ms: float = 0.0
    state_snapshot_ms: float = 0.0
    transition_derivation_ms: float = 0.0
    constraint_compilation_ms: float = 0.0
    solver_ms: float = 0.0
    binding_ms: float = 0.0
    execution_ms: float = 0.0
    state_commit_ms: float = 0.0
    monitor_total_ms: float = 0.0

    def merged(self, **updates: float) -> "TimingBreakdown":
        return replace(self, **updates)

    @property
    def canonical_payload(self) -> dict[str, float]:
        return {
            "schema_validation_ms": self.schema_validation_ms,
            "state_snapshot_ms": self.state_snapshot_ms,
            "transition_derivation_ms": self.transition_derivation_ms,
            "constraint_compilation_ms": self.constraint_compilation_ms,
            "solver_ms": self.solver_ms,
            "binding_ms": self.binding_ms,
            "execution_ms": self.execution_ms,
            "state_commit_ms": self.state_commit_ms,
            "monitor_total_ms": self.monitor_total_ms,
        }


@dataclass(frozen=True)
class EvaluationContext:
    run_id: str
    environment: str
    scenario_label: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        environment: str,
        scenario_label: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "EvaluationContext":
        normalized = tuple(sorted((str(key), str(value)) for key, value in (metadata or {}).items()))
        return cls(run_id=run_id, environment=environment, scenario_label=scenario_label, metadata=normalized)


@dataclass(frozen=True)
class VerificationContext:
    run_id: str
    environment: str
    monitor: str
    action_digest: str
    pre_state_digest: str
    pre_state_version: int
    post_state_digest: str
    policy_digest: str
    policy_version: str
    contract_digest: str
    contract_version: str
    session_id: str
    principal_id: str
    decision_id: str

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "environment": self.environment,
            "monitor": self.monitor,
            "action_digest": self.action_digest,
            "pre_state_digest": self.pre_state_digest,
            "pre_state_version": self.pre_state_version,
            "post_state_digest": self.post_state_digest,
            "policy_digest": self.policy_digest,
            "policy_version": self.policy_version,
            "contract_digest": self.contract_digest,
            "contract_version": self.contract_version,
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "decision_id": self.decision_id,
        }


@dataclass(frozen=True)
class ExecutionTicket:
    action: ActionProposal
    pre_state: CanonicalState
    post_state: CanonicalState
    context: VerificationContext
    auth_tag: str

    @property
    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "action": self.action.canonical_payload,
            "pre_state": self.pre_state.canonical_payload,
            "post_state": self.post_state.canonical_payload,
            "context": self.context.canonical_payload,
        }

    @property
    def ticket_digest(self) -> str:
        return sha256_digest({**self.unsigned_payload, "auth_tag": self.auth_tag})


class TicketAuthority:
    """Per-runtime HMAC authority; the secret never leaves the trusted process."""

    def __init__(self, secret_key: bytes | None = None) -> None:
        self._secret_key = secret_key or secrets.token_bytes(32)

    def issue(
        self,
        *,
        action: ActionProposal,
        pre_state: CanonicalState,
        post_state: CanonicalState,
        context: VerificationContext,
    ) -> ExecutionTicket:
        unsigned = ExecutionTicket(
            action=action,
            pre_state=pre_state,
            post_state=post_state,
            context=context,
            auth_tag="",
        )
        return replace(unsigned, auth_tag=self._tag(unsigned.unsigned_payload))

    def verify(self, ticket: ExecutionTicket) -> bool:
        expected = self._tag(ticket.unsigned_payload)
        return hmac.compare_digest(expected, ticket.auth_tag)

    def _tag(self, payload: dict[str, Any]) -> str:
        return hmac.new(
            self._secret_key,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


@dataclass(frozen=True)
class VerificationDecision:
    status: DecisionStatus
    reason: str
    context: VerificationContext | None
    violated_invariants: tuple[str, ...]
    solver_result: str
    conflict_explanation: tuple[str, ...]
    timings: TimingBreakdown
    ticket: ExecutionTicket | None = None
    error: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    executed: bool
    commit_success: bool
    reason: str
    decision_id: str | None
    new_state: CanonicalState | None
    new_state_version: int | None
    binding_ms: float = 0.0
    execution_ms: float = 0.0
    state_commit_ms: float = 0.0
    error: str | None = None
