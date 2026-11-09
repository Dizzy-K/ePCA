from __future__ import annotations

from enum import Enum
from typing import Any

from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.policy import PolicySet
from epca.runtime.state import CanonicalState, StateSnapshot
from pcc.certificate import ActionCertificate, CertificateObligation
from pcc.obligations import evaluate_obligations


class ProducerMode(str, Enum):
    NORMAL = "normal"
    INVALID = "invalid"
    MISSING = "missing"


class DeterministicCertificateProducer:
    """External deterministic producer; none of its claims are trusted by the checker."""

    producer_id = "deterministic-symbolic-v1"

    def __init__(self, mode: ProducerMode = ProducerMode.NORMAL) -> None:
        self.mode = mode

    def produce(
        self,
        *,
        environment: str,
        snapshot: StateSnapshot[Any],
        action: ActionProposal,
        contract: ActionContract[Any],
        policy: PolicySet[Any],
    ) -> ActionCertificate | None:
        if self.mode == ProducerMode.MISSING:
            return None
        post_state = contract.transition(snapshot.state, action)
        results = evaluate_obligations(environment, snapshot.state, action, post_state)
        obligations = tuple(
            CertificateObligation(
                name=name,
                claimed_satisfied=value,
                witness=(
                    ("pre_state_hash", snapshot.state_digest),
                    ("action_digest", action.digest),
                    ("post_state_hash", post_state.digest),
                    ("claim", str(value).lower()),
                ),
            )
            for name, value in sorted(results.items())
        )
        if self.mode == ProducerMode.INVALID and obligations:
            first = obligations[0]
            obligations = (
                CertificateObligation(first.name, not first.claimed_satisfied, first.witness),
                *obligations[1:],
            )
        return ActionCertificate(
            environment=environment,
            action_payload=action.canonical_payload,
            action_digest=action.digest,
            pre_state_payload=snapshot.state.canonical_payload,
            pre_state_hash=snapshot.state_digest,
            pre_state_version=snapshot.state_version,
            claimed_post_state=post_state.canonical_payload,
            post_state_hash=post_state.digest,
            policy_version=policy.policy_version,
            policy_digest=policy.policy_digest,
            contract_version=contract.contract_version,
            contract_digest=contract.contract_digest,
            session_id=action.session_id,
            principal_id=action.principal_id,
            obligations=obligations,
            producer_id=self.producer_id,
        )
