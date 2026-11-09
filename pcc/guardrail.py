from __future__ import annotations

import time
from typing import Any, Generic, TypeVar

from epca.guardrails.base import Guardrail
from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.decision import EvaluationContext, TimingBreakdown, VerificationDecision
from epca.runtime.policy import PolicySet
from epca.runtime.state import CanonicalState, StateSnapshot
from epca.runtime.verifier import DecisionIssuer
from pcc.certificate import ActionCertificate
from pcc.checker import ConcreteCertificateChecker
from pcc.producer import DeterministicCertificateProducer


StateT = TypeVar("StateT", bound=CanonicalState)


class PCCActionGuardrail(Guardrail[StateT], Generic[StateT]):
    name = "pcc_action"

    def __init__(
        self,
        *,
        environment: str,
        issuer: DecisionIssuer[StateT],
        producer: DeterministicCertificateProducer | None = None,
        checker: ConcreteCertificateChecker | None = None,
    ) -> None:
        self.environment = environment
        self.issuer = issuer
        self.producer = producer or DeterministicCertificateProducer()
        self.checker = checker or ConcreteCertificateChecker()
        self.last_certificate: ActionCertificate | None = None
        self.last_generation_ms = 0.0
        self.last_checking_ms = 0.0
        self.last_certificate_size = 0
        self.samples: list[dict[str, float | int | bool]] = []

    def evaluate(
        self,
        *,
        evaluation: EvaluationContext,
        snapshot: StateSnapshot[StateT],
        action: ActionProposal,
        contract: ActionContract[StateT],
        policy: PolicySet[StateT],
        base_timings: TimingBreakdown,
        request_started: float,
    ) -> VerificationDecision:
        generation_started = time.perf_counter()
        certificate = self.producer.produce(
            environment=self.environment,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
        )
        self.last_generation_ms = (time.perf_counter() - generation_started) * 1000.0
        checking_started = time.perf_counter()
        checked = self.checker.check(
            environment=self.environment,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            certificate=certificate,
        )
        self.last_checking_ms = (time.perf_counter() - checking_started) * 1000.0
        self.last_certificate = certificate
        self.last_certificate_size = certificate.size_bytes if certificate is not None else 0
        self.samples.append(
            {
                "generation_ms": self.last_generation_ms,
                "checking_ms": self.last_checking_ms,
                "total_verification_ms": self.last_generation_ms + self.last_checking_ms,
                "certificate_size_bytes": self.last_certificate_size,
                "accepted": checked.accepted,
            }
        )
        timings = base_timings.merged(
            constraint_compilation_ms=self.last_generation_ms,
            solver_ms=self.last_checking_ms,
        )
        return self.issuer.from_rule(
            monitor=self.name,
            evaluation=evaluation,
            snapshot=snapshot,
            action=action,
            contract=contract,
            policy=policy,
            allow=checked.accepted,
            reason=checked.reason,
            violated_invariants=checked.violated_obligations,
            base_timings=timings,
            request_started=request_started,
        )
