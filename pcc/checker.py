from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from epca.runtime.action import ActionProposal
from epca.runtime.contract import ActionContract
from epca.runtime.hashing import sha256_digest
from epca.runtime.policy import PolicySet
from epca.runtime.state import StateSnapshot
from pcc.certificate import ActionCertificate
from pcc.obligations import evaluate_obligations


@dataclass(frozen=True)
class CertificateCheck:
    accepted: bool
    reason: str
    violated_obligations: tuple[str, ...]
    derived_post_state: Any | None


class ConcreteCertificateChecker:
    """Independent concrete witness checker; it never invokes the ePCA verifier."""

    def check(
        self,
        *,
        environment: str,
        snapshot: StateSnapshot[Any],
        action: ActionProposal,
        contract: ActionContract[Any],
        policy: PolicySet[Any],
        certificate: ActionCertificate | None,
    ) -> CertificateCheck:
        if certificate is None:
            return CertificateCheck(False, "missing_certificate", (), None)
        if certificate.environment != environment:
            return CertificateCheck(False, "environment_binding_mismatch", (), None)
        if certificate.action_payload != action.canonical_payload or certificate.action_digest != action.digest:
            return CertificateCheck(False, "action_binding_mismatch", (), None)
        if (
            certificate.session_id != action.session_id
            or certificate.principal_id != action.principal_id
        ):
            return CertificateCheck(False, "identity_binding_mismatch", (), None)
        if (
            certificate.pre_state_version != snapshot.state_version
            or certificate.pre_state_hash != snapshot.state_digest
            or certificate.pre_state_payload != snapshot.state.canonical_payload
        ):
            return CertificateCheck(False, "stale_certificate", (), None)
        if certificate.policy_version != policy.policy_version or certificate.policy_digest != policy.policy_digest:
            return CertificateCheck(False, "policy_binding_mismatch", (), None)
        if (
            certificate.contract_version != contract.contract_version
            or certificate.contract_digest != contract.contract_digest
        ):
            return CertificateCheck(False, "contract_binding_mismatch", (), None)

        derived_post = contract.transition(snapshot.state, action)
        if (
            certificate.claimed_post_state != derived_post.canonical_payload
            or certificate.post_state_hash != derived_post.digest
            or sha256_digest(certificate.claimed_post_state) != certificate.post_state_hash
        ):
            return CertificateCheck(False, "post_state_transition_mismatch", (), derived_post)

        expected = evaluate_obligations(environment, snapshot.state, action, derived_post)
        supplied = {item.name: item for item in certificate.obligations}
        if set(supplied) != set(expected):
            return CertificateCheck(False, "obligation_set_mismatch", (), derived_post)
        for name, actual in expected.items():
            item = supplied[name]
            witness = dict(item.witness)
            if (
                witness.get("pre_state_hash") != snapshot.state_digest
                or witness.get("action_digest") != action.digest
                or witness.get("post_state_hash") != derived_post.digest
                or witness.get("claim") != str(actual).lower()
                or item.claimed_satisfied != actual
            ):
                return CertificateCheck(False, "invalid_obligation_witness", (name,), derived_post)
        violated = tuple(name for name, satisfied in expected.items() if not satisfied)
        if violated:
            return CertificateCheck(False, "safety_obligation_failed", violated, derived_post)
        return CertificateCheck(True, "certificate_valid", (), derived_post)
