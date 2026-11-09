from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from epca.runtime.hashing import canonical_json, sha256_digest


@dataclass(frozen=True)
class CertificateObligation:
    name: str
    claimed_satisfied: bool
    witness: tuple[tuple[str, str], ...]

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "claimed_satisfied": self.claimed_satisfied,
            "witness": [list(item) for item in self.witness],
        }


@dataclass(frozen=True)
class ActionCertificate:
    environment: str
    action_payload: dict[str, Any]
    action_digest: str
    pre_state_payload: dict[str, Any]
    pre_state_hash: str
    pre_state_version: int
    claimed_post_state: dict[str, Any]
    post_state_hash: str
    policy_version: str
    policy_digest: str
    contract_version: str
    contract_digest: str
    session_id: str
    principal_id: str
    obligations: tuple[CertificateObligation, ...]
    producer_id: str = "deterministic-symbolic-v1"

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "action_payload": self.action_payload,
            "action_digest": self.action_digest,
            "pre_state_payload": self.pre_state_payload,
            "pre_state_hash": self.pre_state_hash,
            "pre_state_version": self.pre_state_version,
            "claimed_post_state": self.claimed_post_state,
            "post_state_hash": self.post_state_hash,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "contract_version": self.contract_version,
            "contract_digest": self.contract_digest,
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "obligations": [item.canonical_payload for item in self.obligations],
            "producer_id": self.producer_id,
        }

    @property
    def canonical_serialization(self) -> str:
        return canonical_json(self.canonical_payload)

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_payload)

    @property
    def size_bytes(self) -> int:
        return len(self.canonical_serialization.encode("utf-8"))
