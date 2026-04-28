from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GuardrailState:
    current_outflow: float
    current_limit: float
    agent_privilege: int
    turn_index: int
    history: list[str] = field(default_factory=list)


@dataclass
class GuardrailVerdict:
    decision: str
    reason: str
    rollback_applied: bool
    verification_latency_ms: float
    unsat_core_names: list[str] = field(default_factory=list)
    unsat_core_details: list[str] = field(default_factory=list)
    guardrail_metadata: dict[str, Any] = field(default_factory=dict)
    next_state: dict[str, float] | None = None


class BaseGuardrail(ABC):
    guardrail_name: str

    @abstractmethod
    def evaluate_action(self, state: GuardrailState, action_payload: dict[str, Any]) -> GuardrailVerdict:
        raise NotImplementedError
