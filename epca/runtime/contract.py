from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

import z3
from pydantic import BaseModel

from epca.runtime.action import ActionProposal
from epca.runtime.hashing import sha256_digest
from epca.runtime.state import CanonicalState


StateT = TypeVar("StateT", bound=CanonicalState)


@dataclass(frozen=True)
class NamedConstraint:
    name: str
    formula: z3.BoolRef
    description: str


class ActionContract(ABC, Generic[StateT]):
    action_name: str
    contract_version: str
    semantics_id: str
    parameter_model: type[BaseModel]

    @property
    def canonical_spec(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "contract_version": self.contract_version,
            "semantics_id": self.semantics_id,
            "parameter_schema": self.parameter_model.model_json_schema(),
        }

    @property
    def contract_digest(self) -> str:
        return sha256_digest(self.canonical_spec)

    def accepts(self, action: ActionProposal) -> bool:
        return action.action == self.action_name and isinstance(action.params, self.parameter_model)

    @abstractmethod
    def transition(self, pre_state: StateT, action: ActionProposal) -> StateT:
        """Deterministically derive the one exact post-state."""

    @abstractmethod
    def compile_transition(self, symbols: Any, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        """Compile the exact registered transition semantics to SMT."""


class ContractRegistry(Generic[StateT]):
    def __init__(self, contracts: tuple[ActionContract[StateT], ...]) -> None:
        self._active: dict[str, ActionContract[StateT]] = {}
        for contract in contracts:
            self.activate(contract)

    def activate(self, contract: ActionContract[StateT]) -> None:
        self._active[contract.action_name] = contract

    def active_for(self, action_name: str) -> ActionContract[StateT]:
        try:
            return self._active[action_name]
        except KeyError as exc:
            raise KeyError(f"No active contract for action {action_name!r}") from exc

    def active_contracts(self) -> tuple[ActionContract[StateT], ...]:
        return tuple(self._active[name] for name in sorted(self._active))
