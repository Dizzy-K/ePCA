from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Generic, TypeVar

import z3

from epca.runtime.action import ActionProposal
from epca.runtime.contract import NamedConstraint
from epca.runtime.hashing import sha256_digest
from epca.runtime.state import CanonicalState


StateT = TypeVar("StateT", bound=CanonicalState)


@dataclass(frozen=True)
class SecurityInvariant(Generic[StateT]):
    name: str
    description: str
    semantics_id: str
    evaluate_fn: Callable[[StateT, ActionProposal, StateT], bool]
    compile_fn: Callable[[Any, ActionProposal], z3.BoolRef]

    def evaluate(self, pre_state: StateT, action: ActionProposal, post_state: StateT) -> bool:
        return bool(self.evaluate_fn(pre_state, action, post_state))

    def compile(self, symbols: Any, action: ActionProposal) -> NamedConstraint:
        return NamedConstraint(
            name=f"invariant::{self.name}",
            formula=self.compile_fn(symbols, action),
            description=self.description,
        )

    @property
    def canonical_spec(self) -> dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "semantics_id": self.semantics_id,
        }


@dataclass(frozen=True)
class PolicySet(Generic[StateT]):
    policy_version: str
    invariants: tuple[SecurityInvariant[StateT], ...]

    @property
    def canonical_spec(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "invariants": [invariant.canonical_spec for invariant in self.invariants],
        }

    @property
    def policy_digest(self) -> str:
        return sha256_digest(self.canonical_spec)

    def violated(self, pre_state: StateT, action: ActionProposal, post_state: StateT) -> tuple[str, ...]:
        return tuple(
            invariant.name
            for invariant in self.invariants
            if not invariant.evaluate(pre_state, action, post_state)
        )

    def compile(self, symbols: Any, action: ActionProposal) -> tuple[NamedConstraint, ...]:
        return tuple(invariant.compile(symbols, action) for invariant in self.invariants)


class PolicyRegistry(Generic[StateT]):
    def __init__(self, active: PolicySet[StateT]) -> None:
        self._active = active

    @property
    def active(self) -> PolicySet[StateT]:
        return self._active

    def activate(self, policy: PolicySet[StateT]) -> None:
        self._active = policy
