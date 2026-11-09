from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Generic, Iterator, Protocol, TypeVar


class CanonicalState(Protocol):
    state_version: int
    policy_version: str

    @property
    def digest(self) -> str: ...

    @property
    def canonical_payload(self) -> dict[str, Any]: ...


StateT = TypeVar("StateT", bound=CanonicalState)


@dataclass(frozen=True)
class StateSnapshot(Generic[StateT]):
    environment: str
    session_id: str
    state: StateT
    state_version: int
    state_digest: str

    @classmethod
    def capture(cls, environment: str, session_id: str, state: StateT) -> "StateSnapshot[StateT]":
        return cls(
            environment=environment,
            session_id=session_id,
            state=state,
            state_version=state.state_version,
            state_digest=state.digest,
        )


class StateVersionError(RuntimeError):
    pass


class LockedState(Generic[StateT]):
    def __init__(self, store: "VersionedStateStore[StateT]", session_id: str) -> None:
        self._store = store
        self.session_id = session_id

    @property
    def current(self) -> StateT:
        return self._store._states[self.session_id]

    def commit(self, post_state: StateT, *, expected_version: int) -> StateT:
        current = self.current
        if current.state_version != expected_version:
            raise StateVersionError(
                f"stale state: expected version {expected_version}, current version {current.state_version}"
            )
        if post_state.state_version != current.state_version + 1:
            raise StateVersionError(
                "post-state version must increment exactly once: "
                f"current={current.state_version}, post={post_state.state_version}"
            )
        self._store._states[self.session_id] = post_state
        return post_state


class VersionedStateStore(Generic[StateT]):
    """Small auditable per-session lock store used by the Phase 1 simulator."""

    def __init__(self, environment: str) -> None:
        self.environment = environment
        self._states: dict[str, StateT] = {}
        self._locks: dict[str, threading.RLock] = {}
        self._registry_lock = threading.RLock()

    def create(self, session_id: str, state: StateT) -> None:
        with self._registry_lock:
            if session_id in self._states:
                raise ValueError(f"Session already exists: {session_id}")
            self._states[session_id] = state
            self._locks[session_id] = threading.RLock()

    def sessions(self) -> tuple[str, ...]:
        with self._registry_lock:
            return tuple(sorted(self._states))

    def snapshot(self, session_id: str) -> StateSnapshot[StateT]:
        lock = self._lock_for(session_id)
        with lock:
            return StateSnapshot.capture(self.environment, session_id, self._states[session_id])

    @contextmanager
    def locked(self, session_id: str) -> Iterator[LockedState[StateT]]:
        lock = self._lock_for(session_id)
        with lock:
            yield LockedState(self, session_id)

    def administrative_update(self, session_id: str, update: Callable[[StateT], StateT]) -> StateT:
        """Apply a trusted out-of-band update while preserving monotonic versioning."""
        with self.locked(session_id) as locked:
            current = locked.current
            updated = update(current)
            return locked.commit(updated, expected_version=current.state_version)

    def _lock_for(self, session_id: str) -> threading.RLock:
        with self._registry_lock:
            try:
                return self._locks[session_id]
            except KeyError as exc:
                raise KeyError(f"Unknown session: {session_id}") from exc
