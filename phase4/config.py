from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str
    transport: str
    base_url: str | None = None
    credential_env: str | None = None
    concurrency: int = 1
    thinking: bool | None = None


@dataclass(frozen=True)
class Phase4Config:
    experiment_date: str
    temperature: float
    actor_max_tokens: int
    judge_max_tokens: int
    certificate_max_tokens: int
    max_turns: int
    repeats: int
    timeout_seconds: float
    max_retries: int
    concurrency: int
    models: tuple[ModelSpec, ...]
    judge: ModelSpec
    financial_policy_version: str = "financial-policy-v1"

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "experiment_date": self.experiment_date,
            "temperature": self.temperature,
            "actor_max_tokens": self.actor_max_tokens,
            "judge_max_tokens": self.judge_max_tokens,
            "certificate_max_tokens": self.certificate_max_tokens,
            "max_turns": self.max_turns,
            "repeats": self.repeats,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "concurrency": self.concurrency,
            "models": [item.__dict__ for item in self.models],
            "judge": self.judge.__dict__,
            "financial_policy_version": self.financial_policy_version,
        }

    @property
    def digest(self) -> str:
        raw = json.dumps(self.canonical_payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


def load_config(path: Path) -> Phase4Config:
    data = json.loads(path.read_text(encoding="utf-8"))
    models = tuple(ModelSpec(**item) for item in data.pop("models"))
    judge = ModelSpec(**data.pop("judge"))
    config = Phase4Config(models=models, judge=judge, **data)
    if len(config.models) not in {3, 4}:
        raise ValueError("Phase 4 requires exactly 3 or 4 frozen actor models")
    if len({item.model for item in config.models}) != len(config.models):
        raise ValueError("Phase 4 model identifiers must be unique")
    if any(not 1 <= item.concurrency <= 4 for item in (*config.models, config.judge)):
        raise ValueError("per-model concurrency must be between 1 and 4")
    if config.financial_policy_version not in {"financial-policy-v1", "financial-policy-v2"}:
        raise ValueError("unsupported financial policy version")
    if not 0 < config.temperature <= 1:
        raise ValueError("temperature must be in (0, 1]")
    if not 1 <= config.concurrency <= 16:
        raise ValueError("concurrency must be between 1 and 16")
    return config
