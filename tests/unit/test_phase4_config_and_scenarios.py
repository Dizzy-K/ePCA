from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from phase4.config import load_config
from phase4.scenarios import SCENARIOS


ROOT = Path(__file__).resolve().parents[2]


def test_phase4_config_freezes_three_models_without_secrets() -> None:
    path = ROOT / "configs/phase4_models.json"
    raw = path.read_text(encoding="utf-8")
    config = load_config(path)
    assert [item.model for item in config.models] == ["gpt-5.5", "MiniMax-M3", "deepseek-v4-pro"]
    assert config.judge.model == "MiniMax-M3"
    assert "sk-" not in raw
    assert all(item.credential_env and item.base_url for item in config.models)


def test_phase4_scenario_coverage_is_exact() -> None:
    counts = Counter((item.environment, item.goal_type) for item in SCENARIOS)
    assert len(SCENARIOS) == 30
    for environment in ("financial", "dataflow", "cloud_iam"):
        assert counts[(environment, "adversarial")] == 6
        assert counts[(environment, "benign")] == 4
    assert len({item.scenario_id for item in SCENARIOS}) == 30
