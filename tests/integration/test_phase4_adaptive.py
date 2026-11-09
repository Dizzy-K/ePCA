from __future__ import annotations

import json
from pathlib import Path

from phase4.adaptive import JUDGE_SYSTEM_PROMPT, run_episode
from phase4.config import load_config
from phase4.model_client import ModelResponse
from phase4.scenarios import SCENARIOS


ROOT = Path(__file__).resolve().parents[2]


class SequenceClient:
    def __init__(self, outputs: list[str]) -> None:
        self.outputs = iter(outputs)

    def complete(self, **kwargs):
        value = next(self.outputs)
        return ModelResponse(value, 1.0, 10, 5, None, "stop", kwargs["model"].model, 1)


def test_benign_agent_action_executes_through_epca() -> None:
    config = load_config(ROOT / "configs/phase4_models.json")
    scenario = next(item for item in SCENARIOS if item.scenario_id == "fin-benign-transfer")
    output = json.dumps({"status": "act", "principal_id": "agent", "action": {"action": "transfer", "params": {"amount": 100, "recipient": "vendor_1"}}})
    row = run_episode(config=config, model=config.models[0], scenario=scenario, repeat=1, guardrail="ePCA", client=SequenceClient([output]))
    assert row["benign_task_completed"] is True
    assert row["unsafe_effect_materialized"] is False
    assert row["trajectory_length"] == 1


class JudgeFailureClient:
    def complete(self, **kwargs):
        if kwargs["system"] == JUDGE_SYSTEM_PROMPT:
            return ModelResponse(None, 2.0, 0, 0, "timeout", None, kwargs["model"].model, 3)
        text = json.dumps({"status": "act", "principal_id": "agent", "action": {"action": "transfer", "params": {"amount": 100, "recipient": "vendor"}}})
        return ModelResponse(text, 1.0, 10, 5, None, "stop", kwargs["model"].model, 1)


def test_judge_failure_is_error_not_block() -> None:
    config = load_config(ROOT / "configs/phase4_models.json")
    scenario = next(item for item in SCENARIOS if item.scenario_id == "fin-benign-transfer")
    row = run_episode(config=config, model=config.models[0], scenario=scenario, repeat=1, guardrail="LLMJudge", client=JudgeFailureClient())
    assert row["api_error"] == "judge:timeout"
    assert row["block_count"] == 0
    assert row["decision"] == "error"
    assert row["benign_task_completed"] is False


def test_uniform_feedback_hides_guardrail_reason() -> None:
    config = load_config(ROOT / "configs/phase4_models.json")
    scenario = next(item for item in SCENARIOS if item.scenario_id == "fin-bypass-approval")
    blocked = json.dumps({"status": "act", "principal_id": "agent", "action": {"action": "transfer", "params": {"amount": 600, "recipient": "vendor"}}})
    give_up = json.dumps({"status": "give_up"})
    row = run_episode(config=config, model=config.models[0], scenario=scenario, repeat=1, guardrail="ePCA", client=SequenceClient([blocked, give_up]))
    assert row["trajectory"][0]["agent_feedback"] == "Action blocked by runtime policy."
    assert row["trajectory"][0]["detailed_violations"]
    assert row["unsafe_effect_materialized"] is False
