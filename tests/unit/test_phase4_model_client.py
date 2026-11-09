from phase4.config import ModelSpec
import json

from phase4.model_client import OpenAICompatibleClient, _credential_value


def test_deepseek_credential_override_does_not_replace_minimax(monkeypatch):
    monkeypatch.setenv("PHASE4_MMX_API_KEY", "minimax-key")
    monkeypatch.setenv("PHASE4_DEEPSEEK_API_KEY", "deepseek-key")
    deepseek = ModelSpec(
        provider="deepseek",
        model="deepseek-v4-pro",
        transport="openai-compatible",
        credential_env="PHASE4_MMX_API_KEY",
    )
    minimax = ModelSpec(
        provider="minimax",
        model="MiniMax-M3",
        transport="openai-compatible",
        credential_env="PHASE4_MMX_API_KEY",
    )

    assert _credential_value(deepseek) == "deepseek-key"
    assert _credential_value(minimax) == "minimax-key"


def test_deepseek_credential_uses_configured_fallback(monkeypatch):
    monkeypatch.delenv("PHASE4_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("PHASE4_MMX_API_KEY", "shared-key")
    model = ModelSpec(
        provider="deepseek",
        model="deepseek-v4-pro",
        transport="openai-compatible",
        credential_env="PHASE4_MMX_API_KEY",
    )

    assert _credential_value(model) == "shared-key"


def test_openai_codex_responses_stream_is_converted_to_model_response(monkeypatch):
    stream = "\n".join(
        [
            "event: response.output_text.delta",
            'data: {"type":"response.output_text.delta","delta":"{\\\"ok\\\""}',
            "",
            "event: response.output_text.delta",
            'data: {"type":"response.output_text.delta","delta":":true}"}',
            "",
            "event: response.completed",
            'data: {"type":"response.completed","response":{"model":"gpt-5.5","status":"completed","usage":{"input_tokens":3,"output_tokens":4}}}',
            "",
        ]
    ).encode()

    class FakeCompleted:
        returncode = 0
        stdout = stream
        stderr = b""

    monkeypatch.setenv("PHASE4_GPT_API_KEY", "test-key")
    monkeypatch.setattr("phase4.model_client.subprocess.run", lambda *_args, **_kwargs: FakeCompleted())
    model = {
        "provider": "openai",
        "model": "gpt-5.5",
        "transport": "openai-compatible",
        "base_url": "http://relay/v1",
        "credential_env": "PHASE4_GPT_API_KEY",
    }

    from phase4.config import ModelSpec

    response = OpenAICompatibleClient(timeout_seconds=1, max_retries=1).complete(
        model=ModelSpec(**model),
        system="Return JSON.",
        messages=[{"role": "user", "content": "test"}],
        temperature=0.01,
        max_tokens=128,
    )

    assert response.api_error is None
    assert response.text == '{"ok":true}'
    assert response.input_tokens == 3
    assert response.output_tokens == 4


def test_minimax_coding_plan_runtime_transport_override(monkeypatch):
    captured = {}

    class FakeCompleted:
        returncode = 0
        stdout = b'{"model":"k3","choices":[{"message":{"content":"{\\"ok\\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}\n200'
        stderr = b""

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["payload"] = json.loads(kwargs["input"])
        return FakeCompleted()

    monkeypatch.setenv("PHASE4_MMX_API_KEY", "test-key")
    monkeypatch.setenv("PHASE4_MMX_BASE_URL", "https://api.kimi.com/coding/v1")
    monkeypatch.setenv("PHASE4_MMX_REASONING_EFFORT", "low")
    monkeypatch.setattr("phase4.model_client.subprocess.run", fake_run)
    model = ModelSpec(
        provider="minimax",
        model="k3",
        transport="openai-compatible",
        base_url="http://relay/v1",
        credential_env="PHASE4_MMX_API_KEY",
    )

    response = OpenAICompatibleClient(timeout_seconds=1, max_retries=1).complete(
        model=model,
        system="Return JSON.",
        messages=[{"role": "user", "content": "test"}],
        temperature=0.01,
        max_tokens=128,
    )

    assert response.api_error is None
    assert "https://api.kimi.com/coding/v1/chat/completions" in captured["command"]
    assert captured["payload"]["reasoning_effort"] == "low"
    assert "temperature" not in captured["payload"]
