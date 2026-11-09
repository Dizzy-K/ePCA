from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from phase4.config import ModelSpec


@dataclass(frozen=True)
class ModelResponse:
    text: str | None
    latency_ms: float
    input_tokens: int
    output_tokens: int
    api_error: str | None
    stop_reason: str | None
    response_model: str | None
    attempts: int
    cost_usd: float | None = None


class ModelClient(Protocol):
    def complete(
        self,
        *,
        model: ModelSpec,
        system: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> ModelResponse: ...


def _safe_error(value: str) -> str:
    compact = " ".join(value.strip().split())
    return compact[:500] or "unknown_remote_error"


def _credential_value(model: ModelSpec) -> str:
    """Resolve credentials without putting relay-specific secrets in frozen config.

    DeepSeek and MiniMax can share a relay while using separate entitlements.  The
    model-specific override keeps that transport detail out of the experiment
    identity; the configured environment variable remains the compatibility
    fallback.
    """
    if model.provider == "deepseek":
        override = os.getenv("PHASE4_DEEPSEEK_API_KEY", "").strip()
        if override:
            return override
    return os.getenv(model.credential_env or "", "").strip()


class MMXModelClient:
    """MiniMax transport that retains final text/usage and discards thinking blocks."""

    def __init__(self, *, timeout_seconds: float = 120, max_retries: int = 3) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def complete(
        self,
        *,
        model: ModelSpec,
        system: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> ModelResponse:
        if model.transport != "mmx-cli" or model.provider != "minimax":
            return ModelResponse(None, 0.0, 0, 0, "unsupported_transport", None, None, 0)
        payload = json.dumps(messages, ensure_ascii=False)
        last_error = "remote_call_failed"
        total_started = time.perf_counter()
        for attempt in range(1, self.max_retries + 1):
            command = [
                "mmx", "text", "chat", "--model", model.model,
                "--system", system, "--messages-file", "-",
                "--temperature", str(temperature), "--max-tokens", str(max_tokens),
                "--non-interactive", "--output", "json",
            ]
            try:
                result = subprocess.run(
                    command,
                    input=payload,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                last_error = "timeout"
                if attempt < self.max_retries:
                    time.sleep(min(2 ** (attempt - 1), 4))
                    continue
                break
            if result.returncode != 0:
                last_error = f"mmx_exit_{result.returncode}:{_safe_error(result.stderr)}"
                if result.returncode in {4, 5} and attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break
            try:
                raw = json.loads(result.stdout)
                blocks = raw.get("content", [])
                # Never retain or return provider thinking/reasoning blocks.
                final_text = "".join(str(block.get("text", "")) for block in blocks if block.get("type") == "text").strip()
                usage = raw.get("usage") or {}
                if not final_text:
                    last_error = f"empty_final_text:{raw.get('stop_reason', 'unknown')}"
                    if attempt < self.max_retries:
                        continue
                    break
                return ModelResponse(
                    final_text,
                    (time.perf_counter() - total_started) * 1000.0,
                    int(usage.get("input_tokens", 0)),
                    int(usage.get("output_tokens", 0)),
                    None,
                    raw.get("stop_reason"),
                    raw.get("model"),
                    attempt,
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                last_error = f"response_parse_error:{type(exc).__name__}"
                if attempt < self.max_retries:
                    continue
                break
        return ModelResponse(
            None,
            (time.perf_counter() - total_started) * 1000.0,
            0,
            0,
            last_error,
            None,
            model.model,
            self.max_retries,
        )


class OpenAICompatibleClient:
    """Small OpenAI-compatible relay client; credentials remain environment-only."""

    def __init__(self, *, timeout_seconds: float = 120, max_retries: int = 3) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def complete(
        self,
        *,
        model: ModelSpec,
        system: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> ModelResponse:
        if model.transport != "openai-compatible" or not model.base_url or not model.credential_env:
            return ModelResponse(None, 0.0, 0, 0, "unsupported_transport", None, None, 0)
        api_key = _credential_value(model)
        if not api_key:
            return ModelResponse(None, 0.0, 0, 0, f"missing_credential:{model.credential_env}", None, None, 0)
        # The local relay exposes the GPT/Codex channel through the Responses
        # streaming endpoint rather than Chat Completions.  Keep this branch
        # provider-specific so the existing OpenAI-compatible path remains
        # unchanged for DeepSeek and MiniMax.
        if model.provider == "openai":
            return self._complete_responses(
                model=model,
                system=system,
                messages=messages,
                max_tokens=max_tokens,
                api_key=api_key,
            )
        base_url = model.base_url
        # Keep provider routing out of the frozen experiment configuration.
        # Kimi Coding Plan keys use a dedicated endpoint and expose reasoning
        # effort instead of temperature; both adaptations are explicitly
        # opt-in at runtime so relay-based paper runs retain their old wire
        # format and configuration hash.
        minimax_reasoning_effort = ""
        if model.provider == "minimax":
            base_url = os.getenv("PHASE4_MMX_BASE_URL", "").strip() or base_url
            minimax_reasoning_effort = os.getenv("PHASE4_MMX_REASONING_EFFORT", "").strip()
            if minimax_reasoning_effort and minimax_reasoning_effort not in {"low", "high", "max"}:
                return ModelResponse(None, 0.0, 0, 0, "invalid_minimax_reasoning_effort", None, model.model, 0)
        request_payload: dict[str, Any] = {
            "model": model.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "max_tokens": max_tokens,
        }
        if minimax_reasoning_effort:
            request_payload["reasoning_effort"] = minimax_reasoning_effort
        else:
            request_payload["temperature"] = temperature
        # DeepSeek v4 can spend most of the request budget on hidden reasoning
        # even when the protocol asks for one short JSON object.  The v2
        # experiment fixes this explicitly in its config; legacy configs omit
        # the field and retain their original behavior.
        if model.provider == "deepseek" and model.thinking is not None:
            request_payload["thinking"] = {"type": "enabled" if model.thinking else "disabled"}
        payload = json.dumps(request_payload, ensure_ascii=False).encode()
        # The frozen config names the relay used for the paper run.  For the
        # DeepSeek recovery path, an explicitly supplied runtime endpoint may
        # be used without changing the frozen config/hash or serializing a key.
        if model.provider == "deepseek":
            base_url = os.getenv("PHASE4_DEEPSEEK_BASE_URL", "").strip() or base_url
        endpoint = base_url.rstrip("/") + "/chat/completions"
        started = time.perf_counter()
        last_error = "remote_call_failed"
        for attempt in range(1, self.max_retries + 1):
            try:
                # Use curl as a hard wall-clock boundary.  urllib can remain
                # blocked when a relay sends headers or a partial body and then
                # stops making progress, which previously left whole batches
                # waiting well beyond their configured timeout.
                result = subprocess.run(
                    [
                        "curl", "--silent", "--show-error",
                        "--max-time", str(max(1.0, self.timeout_seconds)),
                        "--write-out", "\n%{http_code}",
                        "-X", "POST", endpoint,
                        "-H", f"Authorization: Bearer {api_key}",
                        "-H", "Content-Type: application/json",
                        "--data-binary", "@-",
                    ],
                    input=payload,
                    capture_output=True,
                    timeout=max(5.0, self.timeout_seconds + 10.0),
                    check=False,
                )
                if result.returncode != 0:
                    last_error = (
                        "timeout"
                        if result.returncode == 28
                        else f"transport_error:curl_exit_{result.returncode}"
                    )
                    if attempt < self.max_retries:
                        time.sleep(min(2 ** attempt, 8))
                        continue
                    break
                body, separator, status_text = result.stdout.rpartition(b"\n")
                if not separator or not status_text.isdigit():
                    raise ValueError("missing_http_status")
                status = int(status_text)
                if status >= 400:
                    last_error = f"http_{status}"
                    if status in {400, 408, 409, 429, 500, 502, 503, 504} and attempt < self.max_retries:
                        time.sleep(min(2 ** attempt, 8))
                        continue
                    break
                raw = json.loads(body)
            except subprocess.TimeoutExpired:
                last_error = "timeout"
                if attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break
            except (OSError, json.JSONDecodeError, UnicodeError, TypeError, ValueError) as exc:
                last_error = f"transport_error:{type(exc).__name__}"
                if attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break
            choices = raw.get("choices") or []
            message = (choices[0].get("message") or {}) if choices else {}
            # Deliberately ignore reasoning_content and any provider-private fields.
            text_value = message.get("content")
            if isinstance(text_value, list):
                text_value = "".join(str(block.get("text", "")) for block in text_value if isinstance(block, dict) and block.get("type") == "text")
            final_text = text_value.strip() if isinstance(text_value, str) else ""
            usage = raw.get("usage") or {}
            if not final_text:
                last_error = f"empty_final_text:{choices[0].get('finish_reason', 'unknown') if choices else 'no_choice'}"
                if attempt < self.max_retries:
                    continue
                break
            return ModelResponse(
                final_text,
                (time.perf_counter() - started) * 1000.0,
                int(usage.get("prompt_tokens", usage.get("input_tokens", 0))),
                int(usage.get("completion_tokens", usage.get("output_tokens", 0))),
                None,
                choices[0].get("finish_reason") if choices else None,
                raw.get("model"),
                attempt,
                float(raw.get("cost", usage.get("cost", usage.get("total_cost")))) if raw.get("cost", usage.get("cost", usage.get("total_cost"))) is not None else None,
            )
        return ModelResponse(None, (time.perf_counter() - started) * 1000.0, 0, 0, last_error, None, model.model, self.max_retries)

    def _complete_responses(
        self,
        *,
        model: ModelSpec,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        api_key: str,
    ) -> ModelResponse:
        """Call a Codex-compatible Responses/SSE endpoint and retain text only."""
        reasoning_effort = "low"
        # The GPT relay has occasionally overloaded on long certificate
        # prompts at the default low-reasoning setting.  A recovery-only
        # certificate override keeps the actor stage (and its behavior) at the
        # frozen setting while allowing the certificate producer to use the
        # model's supported no-reasoning mode.  It is opt-in and not part of
        # the frozen protocol hash.
        if model.provider == "openai":
            certificate_effort = os.getenv("PHASE4_GPT_CERT_REASONING_EFFORT", "").strip()
            general_effort = os.getenv("PHASE4_GPT_REASONING_EFFORT", "").strip()
            if certificate_effort and "external PCC certificate producer" in system:
                reasoning_effort = certificate_effort
            elif general_effort:
                reasoning_effort = general_effort
        payload_fields = {
                "model": model.model,
                "instructions": system,
                "input": [
                    {"role": item["role"], "content": item["content"]}
                    for item in messages
                ],
                "max_output_tokens": max_tokens,
                "reasoning": {"effort": reasoning_effort},
                "stream": True,
            }
        # Recovery runs may explicitly select a relay service tier.  Keep the
        # default payload unchanged so frozen experiments do not acquire a new
        # protocol field; the override is opt-in and runtime-only.
        service_tier = os.getenv("PHASE4_GPT_SERVICE_TIER", "").strip()
        if model.provider == "openai" and service_tier:
            payload_fields["service_tier"] = service_tier
        if (
            model.provider == "openai"
            and "external PCC certificate producer" in system
            and os.getenv("PHASE4_GPT_JSON_FORMAT", "").strip().lower() in {"1", "true", "yes"}
        ):
            # The relay is substantially more reliable when the requested
            # JSON-only output is represented by the Responses API's native
            # structured-output field.  This constrains syntax only; the PCC
            # checker still recomputes every semantic field.
            payload_fields["text"] = {"format": {"type": "json_object"}}
        payload = json.dumps(payload_fields, ensure_ascii=False).encode()
        base_url = model.base_url
        if model.provider == "deepseek":
            base_url = os.getenv("PHASE4_DEEPSEEK_BASE_URL", "").strip() or base_url
        elif model.provider == "openai":
            # The GPT relay endpoint is selected at runtime so recovery runs
            # can use a temporary SSH tunnel without changing the frozen
            # experiment configuration or its digest.
            base_url = os.getenv("PHASE4_GPT_BASE_URL", "").strip() or base_url
        endpoint = base_url.rstrip("/") + "/responses"
        started = time.perf_counter()
        last_error = "remote_call_failed"
        for attempt in range(1, self.max_retries + 1):
            request = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
            try:
                # Some relay responses keep the HTTP/SSE socket open after the
                # useful terminal event, and urllib's buffered readline can then
                # outlive its nominal socket timeout.  A curl subprocess gives
                # this recovery path a hard wall-clock cutoff that can actually
                # terminate the stuck connection.
                result = subprocess.run(
                    [
                        "curl", "--silent", "--show-error", "--no-buffer",
                        "--max-time", str(max(1.0, self.timeout_seconds)),
                        "-X", "POST", endpoint,
                        "-H", f"Authorization: Bearer {api_key}",
                        "-H", "Content-Type: application/json",
                        "--data-binary", "@-",
                    ],
                    input=payload,
                    capture_output=True,
                    timeout=max(5.0, self.timeout_seconds + 10.0),
                    check=False,
                )
                if result.returncode != 0:
                    detail = _safe_error(result.stderr.decode("utf-8", errors="replace"))
                    raise OSError(f"curl_exit_{result.returncode}:{detail}")
                raw_stream = result.stdout.decode("utf-8", errors="replace")
            except urllib.error.HTTPError as exc:
                last_error = f"http_{exc.code}"
                if exc.code in {400, 408, 409, 429, 500, 502, 503, 504} and attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break
            except TimeoutError:
                last_error = "timeout"
                if attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break
            except (OSError, subprocess.TimeoutExpired, UnicodeError, TypeError, ValueError) as exc:
                last_error = "timeout" if isinstance(exc, subprocess.TimeoutExpired) else f"transport_error:{type(exc).__name__}"
                if attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                break

            text_parts: list[str] = []
            usage: dict[str, Any] = {}
            response_model: str | None = None
            stop_reason: str | None = None
            stream_error: str | None = None
            fallback_text_parts: list[str] = []
            lines = raw_stream.splitlines()
            for index, line in enumerate(lines):
                if not line.startswith("event: ") or index + 1 >= len(lines):
                    continue
                event = line[7:].strip()
                data_line = lines[index + 1]
                if not data_line.startswith("data: "):
                    continue
                try:
                    data = json.loads(data_line[6:])
                except json.JSONDecodeError:
                    continue
                if event == "response.output_text.delta":
                    delta = data.get("delta")
                    if isinstance(delta, str):
                        text_parts.append(delta)
                elif event == "response.output_text.done":
                    # Some relays emit the terminal text event without any
                    # preceding delta events.  The `text` field is the
                    # complete assistant output; use it only when no deltas
                    # were collected so a normal response is not duplicated.
                    done_text = data.get("text")
                    if not text_parts and isinstance(done_text, str):
                        text_parts.append(done_text)
                elif event == "response.content_part.done":
                    part = data.get("part") or {}
                    part_text = part.get("text") if isinstance(part, dict) else None
                    if isinstance(part_text, str):
                        fallback_text_parts.append(part_text)
                elif event == "response.output_item.done":
                    item = data.get("item") or {}
                    content = item.get("content") if isinstance(item, dict) else None
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and isinstance(block.get("text"), str):
                                fallback_text_parts.append(block["text"])
                elif event == "response.completed":
                    completed = data.get("response") or {}
                    response_model = completed.get("model") or response_model
                    usage = completed.get("usage") or usage
                    stop_reason = completed.get("status") or stop_reason
                elif event in {"response.failed", "error"}:
                    error = data.get("error") or data
                    if isinstance(error, dict):
                        code = str(error.get("code", "")).strip()
                        message = str(error.get("message", "response_stream_failed")).strip()
                        stream_error = f"{code}:{message}" if code else message
                    else:
                        stream_error = "response_stream_failed"

            if not text_parts and fallback_text_parts:
                text_parts.extend(fallback_text_parts)
            final_text = "".join(text_parts).strip()
            input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)))
            output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)))
            if stream_error:
                last_error = f"response_error:{stream_error[:300]}"
            elif not final_text:
                last_error = "empty_final_text:responses"
            else:
                return ModelResponse(
                    final_text,
                    (time.perf_counter() - started) * 1000.0,
                    input_tokens,
                    output_tokens,
                    None,
                    stop_reason,
                    response_model or model.model,
                    attempt,
                )
            if attempt < self.max_retries:
                time.sleep(min(2 ** attempt, 8))
                continue
            break
        return ModelResponse(None, (time.perf_counter() - started) * 1000.0, 0, 0, last_error, None, model.model, self.max_retries)


class RemoteModelClient:
    def __init__(self, *, timeout_seconds: float = 120, max_retries: int = 3) -> None:
        self.mmx = MMXModelClient(timeout_seconds=timeout_seconds, max_retries=max_retries)
        self.openai_compatible = OpenAICompatibleClient(timeout_seconds=timeout_seconds, max_retries=max_retries)
        self._model_limits: dict[str, threading.BoundedSemaphore] = {}
        self._limit_lock = threading.Lock()

    def complete(self, **kwargs: Any) -> ModelResponse:
        model: ModelSpec = kwargs["model"]
        with self._limit_lock:
            concurrency = model.concurrency
            # Recovery runs may opt into a small, explicit GPT parallelism
            # limit without changing the frozen model specification/hash.  The
            # default remains the configured per-model limit.
            if model.provider == "openai":
                override = os.getenv("PHASE4_GPT_CONCURRENCY", "").strip()
                if override:
                    try:
                        concurrency = max(1, int(override))
                    except ValueError:
                        concurrency = model.concurrency
            limit = self._model_limits.setdefault(model.model, threading.BoundedSemaphore(concurrency))
        # Each exact model is serialized; the experiment-level executor may
        # impose a stricter global limit for fragile relay transports.
        with limit:
            if model.transport == "openai-compatible":
                return self.openai_compatible.complete(**kwargs)
            return self.mmx.complete(**kwargs)


def extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start < 0 or end <= start:
            raise
        value = json.loads(stripped[start : end + 1])
    if not isinstance(value, dict):
        raise ValueError("model output must be a JSON object")
    return value
