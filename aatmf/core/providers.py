"""LLM provider adapters for OpenAI, Anthropic, and custom endpoints."""

import time
from typing import Protocol

import structlog

from aatmf.core.models import (
    CompletionResult,
    Message,
    ProviderName,
    TargetConfig,
    TokenUsage,
)

logger = structlog.get_logger()


class ProviderAdapter(Protocol):
    """Protocol that all provider adapters must implement."""

    async def complete(self, messages: list[Message], config: TargetConfig) -> CompletionResult: ...

    async def health_check(self, config: TargetConfig) -> bool: ...


class OpenAIAdapter:
    """Adapter for OpenAI-compatible APIs (GPT-4o, etc.)."""

    def __init__(self):
        self._client = None

    def _get_client(self, config: TargetConfig):
        import openai

        kwargs = {}
        if config.api_key:
            kwargs["api_key"] = config.api_key
        if config.base_url:
            kwargs["base_url"] = config.base_url
        return openai.AsyncOpenAI(**kwargs)

    async def complete(self, messages: list[Message], config: TargetConfig) -> CompletionResult:
        client = self._get_client(config)
        msg_dicts = [{"role": m.role, "content": m.content} for m in messages]

        start = time.monotonic()
        response = await client.chat.completions.create(
            model=config.model,
            messages=msg_dicts,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )
        latency = int((time.monotonic() - start) * 1000)

        choice = response.choices[0]
        usage = TokenUsage(
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
        )
        return CompletionResult(
            text=choice.message.content or "",
            usage=usage,
            finish_reason=choice.finish_reason or "stop",
            latency_ms=latency,
        )

    async def health_check(self, config: TargetConfig) -> bool:
        try:
            result = await self.complete([Message(role="user", content="Say 'ok'")], config)
            return len(result.text) > 0
        except Exception as e:
            logger.error("health_check_failed", provider="openai", error=str(e))
            return False


class AnthropicAdapter:
    """Adapter for Anthropic Claude API."""

    def _get_client(self, config: TargetConfig):
        import anthropic

        kwargs = {}
        if config.api_key:
            kwargs["api_key"] = config.api_key
        return anthropic.AsyncAnthropic(**kwargs)

    async def complete(self, messages: list[Message], config: TargetConfig) -> CompletionResult:
        client = self._get_client(config)

        system = None
        msg_list = []
        for m in messages:
            if m.role == "system":
                system = m.content
            else:
                msg_list.append({"role": m.role, "content": m.content})

        start = time.monotonic()
        kwargs = {
            "model": config.model,
            "messages": msg_list,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        if system:
            kwargs["system"] = system

        response = await client.messages.create(**kwargs)
        latency = int((time.monotonic() - start) * 1000)

        text = response.content[0].text if response.content else ""
        usage = TokenUsage(
            prompt_tokens=response.usage.input_tokens if response.usage else 0,
            completion_tokens=response.usage.output_tokens if response.usage else 0,
        )
        return CompletionResult(
            text=text,
            usage=usage,
            finish_reason=response.stop_reason or "stop",
            latency_ms=latency,
        )

    async def health_check(self, config: TargetConfig) -> bool:
        try:
            result = await self.complete([Message(role="user", content="Say 'ok'")], config)
            return len(result.text) > 0
        except Exception as e:
            logger.error("health_check_failed", provider="anthropic", error=str(e))
            return False


class LocalAdapter:
    """Adapter for local/self-hosted models via OpenAI-compatible API."""

    async def complete(self, messages: list[Message], config: TargetConfig) -> CompletionResult:
        import httpx

        msg_dicts = [{"role": m.role, "content": m.content} for m in messages]

        start = time.monotonic()
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{config.base_url}/v1/chat/completions",
                json={
                    "model": config.model,
                    "messages": msg_dicts,
                    "temperature": config.temperature,
                    "max_tokens": config.max_tokens,
                },
            )
            response.raise_for_status()
        latency = int((time.monotonic() - start) * 1000)

        data = response.json()
        return CompletionResult(
            text=data["choices"][0]["message"]["content"],
            latency_ms=latency,
            finish_reason=data["choices"][0].get("finish_reason", "stop"),
        )

    async def health_check(self, config: TargetConfig) -> bool:
        try:
            result = await self.complete([Message(role="user", content="Say 'ok'")], config)
            return len(result.text) > 0
        except Exception:
            return False


def get_provider(name: ProviderName) -> ProviderAdapter:
    """Factory function to get the right adapter."""
    providers = {
        ProviderName.OPENAI: OpenAIAdapter,
        ProviderName.ANTHROPIC: AnthropicAdapter,
        ProviderName.LOCAL: LocalAdapter,
        ProviderName.CUSTOM: LocalAdapter,
    }
    cls = providers.get(name)
    if not cls:
        raise ValueError(f"Unknown provider: {name}")
    return cls()
