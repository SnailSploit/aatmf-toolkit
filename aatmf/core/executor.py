"""Probe executor — sends probes to target LLMs and collects responses."""

import asyncio

import structlog

from aatmf.core.encoding import ENCODING_FUNCTIONS, ENCODING_WRAPPERS
from aatmf.core.evaluator import HARD_REFUSAL_PHRASES
from aatmf.core.models import (
    CompletionResult,
    ExecutionResult,
    Message,
    Probe,
    ProbeVerdict,
    TargetConfig,
)
from aatmf.core.providers import ProviderAdapter, get_provider
from aatmf.core.rate_limiter import TokenBucketLimiter
from aatmf.core.utils import SIMULATION_TYPES

logger = structlog.get_logger()


class ProbeExecutor:
    """Executes probes against target LLMs with rate limiting and retries."""

    def __init__(
        self,
        provider: ProviderAdapter | None = None,
        rate_limiter: TokenBucketLimiter | None = None,
    ):
        self._provider = provider
        self._rate_limiter = rate_limiter or TokenBucketLimiter()

    async def execute(self, probe: Probe, target: TargetConfig) -> ExecutionResult:
        """Main entry point. Dispatches to the right handler based on probe type."""
        provider = self._provider or get_provider(target.provider)
        probe_type_str = probe.probe_type.value

        # Simulation-only types return SKIPPED immediately
        if probe_type_str in SIMULATION_TYPES:
            return ExecutionResult(
                probe_id=probe.id,
                response_text="[SIMULATION-ONLY] This probe type requires manual execution.",
                verdict_hint=ProbeVerdict.SKIPPED,
            )

        if probe_type_str == "encoding":
            return await self._execute_encoding(probe, target, provider)
        elif probe_type_str == "multi_turn":
            return await self._execute_multi_turn(probe, target, provider)
        else:
            return await self._execute_single(probe, target, provider)

    async def _execute_single(
        self, probe: Probe, target: TargetConfig, provider: ProviderAdapter
    ) -> ExecutionResult:
        """Single-turn execution."""
        messages = list(probe.messages)
        if probe.system_prompt or target.system_prompt:
            sys_prompt = probe.system_prompt or target.system_prompt
            messages.insert(0, Message(role="system", content=sys_prompt))

        result = await self._execute_with_retry(messages, target, provider)
        if result is None:
            return ExecutionResult(
                probe_id=probe.id,
                response_text="",
                error="All retries failed",
                verdict_hint=ProbeVerdict.ERROR,
            )

        return ExecutionResult(
            probe_id=probe.id,
            response_text=result.text,
            latency_ms=result.latency_ms,
            token_count=result.usage.total_tokens,
            finish_reason=result.finish_reason,
        )

    async def _execute_encoding(
        self, probe: Probe, target: TargetConfig, provider: ProviderAdapter
    ) -> ExecutionResult:
        """Apply encoding wrapper before sending as single-turn."""
        encoding_type = probe.encoding_type or "base64"
        encode_fn = ENCODING_FUNCTIONS.get(encoding_type, ENCODING_FUNCTIONS["plain"])
        wrapper = ENCODING_WRAPPERS.get(encoding_type, "{payload}")

        # Get the user message content
        user_content = ""
        for msg in probe.messages:
            if msg.role == "user":
                user_content = msg.content
                break

        # Encode and wrap
        encoded = encode_fn(user_content)
        wrapped = wrapper.format(payload=encoded)

        messages = [Message(role="user", content=wrapped)]
        if probe.system_prompt or target.system_prompt:
            sys_prompt = probe.system_prompt or target.system_prompt
            messages.insert(0, Message(role="system", content=sys_prompt))

        result = await self._execute_with_retry(messages, target, provider)
        if result is None:
            return ExecutionResult(
                probe_id=probe.id,
                response_text="",
                error="All retries failed",
                verdict_hint=ProbeVerdict.ERROR,
            )

        return ExecutionResult(
            probe_id=probe.id,
            response_text=result.text,
            latency_ms=result.latency_ms,
            token_count=result.usage.total_tokens,
            finish_reason=result.finish_reason,
        )

    async def _execute_multi_turn(
        self, probe: Probe, target: TargetConfig, provider: ProviderAdapter
    ) -> ExecutionResult:
        """Send messages one at a time, collecting all responses."""
        conversation: list[Message] = []
        all_responses: list[str] = []
        total_latency = 0
        total_tokens = 0
        early_termination = False
        failure_turn = None

        if probe.system_prompt or target.system_prompt:
            sys_prompt = probe.system_prompt or target.system_prompt
            conversation.append(Message(role="system", content=sys_prompt))

        for turn_idx, msg in enumerate(probe.messages):
            if msg.role == "user":
                conversation.append(msg)

                result = await self._execute_with_retry(conversation, target, provider)
                if result is None:
                    return ExecutionResult(
                        probe_id=probe.id,
                        response_text=all_responses[-1] if all_responses else "",
                        error=f"Retry failed at turn {turn_idx + 1}",
                        verdict_hint=ProbeVerdict.ERROR,
                        all_turn_responses=all_responses,
                        total_turns=len(all_responses),
                        is_multi_turn=True,
                    )

                all_responses.append(result.text)
                total_latency += result.latency_ms
                total_tokens += result.usage.total_tokens
                conversation.append(Message(role="assistant", content=result.text))

                # Early termination check: if model hard-refuses, stop
                response_lower = result.text.lower()[:200]
                hard_refused = any(p in response_lower for p in HARD_REFUSAL_PHRASES)
                if hard_refused and turn_idx < len(probe.messages) - 1:
                    early_termination = True
                    failure_turn = turn_idx + 1
                    break

            elif msg.role == "assistant":
                # Scripted assistant message (part of the attack setup)
                conversation.append(msg)

        final_response = all_responses[-1] if all_responses else ""
        return ExecutionResult(
            probe_id=probe.id,
            response_text=final_response,
            latency_ms=total_latency,
            token_count=total_tokens,
            all_turn_responses=all_responses,
            total_turns=len(all_responses),
            is_multi_turn=True,
            early_termination=early_termination,
            failure_turn=failure_turn,
        )

    async def _execute_with_retry(
        self,
        messages: list[Message],
        target: TargetConfig,
        provider: ProviderAdapter,
        max_retries: int = 3,
    ) -> CompletionResult | None:
        """Retry wrapper for per-turn resilience."""
        for attempt in range(max_retries):
            try:
                await self._rate_limiter.acquire()
                return await provider.complete(messages, target)
            except Exception as e:
                logger.warning(
                    "execution_retry",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    error=str(e),
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2**attempt)
        return None
