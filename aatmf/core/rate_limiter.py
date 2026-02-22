"""Async token-bucket rate limiter for LLM API calls."""
import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class TokenBucketLimiter:
    """
    Token bucket rate limiter.

    Args:
        tokens_per_second: Refill rate (e.g. 80000 TPM / 60 = 1333 TPS)
        max_tokens: Maximum burst capacity
    """
    tokens_per_second: float = 1333.0
    max_tokens: float = 80000.0
    _tokens: float = field(init=False, default=0.0)
    _last_refill: float = field(init=False, default=0.0)
    _lock: asyncio.Lock = field(init=False, default_factory=asyncio.Lock)

    def __post_init__(self):
        self._tokens = self.max_tokens
        self._last_refill = time.monotonic()

    async def acquire(self, tokens: int = 1) -> None:
        """Wait until enough tokens are available, then consume them."""
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.tokens_per_second
                await asyncio.sleep(wait)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.max_tokens, self._tokens + elapsed * self.tokens_per_second)
        self._last_refill = now
