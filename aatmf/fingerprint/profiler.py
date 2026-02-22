"""Fingerprint profiler — runs diagnostic probes and builds a behavioral profile."""

import asyncio
from collections import defaultdict

import structlog

from aatmf.core.evaluator import HARD_REFUSAL_PHRASES, evaluate
from aatmf.core.executor import ProbeExecutor
from aatmf.core.models import (
    BehavioralProfile,
    EvalTier,
    ProbeVerdict,
    TargetConfig,
)
from aatmf.core.providers import get_provider
from aatmf.core.rate_limiter import TokenBucketLimiter
from aatmf.fingerprint.diagnostics import build_diagnostic_probes, build_language_probes

logger = structlog.get_logger()


class Profiler:
    """Profiles a model's safety defense behavior."""

    def __init__(self, eval_tier: EvalTier = EvalTier.FAST):
        self._eval_tier = eval_tier

    async def profile(
        self,
        target: TargetConfig,
        concurrency: int = 3,
    ) -> BehavioralProfile:
        """Run diagnostic probes and build a behavioral profile."""
        provider = get_provider(target.provider)

        # Health check
        healthy = await provider.health_check(target)
        if not healthy:
            raise RuntimeError(f"Health check failed for {target.provider.value}:{target.model}")

        rate_limiter = TokenBucketLimiter()
        executor = ProbeExecutor(provider=provider, rate_limiter=rate_limiter)

        # Build probe sets
        diag_probes = build_diagnostic_probes()
        lang_probes = build_language_probes()
        all_probes = diag_probes + lang_probes

        # Execute with concurrency
        semaphore = asyncio.Semaphore(concurrency)
        results = []

        async def run_one(probe):
            async with semaphore:
                exec_result = await executor.execute(probe, target)
                verdict, score, details = await evaluate(
                    response=exec_result.response_text,
                    probe=probe,
                    tier=self._eval_tier,
                )
                return probe, exec_result, verdict, score

        tasks = [run_one(p) for p in all_probes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate into profile
        category_blocked: dict[str, int] = defaultdict(int)
        category_total: dict[str, int] = defaultdict(int)
        encoding_bypassed: dict[str, int] = defaultdict(int)
        encoding_total: dict[str, int] = defaultdict(int)
        language_bypassed: dict[str, int] = defaultdict(int)
        language_total: dict[str, int] = defaultdict(int)
        refusal_phrases: set[str] = set()
        refusal_latencies: list[float] = []
        non_refusal_latencies: list[float] = []

        for item in results:
            if isinstance(item, Exception):
                logger.warning("diagnostic_probe_error", error=str(item))
                continue

            probe, exec_result, verdict, score = item
            cat = probe.metadata.get("category", "unknown")
            enc = probe.metadata.get("encoding", "plain")
            lang = probe.metadata.get("language")

            if lang:
                language_total[lang] += 1
                if verdict in (ProbeVerdict.BYPASSED, ProbeVerdict.PARTIAL):
                    language_bypassed[lang] += 1
            else:
                category_total[cat] += 1
                encoding_total[enc] += 1

                if verdict == ProbeVerdict.BLOCKED:
                    category_blocked[cat] += 1
                    refusal_latencies.append(exec_result.latency_ms)
                    # Check which refusal phrases matched
                    resp_lower = exec_result.response_text.lower()[:200]
                    for phrase in HARD_REFUSAL_PHRASES:
                        if phrase in resp_lower:
                            refusal_phrases.add(phrase)
                else:
                    non_refusal_latencies.append(exec_result.latency_ms)
                    if verdict in (ProbeVerdict.BYPASSED, ProbeVerdict.PARTIAL):
                        encoding_bypassed[enc] += 1

        # Compute rates
        category_block_rates = {
            cat: category_blocked[cat] / category_total[cat]
            for cat in category_total
            if category_total[cat] > 0
        }
        encoding_bypass_rates = {
            enc: encoding_bypassed[enc] / encoding_total[enc]
            for enc in encoding_total
            if encoding_total[enc] > 0
        }
        language_bypass_rates = {
            lang: language_bypassed[lang] / language_total[lang]
            for lang in language_total
            if language_total[lang] > 0
        }

        # Latency overhead
        avg_refusal = sum(refusal_latencies) / len(refusal_latencies) if refusal_latencies else 0
        avg_non_refusal = (
            sum(non_refusal_latencies) / len(non_refusal_latencies) if non_refusal_latencies else 0
        )
        latency_overhead = max(0, avg_refusal - avg_non_refusal)

        return BehavioralProfile(
            target=target,
            observed_refusal_phrases=sorted(refusal_phrases),
            category_block_rates=category_block_rates,
            encoding_bypass_rates=encoding_bypass_rates,
            language_bypass_rates=language_bypass_rates,
            mean_refusal_latency_overhead_ms=latency_overhead,
        )
