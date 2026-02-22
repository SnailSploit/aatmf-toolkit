"""Red Card Runner — executes probe suites against target models."""

import asyncio
import uuid

import structlog

from aatmf.core.evaluator import evaluate
from aatmf.core.executor import ProbeExecutor
from aatmf.core.models import (
    BudgetTracker,
    Confidence,
    EvalTier,
    ProbeResult,
    ProbeVerdict,
    RedCard,
    RedCardResult,
    SuiteResult,
    TargetConfig,
)
from aatmf.core.providers import ProviderAdapter, get_provider
from aatmf.core.rate_limiter import TokenBucketLimiter

logger = structlog.get_logger()


class RedCardRunner:
    """Runs all probes in a single Red Card against a target."""

    def __init__(
        self,
        executor: ProbeExecutor | None = None,
        eval_tier: EvalTier = EvalTier.STANDARD,
        judge_provider: ProviderAdapter | None = None,
        judge_config: TargetConfig | None = None,
        budget_tracker: BudgetTracker | None = None,
    ):
        self._executor = executor or ProbeExecutor()
        self._eval_tier = eval_tier
        self._judge_provider = judge_provider
        self._judge_config = judge_config
        self._budget_tracker = budget_tracker

    async def run_card(self, card: RedCard, target: TargetConfig) -> RedCardResult:
        """Run all probes in a card and aggregate results."""
        probe_results: list[ProbeResult] = []

        for probe in card.probes:
            try:
                exec_result = await self._executor.execute(probe, target)

                if exec_result.verdict_hint == ProbeVerdict.SKIPPED:
                    probe_results.append(
                        ProbeResult(
                            probe_id=probe.id,
                            technique_id=probe.technique.id,
                            tactic_id=probe.tactic.id,
                            category=probe.metadata.get("category", ""),
                            layer=probe.layer,
                            verdict=ProbeVerdict.SKIPPED,
                            compliance_score=0.0,
                            confidence=Confidence.HIGH,
                        )
                    )
                    continue

                if exec_result.error:
                    probe_results.append(
                        ProbeResult(
                            probe_id=probe.id,
                            technique_id=probe.technique.id,
                            tactic_id=probe.tactic.id,
                            category=probe.metadata.get("category", ""),
                            layer=probe.layer,
                            verdict=ProbeVerdict.ERROR,
                            response_text=exec_result.response_text,
                        )
                    )
                    continue

                verdict, score, details = await evaluate(
                    response=exec_result.response_text,
                    probe=probe,
                    tier=self._eval_tier,
                    all_turn_responses=exec_result.all_turn_responses,
                    judge_provider=self._judge_provider,
                    judge_config=self._judge_config,
                    budget_tracker=self._budget_tracker,
                )

                probe_results.append(
                    ProbeResult(
                        probe_id=probe.id,
                        technique_id=probe.technique.id,
                        tactic_id=probe.tactic.id,
                        category=probe.metadata.get("category", ""),
                        layer=probe.layer,
                        verdict=verdict,
                        compliance_score=score,
                        confidence=Confidence.HIGH
                        if details.layer_resolved == 1
                        else Confidence.MEDIUM,
                        response_text=exec_result.response_text,
                        response_hash=exec_result.response_hash,
                        latency_ms=exec_result.latency_ms,
                        eval_details=details,
                        all_turn_responses=exec_result.all_turn_responses,
                    )
                )

            except Exception as e:
                logger.error("probe_execution_error", probe_id=probe.id, error=str(e))
                probe_results.append(
                    ProbeResult(
                        probe_id=probe.id,
                        technique_id=probe.technique.id,
                        tactic_id=probe.tactic.id,
                        category=probe.metadata.get("category", ""),
                        layer=probe.layer,
                        verdict=ProbeVerdict.ERROR,
                    )
                )

        return self._aggregate(card, target, probe_results)

    def _aggregate(
        self,
        card: RedCard,
        target: TargetConfig,
        probe_results: list[ProbeResult],
    ) -> RedCardResult:
        """Aggregate individual probe results into a card result."""
        scoreable = [
            r for r in probe_results if r.verdict not in (ProbeVerdict.SKIPPED, ProbeVerdict.ERROR)
        ]

        blocked = sum(1 for r in scoreable if r.verdict == ProbeVerdict.BLOCKED)
        block_rate = blocked / len(scoreable) if scoreable else 0.0
        avg_compliance = (
            sum(r.compliance_score for r in scoreable) / len(scoreable) if scoreable else 0.0
        )
        leakage = any(
            r.eval_details.must_not_contain_leaked for r in probe_results if r.eval_details
        )
        total_cost = sum(r.cost_usd for r in probe_results)

        passed = (
            block_rate >= card.pass_criteria.min_block_rate
            and avg_compliance <= card.pass_criteria.max_avg_compliance
            and not leakage
        )

        return RedCardResult(
            card_id=card.id,
            provider=target.provider,
            model=target.model,
            probe_results=probe_results,
            passed=passed,
            block_rate=block_rate,
            avg_compliance=avg_compliance,
            leakage_detected=leakage,
            total_cost_usd=total_cost,
        )


class BatchRunner:
    """Runs multiple Red Cards with semaphore-based concurrency."""

    def __init__(
        self,
        eval_tier: EvalTier = EvalTier.STANDARD,
        concurrency: int = 5,
        judge_provider: ProviderAdapter | None = None,
        judge_config: TargetConfig | None = None,
        budget_tracker: BudgetTracker | None = None,
    ):
        self._eval_tier = eval_tier
        self._concurrency = concurrency
        self._judge_provider = judge_provider
        self._judge_config = judge_config
        self._budget_tracker = budget_tracker

    async def run_suite(self, cards: list[RedCard], target: TargetConfig) -> SuiteResult:
        """Run all cards with concurrency control."""
        provider = get_provider(target.provider)

        # Health check
        healthy = await provider.health_check(target)
        if not healthy:
            logger.error("health_check_failed", provider=target.provider.value)
            raise RuntimeError(f"Health check failed for {target.provider.value}:{target.model}")

        rate_limiter = TokenBucketLimiter()
        executor = ProbeExecutor(provider=provider, rate_limiter=rate_limiter)
        runner = RedCardRunner(
            executor=executor,
            eval_tier=self._eval_tier,
            judge_provider=self._judge_provider,
            judge_config=self._judge_config,
            budget_tracker=self._budget_tracker,
        )

        semaphore = asyncio.Semaphore(self._concurrency)

        async def run_with_semaphore(card: RedCard) -> RedCardResult:
            async with semaphore:
                return await runner.run_card(card, target)

        card_results = await asyncio.gather(*(run_with_semaphore(card) for card in cards))

        total_probes = sum(len(cr.probe_results) for cr in card_results)
        passed_cards = sum(1 for cr in card_results if cr.passed)
        total_blocked = sum(
            sum(1 for pr in cr.probe_results if pr.verdict == ProbeVerdict.BLOCKED)
            for cr in card_results
        )
        scoreable_probes = sum(
            sum(
                1
                for pr in cr.probe_results
                if pr.verdict not in (ProbeVerdict.SKIPPED, ProbeVerdict.ERROR)
            )
            for cr in card_results
        )
        overall_block_rate = total_blocked / scoreable_probes if scoreable_probes else 0.0
        total_cost = sum(cr.total_cost_usd for cr in card_results)

        return SuiteResult(
            target=target,
            card_results=list(card_results),
            total_cards=len(cards),
            passed_cards=passed_cards,
            total_probes=total_probes,
            overall_block_rate=overall_block_rate,
            total_cost_usd=total_cost,
            run_id=str(uuid.uuid4()),
            eval_tier=self._eval_tier.value,
        )
