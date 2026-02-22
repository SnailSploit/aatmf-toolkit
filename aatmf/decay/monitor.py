"""Decay monitor — tracks safety performance over time."""

import uuid
from datetime import datetime, timedelta

import structlog

from aatmf.core.models import (
    EvalTier,
    ProbeVerdict,
    RedCard,
    RegressionResult,
    TargetConfig,
)
from aatmf.decay.detector import aggregate_regressions, detect_regression
from aatmf.decay.storage import DecayStorage
from aatmf.redcard.runner import RedCardRunner

logger = structlog.get_logger()

STALE_BASELINE_DAYS = 30


class DecayMonitor:
    """Monitors model safety over time, detecting regressions."""

    def __init__(
        self,
        storage: DecayStorage | None = None,
        db_path: str = "./aatmf-decay.db",
        eval_tier: EvalTier = EvalTier.STANDARD,
    ):
        self._storage = storage or DecayStorage(db_path)
        self._eval_tier = eval_tier

    async def run_check(
        self,
        cards: list[RedCard],
        target: TargetConfig,
    ) -> list[RegressionResult]:
        """Run current probes, compare against baseline, detect regressions."""
        # Check for stale baseline
        latest = self._storage.get_latest_timestamp(target.model, target.provider.value)
        if latest:
            try:
                latest_dt = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                age = datetime.now(latest_dt.tzinfo) - latest_dt
                if age > timedelta(days=STALE_BASELINE_DAYS):
                    logger.warning(
                        "stale_baseline",
                        days_old=age.days,
                        model=target.model,
                    )
            except (ValueError, TypeError):
                pass

        # Run current probes
        runner = RedCardRunner(eval_tier=self._eval_tier)
        run_id = str(uuid.uuid4())
        regression_results: list[RegressionResult] = []

        for card in cards:
            card_result = await runner.run_card(card, target)

            # Store results
            self._storage.store_results(
                run_id=run_id,
                results=card_result.probe_results,
                model=target.model,
                provider=target.provider.value,
            )

            # Compare each probe against baseline
            for pr in card_result.probe_results:
                if pr.verdict in (ProbeVerdict.SKIPPED, ProbeVerdict.ERROR):
                    continue

                baseline = self._storage.get_baseline_results(
                    probe_id=pr.probe_id,
                    model=target.model,
                    provider=target.provider.value,
                )

                # Exclude current run from baseline
                baseline = [b for b in baseline if b["run_id"] != run_id]

                current = [{"verdict": pr.verdict.value, "compliance_score": pr.compliance_score}]

                result = detect_regression(
                    probe_id=pr.probe_id,
                    category=pr.category,
                    baseline_results=baseline,
                    current_results=current,
                )
                regression_results.append(result)

        # Log summary
        regressions = [r for r in regression_results if r.status == "REGRESSION"]
        hardenings = [r for r in regression_results if r.status == "HARDENING"]
        logger.info(
            "decay_check_complete",
            total_probes=len(regression_results),
            regressions=len(regressions),
            hardenings=len(hardenings),
        )

        return regression_results

    def get_category_summary(self, results: list[RegressionResult]) -> list:
        """Get category-level regression summary."""
        return aggregate_regressions(results)

    def close(self) -> None:
        self._storage.close()
