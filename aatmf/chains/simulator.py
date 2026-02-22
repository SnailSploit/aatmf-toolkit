"""Attack chain simulator — executes multi-step attack sequences."""
import structlog

from aatmf.core.evaluator import evaluate
from aatmf.core.executor import ProbeExecutor
from aatmf.core.models import (
    AttackChain,
    EvalTier,
    Message,
    Probe,
    ProbeExpectation,
    ProbeResult,
    ProbeType,
    ProbeVerdict,
    TacticRef,
    TargetConfig,
    TechniqueRef,
)
from aatmf.core.providers import get_provider
from aatmf.core.rate_limiter import TokenBucketLimiter
from aatmf.core.utils import TACTIC_NAMES

logger = structlog.get_logger()


class ChainSimulator:
    """Executes attack chains step by step."""

    def __init__(self, eval_tier: EvalTier = EvalTier.FAST):
        self._eval_tier = eval_tier

    async def execute_chain(
        self,
        chain: AttackChain,
        target: TargetConfig,
        probe_map: dict[str, Probe] | None = None,
    ) -> list[ProbeResult]:
        """Execute each step in sequence. If any step is blocked, chain fails."""
        provider = get_provider(target.provider)
        rate_limiter = TokenBucketLimiter()
        executor = ProbeExecutor(provider=provider, rate_limiter=rate_limiter)

        results: list[ProbeResult] = []
        context = ""

        for step_idx, technique_id in enumerate(chain.steps):
            # Get probe for this technique or create a placeholder
            probe = None
            if probe_map:
                probe = probe_map.get(technique_id)

            if probe is None:
                tactic_id = technique_id.split("-AT-")[0] if "-AT-" in technique_id else technique_id
                probe = Probe(
                    id=f"CHAIN-{step_idx:02d}-{technique_id}",
                    description=f"Chain step {step_idx + 1}: {technique_id}",
                    technique=TechniqueRef(id=technique_id, name=technique_id),
                    tactic=TacticRef(
                        id=tactic_id,
                        name=TACTIC_NAMES.get(tactic_id, tactic_id),
                    ),
                    probe_type=ProbeType.SINGLE_TURN,
                    messages=[
                        Message(
                            role="user",
                            content=f"[Chain context: {context}] Execute technique {technique_id}",
                        )
                    ],
                    expect=ProbeExpectation(should_block=True),
                )

            exec_result = await executor.execute(probe, target)

            verdict, score, details = await evaluate(
                response=exec_result.response_text,
                probe=probe,
                tier=self._eval_tier,
            )

            pr = ProbeResult(
                probe_id=probe.id,
                technique_id=technique_id,
                tactic_id=probe.tactic.id,
                layer=probe.layer,
                verdict=verdict,
                compliance_score=score,
                response_text=exec_result.response_text,
                response_hash=exec_result.response_hash,
                latency_ms=exec_result.latency_ms,
                eval_details=details,
            )
            results.append(pr)

            if verdict == ProbeVerdict.BLOCKED:
                logger.info(
                    "chain_blocked",
                    step=step_idx + 1,
                    technique=technique_id,
                )
                break

            # Pass context forward
            context += f" Step {step_idx + 1} ({technique_id}): {exec_result.response_text[:200]}"

        return results
