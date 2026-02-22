"""Attack chain planner — BFS over compatibility graph."""

from collections import deque

from aatmf.chains.graph import TechniqueRegistry
from aatmf.core.models import AttackChain, BehavioralProfile


def find_best_chains(
    registry: TechniqueRegistry,
    profile: BehavioralProfile,
    max_steps: int = 4,
    top_k: int = 5,
) -> list[AttackChain]:
    """Find the highest-probability attack chains using BFS."""
    all_techniques = registry.all_techniques
    if not all_techniques:
        return []

    # BFS: each state is (chain_so_far, probability)
    queue: deque[tuple[list[str], float]] = deque()
    candidates: list[AttackChain] = []

    # Seed with each technique as a starting point
    for tech_id in all_techniques:
        bypass_rate = profile.technique_bypass_rate(tech_id)
        if bypass_rate < 0.01:
            continue
        queue.append(([tech_id], bypass_rate))

    while queue:
        chain, prob = queue.popleft()

        # Record chain as candidate
        candidates.append(
            AttackChain(
                steps=list(chain),
                probability=prob,
                description=_describe_chain(chain, registry),
                estimated_turns=len(chain),
            )
        )

        # Expand if under max_steps
        if len(chain) >= max_steps:
            continue

        last_tech = chain[-1]
        compatible = registry.get_compatible_techniques(last_tech)

        for next_tech in compatible:
            if next_tech in chain:
                continue
            next_rate = profile.technique_bypass_rate(next_tech)
            new_prob = prob * next_rate
            if new_prob < 0.01:
                continue
            queue.append((chain + [next_tech], new_prob))

    # Sort by probability descending, take top_k
    candidates.sort(key=lambda c: c.probability, reverse=True)
    return candidates[:top_k]


def _describe_chain(chain: list[str], registry: TechniqueRegistry) -> str:
    names = [registry.technique_name(t) for t in chain]
    return " -> ".join(names)
