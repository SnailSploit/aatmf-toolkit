"""Tests for the attack chain planner."""
import pytest

from aatmf.core.models import BehavioralProfile, ProviderName, TargetConfig
from aatmf.chains.graph import COMPATIBILITY, TechniqueRegistry
from aatmf.chains.planner import find_best_chains


@pytest.fixture
def registry():
    reg = TechniqueRegistry()
    reg.add_technique("T1-AT-001", "Direct Instruction Override", "T1")
    reg.add_technique("T1-AT-002", "System Prompt Extraction", "T1")
    reg.add_technique("T2-AT-001", "Encoding Bypass", "T2")
    reg.add_technique("T3-AT-001", "Reasoning Exploit", "T3")
    reg.add_technique("T4-AT-001", "Memory Manipulation", "T4")
    reg.add_technique("T7-AT-001", "Output Manipulation", "T7")
    reg.add_technique("T8-AT-001", "Identity Deception", "T8")
    return reg


@pytest.fixture
def profile():
    target = TargetConfig(provider=ProviderName.OPENAI, model="gpt-4o")
    return BehavioralProfile(
        target=target,
        technique_bypass_rates={
            "T1-AT-001": 0.3,
            "T1-AT-002": 0.2,
            "T2-AT-001": 0.4,
            "T3-AT-001": 0.5,
            "T4-AT-001": 0.35,
            "T7-AT-001": 0.25,
            "T8-AT-001": 0.3,
        },
    )


class TestTechniqueRegistry:
    def test_all_techniques(self, registry):
        assert len(registry.all_techniques) == 7

    def test_by_tactic(self, registry):
        by_tactic = registry.by_tactic
        assert len(by_tactic["T1"]) == 2
        assert len(by_tactic["T2"]) == 1

    def test_compatible_tactics(self, registry):
        compatible = registry.get_compatible_tactics("T1")
        assert "T3" in compatible
        assert "T2" in compatible

    def test_compatible_techniques(self, registry):
        compatible = registry.get_compatible_techniques("T1-AT-001")
        assert "T3-AT-001" in compatible
        assert "T2-AT-001" in compatible

    def test_technique_name(self, registry):
        assert registry.technique_name("T1-AT-001") == "Direct Instruction Override"
        assert registry.technique_name("UNKNOWN") == "UNKNOWN"


class TestChainPlanner:
    def test_finds_chains(self, registry, profile):
        chains = find_best_chains(registry, profile, max_steps=3, top_k=5)
        assert len(chains) > 0

    def test_respects_max_steps(self, registry, profile):
        chains = find_best_chains(registry, profile, max_steps=2, top_k=100)
        for chain in chains:
            assert len(chain.steps) <= 2

    def test_respects_top_k(self, registry, profile):
        chains = find_best_chains(registry, profile, max_steps=4, top_k=3)
        assert len(chains) <= 3

    def test_chains_sorted_by_probability(self, registry, profile):
        chains = find_best_chains(registry, profile, max_steps=3, top_k=10)
        for i in range(len(chains) - 1):
            assert chains[i].probability >= chains[i + 1].probability

    def test_no_duplicate_steps(self, registry, profile):
        chains = find_best_chains(registry, profile, max_steps=4, top_k=20)
        for chain in chains:
            assert len(chain.steps) == len(set(chain.steps))

    def test_empty_registry(self, profile):
        empty_reg = TechniqueRegistry()
        chains = find_best_chains(empty_reg, profile)
        assert len(chains) == 0

    def test_chain_has_description(self, registry, profile):
        chains = find_best_chains(registry, profile, max_steps=2, top_k=1)
        assert chains[0].description != ""

    def test_chain_probability_product(self, registry, profile):
        """Multi-step chain probability should be product of individual rates."""
        chains = find_best_chains(registry, profile, max_steps=2, top_k=50)
        for chain in chains:
            if len(chain.steps) == 2:
                rate1 = profile.technique_bypass_rate(chain.steps[0])
                rate2 = profile.technique_bypass_rate(chain.steps[1])
                assert abs(chain.probability - rate1 * rate2) < 1e-6


class TestCompatibilityMatrix:
    def test_T1_can_chain_to_T3(self):
        assert "T3" in COMPATIBILITY["T1"]

    def test_bidirectional_not_required(self):
        # T7 can chain to T3, but T3 can also chain to T7 — check both exist
        assert "T3" in COMPATIBILITY["T7"]
        assert "T7" in COMPATIBILITY["T3"]
