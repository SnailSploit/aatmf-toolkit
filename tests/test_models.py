"""Tests for Pydantic data models."""
import json

import pytest

from aatmf.core.models import (
    AttackChain,
    BudgetTracker,
    Confidence,
    EvalTier,
    ExecutionResult,
    JudgeScores,
    Message,
    Probe,
    ProbeExpectation,
    ProbeResult,
    ProbeType,
    ProbeVerdict,
    ProviderName,
    RedCard,
    RedCardResult,
    RegressionResult,
    RiskScore,
    SuiteResult,
    TacticRef,
    TargetConfig,
    TechniqueRef,
    TokenUsage,
)


class TestMessage:
    def test_valid_roles(self):
        for role in ["system", "user", "assistant", "tool"]:
            m = Message(role=role, content="hello")
            assert m.role == role

    def test_invalid_role_rejected(self):
        with pytest.raises(Exception):
            Message(role="invalid", content="hello")

    def test_empty_content_rejected(self):
        with pytest.raises(Exception):
            Message(role="user", content="")


class TestRiskScore:
    def test_composite_calculation(self):
        rs = RiskScore(
            likelihood=5, impact=5, exploitability=5,
            detectability=1, recoverability=1,
        )
        assert rs.composite > 0

    def test_defaults(self):
        rs = RiskScore()
        assert rs.likelihood == 3
        assert rs.composite > 0

    def test_bounds_enforced(self):
        with pytest.raises(Exception):
            RiskScore(likelihood=0)
        with pytest.raises(Exception):
            RiskScore(impact=6)


class TestProbe:
    def test_basic_creation(self, sample_probe):
        assert sample_probe.id == "AP001A"
        assert sample_probe.probe_type == ProbeType.INJECTION
        assert len(sample_probe.messages) == 1

    def test_serialization_roundtrip(self, sample_probe):
        data = sample_probe.model_dump(mode="json")
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        probe2 = Probe(**parsed)
        assert probe2.id == sample_probe.id
        assert probe2.technique.id == sample_probe.technique.id


class TestExecutionResult:
    def test_response_hash(self):
        er = ExecutionResult(probe_id="test", response_text="hello world")
        assert len(er.response_hash) == 64  # SHA-256 hex

    def test_hash_deterministic(self):
        er1 = ExecutionResult(probe_id="test", response_text="same")
        er2 = ExecutionResult(probe_id="test", response_text="same")
        assert er1.response_hash == er2.response_hash


class TestJudgeScores:
    def test_composite_weighted(self):
        scores = JudgeScores(compliance=1.0, specificity=1.0, actionability=1.0)
        assert scores.composite == pytest.approx(1.0)

    def test_composite_zero(self):
        scores = JudgeScores(compliance=0.0, specificity=0.0, actionability=0.0)
        assert scores.composite == 0.0

    def test_composite_weights(self):
        # actionability weighted highest (0.40)
        high_action = JudgeScores(compliance=0.0, specificity=0.0, actionability=1.0)
        high_comply = JudgeScores(compliance=1.0, specificity=0.0, actionability=0.0)
        assert high_action.composite > high_comply.composite


class TestTokenUsage:
    def test_total_tokens(self):
        t = TokenUsage(prompt_tokens=100, completion_tokens=50)
        assert t.total_tokens == 150


class TestBudgetTracker:
    def test_can_spend(self):
        bt = BudgetTracker(max_budget_usd=10.0)
        assert bt.can_spend(5.0)
        bt.record_spend(8.0)
        assert not bt.can_spend(5.0)
        assert bt.can_spend(2.0)

    def test_record_spend(self):
        bt = BudgetTracker(max_budget_usd=10.0)
        bt.record_spend(3.0)
        bt.record_spend(4.0)
        assert bt.spent_usd == 7.0


class TestSuiteResult:
    def test_serialization(self, sample_target):
        sr = SuiteResult(
            target=sample_target,
            total_cards=1,
            passed_cards=1,
            total_probes=3,
            overall_block_rate=0.95,
        )
        data = sr.model_dump(mode="json")
        assert data["total_cards"] == 1
        sr2 = SuiteResult(**data)
        assert sr2.overall_block_rate == 0.95
