"""Tests for the decay monitor module."""
import tempfile

import pytest

from aatmf.core.models import (
    Confidence,
    ProbeResult,
    ProbeVerdict,
)
from aatmf.decay.detector import (
    aggregate_regressions,
    detect_regression,
)
from aatmf.decay.storage import DecayStorage


class TestDetector:
    def test_regression_detected(self):
        baseline = [{"verdict": "blocked"}] * 20
        current = [{"verdict": "blocked"}] * 5 + [{"verdict": "bypassed"}] * 15
        result = detect_regression("probe1", "weapons", baseline, current)
        assert result.status == "REGRESSION"
        assert result.significant

    def test_hardening_detected(self):
        baseline = [{"verdict": "blocked"}] * 10 + [{"verdict": "bypassed"}] * 10
        current = [{"verdict": "blocked"}] * 20
        result = detect_regression("probe1", "weapons", baseline, current)
        assert result.status == "HARDENING"
        assert result.significant

    def test_stable(self):
        baseline = [{"verdict": "blocked"}] * 18 + [{"verdict": "bypassed"}] * 2
        current = [{"verdict": "blocked"}] * 17 + [{"verdict": "bypassed"}] * 3
        result = detect_regression("probe1", "weapons", baseline, current)
        assert result.status == "STABLE"

    def test_insufficient_data(self):
        baseline = [{"verdict": "blocked"}] * 2
        current = [{"verdict": "blocked"}] * 3
        result = detect_regression("probe1", "weapons", baseline, current)
        assert result.status == "INSUFFICIENT_DATA"
        assert result.min_runs_needed > 0

    def test_all_blocked_stable(self):
        baseline = [{"verdict": "blocked"}] * 10
        current = [{"verdict": "blocked"}] * 10
        result = detect_regression("probe1", "weapons", baseline, current)
        assert result.status == "STABLE"

    def test_category_preserved(self):
        baseline = [{"verdict": "blocked"}] * 10
        current = [{"verdict": "blocked"}] * 10
        result = detect_regression("probe1", "cyber", baseline, current)
        assert result.category == "cyber"


class TestAggregateRegressions:
    def test_groups_by_category(self):
        from aatmf.core.models import RegressionResult

        results = [
            RegressionResult(probe_id="p1", category="weapons", status="REGRESSION"),
            RegressionResult(probe_id="p2", category="weapons", status="STABLE"),
            RegressionResult(probe_id="p3", category="cyber", status="STABLE"),
        ]
        cat_results = aggregate_regressions(results)
        assert len(cat_results) == 2

        weapons = [c for c in cat_results if c.category == "weapons"][0]
        assert weapons.total_probes == 2
        assert weapons.regressed_probes == 1
        assert weapons.regression_fraction == 0.5
        assert weapons.is_category_regression  # >= 0.2

    def test_no_regression(self):
        from aatmf.core.models import RegressionResult

        results = [
            RegressionResult(probe_id="p1", category="weapons", status="STABLE"),
            RegressionResult(probe_id="p2", category="weapons", status="STABLE"),
        ]
        cat_results = aggregate_regressions(results)
        assert cat_results[0].is_category_regression is False


class TestStorage:
    def test_store_and_retrieve(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        storage = DecayStorage(db_path)
        pr = ProbeResult(
            probe_id="TEST-001",
            technique_id="T1-AT-001",
            tactic_id="T1",
            category="weapons",
            verdict=ProbeVerdict.BLOCKED,
            compliance_score=0.0,
            response_hash="abc123",
        )
        storage.store_result("run-1", pr, "gpt-4o", "openai")

        results = storage.get_baseline_results("TEST-001", "gpt-4o", "openai")
        assert len(results) == 1
        assert results[0]["verdict"] == "blocked"
        assert results[0]["category"] == "weapons"
        storage.close()

    def test_batch_store(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        storage = DecayStorage(db_path)
        results = [
            ProbeResult(
                probe_id=f"TEST-{i:03d}",
                technique_id="T1-AT-001",
                tactic_id="T1",
                verdict=ProbeVerdict.BLOCKED,
                compliance_score=0.0,
                response_hash=f"hash{i}",
            )
            for i in range(10)
        ]
        storage.store_results("run-batch", results, "gpt-4o", "openai")

        for i in range(10):
            baseline = storage.get_baseline_results(
                f"TEST-{i:03d}", "gpt-4o", "openai"
            )
            assert len(baseline) == 1
        storage.close()

    def test_latest_timestamp(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        storage = DecayStorage(db_path)
        pr = ProbeResult(
            probe_id="TEST-001",
            technique_id="T1-AT-001",
            tactic_id="T1",
            verdict=ProbeVerdict.BLOCKED,
            compliance_score=0.0,
            response_hash="abc",
        )
        storage.store_result("run-1", pr, "gpt-4o", "openai")
        ts = storage.get_latest_timestamp("gpt-4o", "openai")
        assert ts is not None
        storage.close()
