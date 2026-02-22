"""Tests for the fingerprint module."""
import pytest

from aatmf.core.models import BehavioralProfile, ProviderName, TargetConfig
from aatmf.fingerprint.diagnostics import build_diagnostic_probes, build_language_probes
from aatmf.fingerprint.matcher import match_profile, _profile_to_vector
from aatmf.fingerprint.signatures import KNOWN_SIGNATURES


class TestDiagnosticProbes:
    def test_builds_50_probes(self):
        probes = build_diagnostic_probes()
        assert len(probes) == 50  # 5 categories x 10 encodings

    def test_categories_covered(self):
        probes = build_diagnostic_probes()
        categories = {p.metadata.get("category") for p in probes}
        assert categories == {"weapons", "drugs", "cyber", "exploitation", "fraud"}

    def test_encodings_covered(self):
        probes = build_diagnostic_probes()
        encodings = {p.metadata.get("encoding") for p in probes}
        expected = {
            "plain", "base64", "hex", "rot13", "unicode",
            "leetspeak", "reversed", "pig_latin", "nato_alphabet", "morse_code",
        }
        assert encodings == expected

    def test_probe_ids_unique(self):
        probes = build_diagnostic_probes()
        ids = [p.id for p in probes]
        assert len(ids) == len(set(ids))

    def test_language_probes_from_file(self):
        probes = build_language_probes()
        # Should find the translations file and load 10 probes
        assert len(probes) == 10

    def test_language_probes_missing_file(self):
        probes = build_language_probes("/nonexistent/path.json")
        assert len(probes) == 0


class TestSignatures:
    def test_four_signatures_defined(self):
        assert len(KNOWN_SIGNATURES) == 4

    def test_signature_names(self):
        names = set(KNOWN_SIGNATURES.keys())
        assert "GPT-4 Moderation API" in names
        assert "Claude Constitutional AI" in names
        assert "Llama Guard" in names
        assert "Custom Enterprise Filter" in names


class TestMatcher:
    def test_match_gpt4_profile(self):
        """A profile similar to GPT-4 should match GPT-4 signature."""
        gpt4_like = KNOWN_SIGNATURES["GPT-4 Moderation API"]
        result = match_profile(gpt4_like)
        assert result.identified_defense == "GPT-4 Moderation API"
        assert result.match_confidence > 0.99

    def test_match_claude_profile(self):
        claude_like = KNOWN_SIGNATURES["Claude Constitutional AI"]
        result = match_profile(claude_like)
        assert result.identified_defense == "Claude Constitutional AI"
        assert result.match_confidence > 0.99

    def test_empty_profile_returns_unknown(self):
        target = TargetConfig(provider=ProviderName.OPENAI, model="test")
        empty = BehavioralProfile(target=target)
        result = match_profile(empty)
        assert result.identified_defense == "UNKNOWN"
        assert result.match_confidence == 0.0

    def test_profile_to_vector_length(self):
        target = TargetConfig(provider=ProviderName.OPENAI, model="test")
        profile = BehavioralProfile(
            target=target,
            category_block_rates={"weapons": 0.9, "drugs": 0.8},
            encoding_bypass_rates={"plain": 0.05, "base64": 0.15},
        )
        vector = _profile_to_vector(profile)
        # 5 categories + 10 encodings + 1 latency = 16
        assert len(vector) == 16

    def test_recommended_vectors(self, sample_behavioral_profile):
        result = match_profile(sample_behavioral_profile)
        # Should have some recommendations (encodings with >30% bypass)
        assert isinstance(result.recommended_attack_vectors, list)
