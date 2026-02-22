"""Attack chain graph — technique registry and compatibility matrix."""
from collections import defaultdict

from aatmf.core.models import Probe


COMPATIBILITY: dict[str, list[str]] = {
    "T1": ["T3", "T2", "T4", "T7", "T8"],
    "T2": ["T1", "T3", "T8"],
    "T3": ["T3", "T4", "T7"],
    "T4": ["T1", "T2", "T3", "T7", "T8"],
    "T7": ["T3"],
    "T8": ["T1", "T3", "T4", "T7"],
    "T16": ["T11", "T1", "T8"],
    "T17": ["T16", "T11"],
    "T18": ["T1", "T2", "T3"],
    "T20": ["T16", "T17", "T11"],
}


class TechniqueRegistry:
    """Registry of known techniques built from loaded probe data."""

    def __init__(self, probes: list[Probe] | None = None):
        self._techniques: dict[str, str] = {}
        self._by_tactic: dict[str, list[str]] = defaultdict(list)
        if probes:
            self._build_from_probes(probes)

    def _build_from_probes(self, probes: list[Probe]) -> None:
        seen: set[str] = set()
        for probe in probes:
            tid = probe.technique.id
            if tid not in seen:
                seen.add(tid)
                self._techniques[tid] = probe.technique.name
                tactic = probe.tactic.id
                self._by_tactic[tactic].append(tid)

    def add_technique(self, technique_id: str, name: str, tactic_id: str) -> None:
        if technique_id not in self._techniques:
            self._techniques[technique_id] = name
            self._by_tactic[tactic_id].append(technique_id)

    @property
    def all_techniques(self) -> list[str]:
        return list(self._techniques.keys())

    @property
    def by_tactic(self) -> dict[str, list[str]]:
        return dict(self._by_tactic)

    def technique_name(self, technique_id: str) -> str:
        return self._techniques.get(technique_id, technique_id)

    def get_compatible_tactics(self, tactic_id: str) -> list[str]:
        return COMPATIBILITY.get(tactic_id, [])

    def get_compatible_techniques(self, technique_id: str) -> list[str]:
        tactic = technique_id.split("-AT-")[0] if "-AT-" in technique_id else technique_id
        compatible_tactics = self.get_compatible_tactics(tactic)
        result: list[str] = []
        for ct in compatible_tactics:
            result.extend(self._by_tactic.get(ct, []))
        return result
