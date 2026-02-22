"""Probe loader — parses AATMF tactic FIXED.md files into Probe objects."""
import re
from pathlib import Path

import structlog

from aatmf.core.models import (
    Message,
    Probe,
    ProbeExpectation,
    ProbeType,
    TacticRef,
    TechniqueRef,
)
from aatmf.core.utils import (
    TACTIC_NAMES,
    TACTIC_PROBE_TYPE_MAP,
    TACTIC_TO_PLAYBOOK_LAYER,
    normalize_tactic_id,
)

logger = structlog.get_logger()

# Parsing regexes
TECHNIQUE_HEADER_RE = re.compile(
    r'###\s+`(T(?:1[0-9]|20|[1-9])-AT-\d{3})`\s+[—-]\s+(.+)'
)
RISK_SCORE_RE = re.compile(
    r'\*\*Risk Score:\*\*\s+([\d.]+)\s+[🔴🟠🟡🟢]\s+(\w+)'
)
PROBE_ID_RE = re.compile(r'\*\*`(AP\d{3}[A-Z])`\*\*')
PROBE_TEXT_RE = re.compile(
    r'\*\*`(AP\d{3}[A-Z])`\*\*\s*\n```\n(.*?)\n```',
    re.DOTALL,
)

# Validation
PLACEHOLDER_TOKENS = [
    "INSERT_", "EXAMPLE_", "TODO", "PLACEHOLDER",
    "[FILL", "{FILL", "HARMFUL", "RESTRICTED",
    "DANGEROUS", "ILLEGAL", "MALICIOUS",
]


class ProbeLoader:
    """Loads and validates probes from AATMF markdown source files."""

    def load_directory(self, path: str | Path) -> list[Probe]:
        """Load all FIXED.md files from a directory."""
        path = Path(path)
        all_probes: list[Probe] = []
        for md_file in sorted(path.glob("*FIXED*.md")):
            probes = self.load_file(md_file)
            all_probes.extend(probes)
            logger.info("loaded_file", file=md_file.name, probes=len(probes))
        logger.info("loaded_total", probes=len(all_probes))
        return all_probes

    def load_file(self, filepath: str | Path) -> list[Probe]:
        """Parse one FIXED.md file and extract all probes."""
        text = Path(filepath).read_text(encoding="utf-8")
        probes: list[Probe] = []

        # Extract probes using multi-line regex
        for match in PROBE_TEXT_RE.finditer(text):
            probe_id = match.group(1)
            probe_text = match.group(2).strip()

            # Find which technique this probe belongs to
            preceding_text = text[:match.start()]
            tech_matches = list(TECHNIQUE_HEADER_RE.finditer(preceding_text))
            if not tech_matches:
                logger.warning("orphan_probe", probe_id=probe_id)
                continue

            last_tech = tech_matches[-1]
            technique_id = last_tech.group(1)
            technique_name = last_tech.group(2).strip()

            # Find risk score between technique header and probe
            section = text[last_tech.start():match.start()]
            risk_match = RISK_SCORE_RE.search(section)
            risk_score = float(risk_match.group(1)) if risk_match else 0.0
            risk_rating = risk_match.group(2) if risk_match else "MEDIUM"

            # Derive tactic
            tactic_id = technique_id.split("-AT-")[0]
            probe_type_str = TACTIC_PROBE_TYPE_MAP.get(tactic_id, "single_turn")
            layer = TACTIC_TO_PLAYBOOK_LAYER.get(tactic_id, 1)
            tactic_name = TACTIC_NAMES.get(tactic_id, tactic_id)

            # Validate probe text
            if not self._validate_probe(probe_id, probe_text):
                continue

            probe = Probe(
                id=probe_id,
                description=f"{technique_name} probe",
                technique=TechniqueRef(
                    id=technique_id,
                    name=technique_name,
                    risk_score=risk_score,
                    risk_rating=risk_rating,
                ),
                tactic=TacticRef(id=tactic_id, name=tactic_name),
                layer=layer,
                probe_type=ProbeType(probe_type_str),
                messages=[Message(role="user", content=probe_text)],
                expect=ProbeExpectation(should_block=True),
                tags=[tactic_id, risk_rating.lower()],
            )
            probes.append(probe)

        return probes

    def _validate_probe(self, probe_id: str, text: str) -> bool:
        """Validate a probe against quality rules. Returns False to skip."""
        if len(text) < 10:
            logger.warning("probe_too_short", probe_id=probe_id, length=len(text))
            return False
        if len(text) > 10000:
            logger.warning("probe_too_long", probe_id=probe_id, length=len(text))
            return False
        for token in PLACEHOLDER_TOKENS:
            if token in text:
                logger.warning("placeholder_token", probe_id=probe_id, token=token)
                return False
        return True
