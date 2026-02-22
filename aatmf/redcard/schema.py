"""Red Card YAML schema loader and validator."""

from pathlib import Path

import structlog
import yaml

from aatmf.core.models import (
    CardMetadata,
    Message,
    PassCriteria,
    Probe,
    ProbeExpectation,
    ProbeType,
    RedCard,
    RiskScore,
    TacticRef,
    TechniqueRef,
)
from aatmf.core.utils import TACTIC_PROBE_TYPE_MAP, TACTIC_TO_PLAYBOOK_LAYER

logger = structlog.get_logger()


def load_card(path: str | Path) -> RedCard:
    """Load a single Red Card from a YAML file."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    tactic = TacticRef(**data["aatmf_tactic"])
    technique = TechniqueRef(**data["aatmf_technique"])
    metadata = CardMetadata(**data.get("metadata", {"title": path.stem}))
    pass_criteria = PassCriteria(**data.get("pass_criteria", {}))
    risk_score = RiskScore(**data.get("risk_score", {}))

    probes = []
    for p_data in data.get("probes", []):
        messages = [Message(**m) for m in p_data.get("messages", [])]
        expect = ProbeExpectation(**p_data.get("expect", {}))

        probe_type_str = TACTIC_PROBE_TYPE_MAP.get(tactic.id, "single_turn")
        layer = TACTIC_TO_PLAYBOOK_LAYER.get(tactic.id, 1)

        probe = Probe(
            id=p_data["id"],
            description=p_data.get("description", f"{technique.name} probe"),
            technique=technique,
            tactic=tactic,
            layer=layer,
            probe_type=ProbeType(probe_type_str),
            messages=messages,
            system_prompt=p_data.get("system_prompt"),
            expect=expect,
            tags=p_data.get("tags", [tactic.id]),
            encoding_type=p_data.get("encoding_type"),
            metadata=p_data.get("metadata", {}),
        )
        probes.append(probe)

    return RedCard(
        id=data["id"],
        aatmf_tactic=tactic,
        aatmf_technique=technique,
        playbook_layer=data.get("playbook_layer", TACTIC_TO_PLAYBOOK_LAYER.get(tactic.id, 1)),
        metadata=metadata,
        risk_score=risk_score,
        probes=probes,
        pass_criteria=pass_criteria,
    )


def load_cards_from_directory(path: str | Path) -> list[RedCard]:
    """Load all Red Card YAML files from a directory (recursive)."""
    path = Path(path)
    cards = []
    for yaml_file in sorted(path.rglob("*.yaml")):
        try:
            card = load_card(yaml_file)
            cards.append(card)
            logger.info("loaded_card", card_id=card.id, probes=len(card.probes))
        except Exception as e:
            logger.error("card_load_error", file=str(yaml_file), error=str(e))
    return cards
