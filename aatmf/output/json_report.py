"""JSON output format for suite results."""
import json

from aatmf.core.models import SuiteResult


def to_json(result: SuiteResult) -> str:
    """Serialize a SuiteResult to JSON."""
    return json.dumps(result.model_dump(mode="json"), indent=2)
