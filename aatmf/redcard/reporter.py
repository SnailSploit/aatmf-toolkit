"""Red Card result reporting — delegates to output formatters."""

from pathlib import Path

import structlog

from aatmf.core.models import SuiteResult

logger = structlog.get_logger()


def write_report(
    result: SuiteResult,
    output_format: str = "json",
    output_path: str | Path | None = None,
) -> str:
    """Write a suite result to the specified format. Returns the output string."""
    if output_format == "json":
        from aatmf.output.json_report import to_json

        content = to_json(result)
    elif output_format == "sarif":
        from aatmf.output.sarif import to_sarif

        content = to_sarif(result)
    elif output_format == "junit":
        from aatmf.output.junit import to_junit

        content = to_junit(result)
    else:
        raise ValueError(f"Unknown output format: {output_format}")

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        logger.info("report_written", path=str(output_path), format=output_format)

    return content
