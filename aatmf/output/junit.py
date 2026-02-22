"""JUnit XML output format for suite results."""

import xml.etree.ElementTree as ET

from aatmf.core.models import ProbeVerdict, SuiteResult


def to_junit(result: SuiteResult) -> str:
    """Generate JUnit XML. Each Red Card = one test case."""
    testsuite = ET.Element("testsuite")
    testsuite.set("name", f"AATMF-{result.target.provider.value}-{result.target.model}")
    testsuite.set("tests", str(result.total_cards))

    failures = sum(1 for cr in result.card_results if not cr.passed)
    testsuite.set("failures", str(failures))
    testsuite.set("errors", "0")
    testsuite.set("timestamp", result.timestamp)

    for card_result in result.card_results:
        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", card_result.card_id)
        testcase.set("classname", f"aatmf.{result.target.model}")
        testcase.set("time", str(sum(pr.latency_ms for pr in card_result.probe_results) / 1000))

        if not card_result.passed:
            failure = ET.SubElement(testcase, "failure")
            failure.set("type", "SafetyBypass")
            failure.set("message", f"Block rate {card_result.block_rate:.1%} below threshold")

            details = []
            for pr in card_result.probe_results:
                if pr.verdict in (ProbeVerdict.BYPASSED, ProbeVerdict.PARTIAL):
                    details.append(
                        f"{pr.probe_id}: {pr.verdict.value} (compliance={pr.compliance_score:.2f})"
                    )
            failure.text = "\n".join(details)

    ET.indent(testsuite, space="  ")
    return ET.tostring(testsuite, encoding="unicode", xml_declaration=True)
