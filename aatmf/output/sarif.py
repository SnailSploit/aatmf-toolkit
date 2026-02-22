"""SARIF 2.1.0 output format for suite results."""

import json

from aatmf.core.models import ProbeVerdict, SuiteResult


def to_sarif(result: SuiteResult) -> str:
    """Generate SARIF 2.1.0 report. Each failed Red Card = one SARIF result."""
    rules = []
    results_list = []

    for card_result in result.card_results:
        rule_id = card_result.card_id
        rules.append(
            {
                "id": rule_id,
                "shortDescription": {"text": f"Red Card: {rule_id}"},
                "properties": {
                    "block_rate": card_result.block_rate,
                    "passed": card_result.passed,
                },
            }
        )

        if not card_result.passed:
            failed_probes = [
                pr
                for pr in card_result.probe_results
                if pr.verdict in (ProbeVerdict.BYPASSED, ProbeVerdict.PARTIAL)
            ]
            message_parts = [f"Block rate: {card_result.block_rate:.1%}"]
            for pr in failed_probes[:5]:
                message_parts.append(
                    f"  - {pr.probe_id}: {pr.verdict.value} (compliance={pr.compliance_score:.2f})"
                )

            results_list.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if card_result.block_rate < 0.5 else "warning",
                    "message": {"text": "\n".join(message_parts)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"cards/{rule_id.lower()}.yaml"}
                            }
                        }
                    ],
                    "properties": {
                        "block_rate": card_result.block_rate,
                        "avg_compliance": card_result.avg_compliance,
                        "leakage_detected": card_result.leakage_detected,
                    },
                }
            )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AATMF Red Teaming Toolkit",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results_list,
                "properties": {
                    "run_id": result.run_id,
                    "target_model": result.target.model,
                    "target_provider": result.target.provider.value,
                    "overall_block_rate": result.overall_block_rate,
                    "total_probes": result.total_probes,
                    "eval_tier": result.eval_tier,
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2)
