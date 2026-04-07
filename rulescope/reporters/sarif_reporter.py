from __future__ import annotations

"""SARIF 2.1.0 reporter for GitHub Advanced Security integration.

Findings are mapped to SARIF results with rule definitions,
physical locations, and severity levels.
"""

import json

from rulescope.models.report import CatalogReport


SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SarifReporter:
    """Export findings in SARIF 2.1.0 format for GitHub Advanced Security / CI integration."""

    def render(self, report: CatalogReport) -> str:
        rules_seen: dict[str, dict] = {}
        results = []

        for rule_report in report.rules:
            for finding in rule_report.findings:
                # Register rule
                if finding.code not in rules_seen:
                    rules_seen[finding.code] = {
                        "id": finding.code,
                        "shortDescription": {"text": finding.message},
                        "helpUri": "https://github.com/Kjean13/rulescope",
                        "properties": {"category": finding.category or "general"},
                    }
                    if finding.recommendation:
                        rules_seen[finding.code]["help"] = {"text": finding.recommendation}

                results.append(
                    {
                        "ruleId": finding.code,
                        "level": SEVERITY_MAP.get(finding.severity, "note"),
                        "message": {
                            "text": f"{finding.message} Evidence: {finding.evidence}" if finding.evidence else finding.message,
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": rule_report.path},
                                }
                            }
                        ],
                    }
                )

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RuleScope",
                            "version": report.version,
                            "informationUri": "https://github.com/Kjean13/rulescope",
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)
