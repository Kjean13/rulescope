from __future__ import annotations

"""Metadata completeness analyzer.

Checks required Sigma fields (title, id, description, status, level,
author, date, tags, falsepositives, references, logsource, detection),
validates UUID format, status/level values, and description length.
"""

import re

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule


REQUIRED_FIELDS = [
    "title",
    "rule_id",
    "description",
    "status",
    "level",
    "author",
    "date",
    "tags",
    "falsepositives",
    "references",
    "logsource",
    "detection",
]

VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


class MetadataAnalyzer:
    """Analyze completeness and quality of rule metadata."""

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        findings: list[Finding] = []
        score = 100

        values = {
            "title": rule.title,
            "rule_id": rule.rule_id,
            "description": rule.description,
            "status": rule.status,
            "level": rule.level,
            "author": rule.author,
            "date": rule.date,
            "tags": rule.tags,
            "falsepositives": rule.falsepositives,
            "references": rule.references,
            "logsource": rule.logsource,
            "detection": rule.detection,
        }

        # Missing fields
        missing = [key for key in REQUIRED_FIELDS if not values.get(key)]
        if missing:
            penalty = min(60, len(missing) * 6)
            score -= penalty
            findings.append(
                Finding(
                    code="META-001",
                    severity="medium",
                    category="metadata",
                    message="Rule is missing important metadata fields.",
                    evidence=", ".join(missing),
                    recommendation="Populate the missing metadata to improve maintainability and portability.",
                    impact=f"Missing {len(missing)} field(s) reduces traceability and automation readiness.",
                )
            )

        # Invalid UUID
        if rule.rule_id and not UUID_RE.match(rule.rule_id):
            score -= 5
            findings.append(
                Finding(
                    code="META-002",
                    severity="low",
                    category="metadata",
                    message="Rule ID is not a valid UUID.",
                    evidence=rule.rule_id,
                    recommendation="Use a UUID v4 to uniquely identify the rule.",
                    impact="Non-UUID IDs can break catalog tooling and dedup pipelines.",
                )
            )

        # Invalid status
        if rule.status and rule.status.lower() not in VALID_STATUSES:
            score -= 5
            findings.append(
                Finding(
                    code="META-003",
                    severity="low",
                    category="metadata",
                    message=f"Status '{rule.status}' is not a standard Sigma status.",
                    evidence=rule.status,
                    recommendation=f"Use one of: {', '.join(sorted(VALID_STATUSES))}.",
                    impact="Non-standard status values break filtering and lifecycle workflows.",
                )
            )

        # Invalid level
        if rule.level and rule.level.lower() not in VALID_LEVELS:
            score -= 5
            findings.append(
                Finding(
                    code="META-004",
                    severity="low",
                    category="metadata",
                    message=f"Level '{rule.level}' is not a standard Sigma level.",
                    evidence=rule.level,
                    recommendation=f"Use one of: {', '.join(sorted(VALID_LEVELS))}.",
                    impact="Non-standard levels break severity-based triage and dashboards.",
                )
            )

        # Short description
        if len(rule.description.strip()) < 25:
            score -= 8
            findings.append(
                Finding(
                    code="META-005",
                    severity="low",
                    category="metadata",
                    message="Description is too short to explain analyst intent.",
                    evidence=rule.description or "(empty)",
                    recommendation="Write a clearer description with context and expected behavior.",
                    impact="Analysts cannot triage effectively without adequate context.",
                )
            )

        # Too few tags
        if len(rule.tags) < 2:
            score -= 6
            findings.append(
                Finding(
                    code="META-006",
                    severity="low",
                    category="metadata",
                    message="Rule has too few tags.",
                    evidence=", ".join(rule.tags) or "(none)",
                    recommendation="Add tags for ATT&CK mapping, product, or data source context.",
                    impact="Sparse tags reduce discoverability and ATT&CK coverage mapping.",
                )
            )

        # Missing date
        if not rule.date:
            score -= 4
            findings.append(
                Finding(
                    code="META-007",
                    severity="info",
                    category="metadata",
                    message="Rule has no creation date.",
                    evidence="date: (empty)",
                    recommendation="Add a date field for lifecycle tracking.",
                    impact="Missing dates make staleness detection impossible.",
                )
            )

        return max(0, score), findings
