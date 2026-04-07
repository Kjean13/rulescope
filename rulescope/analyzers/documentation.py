from __future__ import annotations

"""Documentation quality analyzer.

Scores title clarity, description depth, false-positive guidance
quality, and reference URL validity.
"""

import re

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule


class DocumentationAnalyzer:
    """Assess documentation quality: title clarity, description richness,
    false positive guidance, and reference quality."""

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        findings: list[Finding] = []
        score = 100

        # Title quality
        title = rule.title.strip()
        if title:
            if title.lower() == title:
                score -= 3
                findings.append(
                    Finding(
                        code="DOC-001",
                        severity="info",
                        category="documentation",
                        message="Title is not capitalized.",
                        evidence=title,
                        recommendation="Use title case for readability in dashboards.",
                        impact="Lowercase titles look unprofessional in alert consoles.",
                    )
                )
            # Very generic title
            generic_titles = {"rule", "detection", "test", "test rule", "new rule", "untitled", "sigma rule"}
            if title.lower() in generic_titles:
                score -= 10
                findings.append(
                    Finding(
                        code="DOC-002",
                        severity="medium",
                        category="documentation",
                        message="Title is too generic to be useful.",
                        evidence=title,
                        recommendation="Use a descriptive title that conveys the threat behavior detected.",
                        impact="Generic titles make rules impossible to identify in large catalogs.",
                    )
                )

        # Description quality
        desc = rule.description.strip()
        if desc:
            word_count = len(desc.split())
            if word_count < 5:
                score -= 8
                findings.append(
                    Finding(
                        code="DOC-003",
                        severity="low",
                        category="documentation",
                        message="Description is too terse.",
                        evidence=f"{word_count} words",
                        recommendation="Describe what the rule detects, why it matters, and expected sources.",
                        impact="Short descriptions leave analysts guessing during triage.",
                    )
                )
            elif word_count < 10:
                score -= 4
                findings.append(
                    Finding(
                        code="DOC-004",
                        severity="info",
                        category="documentation",
                        message="Description could be more detailed.",
                        evidence=f"{word_count} words",
                        recommendation="Add context about the threat behavior and data source expectations.",
                        impact="Medium-length descriptions may miss important analyst guidance.",
                    )
                )

        # False positive guidance quality
        if rule.falsepositives:
            trivial = all(
                fp.strip().lower() in {"unknown", "none", "n/a", "", "todo", "tbd", "possible"}
                for fp in rule.falsepositives
            )
            if trivial:
                score -= 6
                findings.append(
                    Finding(
                        code="DOC-005",
                        severity="low",
                        category="documentation",
                        message="False positive entries are generic placeholders.",
                        evidence=", ".join(rule.falsepositives),
                        recommendation="Document specific benign scenarios analysts will encounter.",
                        impact="Placeholder FP guidance provides no operational value.",
                    )
                )

        # References quality
        if rule.references:
            url_pattern = re.compile(r"^https?://", re.IGNORECASE)
            non_urls = [r for r in rule.references if not url_pattern.match(r.strip())]
            if non_urls:
                score -= 3
                findings.append(
                    Finding(
                        code="DOC-006",
                        severity="info",
                        category="documentation",
                        message="Some references are not valid URLs.",
                        evidence=", ".join(non_urls[:3]),
                        recommendation="Use full URLs to research articles, CVEs, or blog posts.",
                        impact="Non-URL references are hard for analysts to follow up on.",
                    )
                )

        return max(0, score), findings
