from __future__ import annotations

"""Structural integrity analyzer.

Validates logsource presence, detection block completeness, condition
existence, empty selections, and condition-selection coherence (undefined
references, unreferenced blocks).
"""

import re

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule


# Matches selection references in Sigma conditions: selection, filter, selection1, filter_admin, etc.
_IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")
# Keywords that are NOT selection references
_CONDITION_KEYWORDS = {
    "and", "or", "not", "all", "of", "them", "1", "condition",
    "true", "false", "none",
}


class StructuralAnalyzer:
    """Validate structural integrity of a Sigma rule."""

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        findings: list[Finding] = []
        score = 100

        # Logsource
        if not isinstance(rule.logsource, dict) or not rule.logsource:
            score -= 40
            findings.append(
                Finding(
                    code="STRUCT-001",
                    severity="high",
                    category="structural",
                    message="Rule is missing a valid logsource object.",
                    evidence=str(rule.logsource),
                    recommendation="Define the target product, service, or category in logsource.",
                    impact="Without logsource, the rule cannot be compiled for any SIEM backend.",
                )
            )
        else:
            # Logsource should have at least product or category
            if not rule.logsource.get("product") and not rule.logsource.get("category"):
                score -= 15
                findings.append(
                    Finding(
                        code="STRUCT-002",
                        severity="medium",
                        category="structural",
                        message="Logsource has neither product nor category.",
                        evidence=str(rule.logsource),
                        recommendation="Add at least a product or category for backend mapping.",
                        impact="Ambiguous logsource leads to unpredictable backend behavior.",
                    )
                )

        # Detection block
        if not isinstance(rule.detection, dict) or not rule.detection:
            score -= 60
            findings.append(
                Finding(
                    code="STRUCT-003",
                    severity="critical",
                    category="structural",
                    message="Rule is missing a valid detection block.",
                    evidence=str(rule.detection),
                    recommendation="Add the detection logic and condition fields.",
                    impact="Without a detection block, the rule has no operational value.",
                )
            )
        else:
            if "condition" not in rule.detection:
                score -= 20
                findings.append(
                    Finding(
                        code="STRUCT-004",
                        severity="high",
                        category="structural",
                        message="Detection block does not define a condition.",
                        evidence=str(list(rule.detection.keys())),
                        recommendation="Add a Sigma condition expression.",
                        impact="Condition-less detection blocks cannot be compiled.",
                    )
                )

            # Check for empty selection blocks
            sel_keys = [k for k in rule.detection.keys() if k != "condition"]
            empty_sels = [k for k in sel_keys if not rule.detection.get(k)]
            if empty_sels:
                score -= 10
                findings.append(
                    Finding(
                        code="STRUCT-005",
                        severity="medium",
                        category="structural",
                        message="Detection block has empty selection(s).",
                        evidence=", ".join(empty_sels),
                        recommendation="Populate selection blocks or remove unused ones.",
                        impact="Empty selections cause silent failures in some converters.",
                    )
                )

            # Coherence check: does the condition reference all defined selections,
            # and do all referenced selections actually exist in the detection block?
            condition = str(rule.detection.get("condition") or "")
            if condition and sel_keys:
                coherence_findings = self._check_condition_coherence(condition, sel_keys)
                for f in coherence_findings:
                    score -= 8
                findings.extend(coherence_findings)

        # Title sanity
        if rule.title and len(rule.title) > 256:
            score -= 3
            findings.append(
                Finding(
                    code="STRUCT-006",
                    severity="info",
                    category="structural",
                    message="Rule title is unusually long.",
                    evidence=f"length: {len(rule.title)}",
                    recommendation="Keep titles concise (under 128 characters).",
                    impact="Long titles truncate in dashboards and alert pipelines.",
                )
            )

        return max(0, score), findings

    def _check_condition_coherence(self, condition: str, selection_keys: list[str]) -> list[Finding]:
        """Verify condition references match actual selection blocks."""
        findings: list[Finding] = []
        condition_lower = condition.lower()

        # Handle wildcard references like "selection*" or "1 of selection*"
        has_wildcard_ref = "*" in condition

        # Extract identifiers from condition
        referenced = set()
        for match in _IDENT_RE.finditer(condition):
            token = match.group(1).lower()
            if token not in _CONDITION_KEYWORDS and not token.isdigit():
                referenced.add(token)

        # Remove "them" as it references all selections
        if "them" in condition_lower:
            return findings

        if has_wildcard_ref:
            # With wildcard refs, only check for unreferenced selections
            return findings

        sel_keys_lower = {k.lower() for k in selection_keys}

        # Selections referenced in condition but not defined
        undefined = referenced - sel_keys_lower
        if undefined:
            findings.append(
                Finding(
                    code="STRUCT-007",
                    severity="high",
                    category="structural",
                    message="Condition references undefined selection(s).",
                    evidence=f"undefined: {', '.join(sorted(undefined))}; defined: {', '.join(sorted(sel_keys_lower))}",
                    recommendation="Fix the condition to reference existing selection block names.",
                    impact="References to undefined selections cause silent compilation failures.",
                )
            )

        # Selections defined but never referenced in condition
        unreferenced = sel_keys_lower - referenced
        if unreferenced and not has_wildcard_ref:
            findings.append(
                Finding(
                    code="STRUCT-008",
                    severity="medium",
                    category="structural",
                    message="Selection block(s) defined but never referenced in condition.",
                    evidence=f"unreferenced: {', '.join(sorted(unreferenced))}",
                    recommendation="Reference unused selections in the condition or remove them.",
                    impact="Unreferenced selections are dead code and confuse reviewers.",
                )
            )

        return findings
