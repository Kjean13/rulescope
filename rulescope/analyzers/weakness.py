from __future__ import annotations

"""Analytical weakness analyzer.

Detects rules that parse correctly but are too broad to trust in prod.
The scoring now favours semantic precision over syntax counting:
field precision × modifier strength × value specificity.
"""

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule
from rulescope.utils.detection_semantics import (
    atom_strength,
    has_anchored_atom,
    iter_detection_atoms,
    semantic_strength,
    weakest_atoms,
)


class WeaknessAnalyzer:
    """Detect analytically weak rules that are syntactically valid but too broad to trust in prod."""

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        score = 100
        findings: list[Finding] = []
        detection = rule.detection or {}
        atoms = list(iter_detection_atoms(detection))
        selector_names = {atom.selector for atom in atoms}
        selector_count = len(selector_names)
        base_fields = {atom.field for atom in atoms}
        wildcard_values = sum(1 for atom in atoms for value in atom.values if "*" in value)
        strength = semantic_strength(rule)

        if selector_count <= 1:
            score -= 12
            findings.append(Finding(
                code="WEAK-001",
                severity="medium",
                category="weakness",
                message="Rule relies on a single selector block.",
                recommendation="Add one or more discriminating selectors to improve selectivity.",
                impact="Single-selector logic is more likely to trigger on broad benign activity.",
            ))

        if wildcard_values >= 3:
            score -= 15
            findings.append(Finding(
                code="WEAK-002",
                severity="high",
                category="weakness",
                message="Rule uses multiple wildcard-heavy values.",
                recommendation="Replace broad wildcards with more specific values or supporting filters.",
                impact="Wildcard-heavy detections often create unstable and noisy detections in production.",
            ))

        if atoms and not has_anchored_atom(detection):
            score -= 12
            findings.append(Finding(
                code="WEAK-003",
                severity="medium",
                category="weakness",
                message="Rule has no anchored field — all matching is contains/unanchored.",
                recommendation="Add at least one endswith, startswith, exact-match, or high-precision anchor such as Image or OriginalFileName.",
                impact="Unanchored rules match any event whose text contains the pattern, producing high false-positive rates.",
            ))

        if len(base_fields) <= 1 and selector_count >= 1:
            score -= 8
            findings.append(Finding(
                code="WEAK-004",
                severity="low",
                category="weakness",
                message="Rule has low field diversity — all selectors operate on the same field.",
                recommendation="Mix process, parent, command line, user, or image path fields for stronger intent.",
                impact="Low field diversity usually means weak context and poor investigative precision.",
            ))

        if rule.level.lower() in {"high", "critical"} and strength < 0.55:
            score -= 10
            findings.append(Finding(
                code="WEAK-005",
                severity="medium",
                category="weakness",
                message="Declared severity is stronger than the underlying detection logic.",
                evidence=f"semantic strength: {strength:.2f}",
                recommendation="Either harden the detection or downgrade the severity until it becomes selective enough.",
                impact="Severity inflation reduces analyst trust in the catalog.",
            ))

        condition = str(detection.get("condition", "")).lower()
        negation_findings = self._check_negation_patterns(condition)
        for _ in negation_findings:
            score -= 10
        findings.extend(negation_findings)

        filter_keys = [k for k in detection if k != "condition" and (k.startswith("filter") or k.startswith("exclude"))]
        select_keys = [k for k in detection if k != "condition" and not k.startswith("filter") and not k.startswith("exclude")]
        if filter_keys and not select_keys and detection.get("condition"):
            score -= 12
            findings.append(Finding(
                code="WEAK-007",
                severity="medium",
                category="weakness",
                message="Detection has only filter/exclusion blocks with no positive selection.",
                evidence=f"filter blocks: {', '.join(filter_keys)}",
                recommendation="Add a positive selection that defines what the rule is looking for, not just what it excludes.",
                impact="Filter-only rules match everything minus exclusions, producing extremely broad detections.",
            ))

        weak_atoms = weakest_atoms(detection, limit=2)
        if weak_atoms and max(atom_strength(atom) for atom in weak_atoms[:1]) < 0.22:
            score -= 12
            findings.append(Finding(
                code="WEAK-008",
                severity="medium",
                category="weakness",
                message="Rule relies on semantically vague values for its primary match.",
                evidence="; ".join(f"{atom.field}|{'|'.join(atom.modifiers) or 'exact'}={','.join(atom.values[:2])}" for atom in weak_atoms),
                recommendation="Prefer values that identify a concrete binary, path, hash, key, or strongly discriminating command fragment.",
                impact="Vague values tend to describe topics or verbs rather than suspicious events, which increases false positives.",
            ))

        if atoms and strength < 0.42:
            score -= 14
            findings.append(Finding(
                code="WEAK-009",
                severity="high",
                category="weakness",
                message="Rule has low semantic precision for the declared intent.",
                evidence=f"semantic strength: {strength:.2f}",
                recommendation="Increase field precision, use stronger modifiers, and replace generic terms with concrete discriminators.",
                impact="Low semantic precision means the rule is more likely to match broad activity than the intended behavior.",
            ))

        status = rule.status.lower().strip()
        if status in {"deprecated", "unsupported"}:
            score = min(score, 55)
        elif status == "experimental" and score > 88:
            score = 88
        return max(score, 0), findings

    def _check_negation_patterns(self, condition: str) -> list[Finding]:
        findings: list[Finding] = []
        stripped = condition.strip()
        if stripped.startswith("not ") and " and " not in stripped and " or " not in stripped:
            findings.append(Finding(
                code="WEAK-006",
                severity="high",
                category="weakness",
                message="Condition uses pure negation without a positive selector.",
                evidence=f"condition: {condition}",
                recommendation="Add a positive selection and combine it with the negation (e.g. 'selection and not filter').",
                impact="Pure negation rules match everything except the excluded pattern, generating massive alert volumes.",
            ))
        return findings
