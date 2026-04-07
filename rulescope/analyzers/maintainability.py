from __future__ import annotations

"""Maintainability analyzer.

Measures condition complexity, nesting depth, selection block count,
condition string length, and large value sets that increase review cost.
"""

from typing import Any

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule


class MaintainabilityAnalyzer:
    """Analyze detection logic complexity and maintainability."""

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        findings: list[Finding] = []
        score = 100

        detection = rule.detection or {}
        keys = [k for k in detection.keys() if k != "condition"]
        condition = str(detection.get("condition") or "")

        # Selection block count
        complexity = len(keys)
        if complexity > 5:
            penalty = min(25, (complexity - 5) * 4)
            score -= penalty
            findings.append(
                Finding(
                    code="MAINT-001",
                    severity="medium",
                    category="maintainability",
                    message="Detection block has many selection blocks.",
                    evidence=f"selection blocks: {complexity}",
                    recommendation="Split the rule or simplify logical structure where possible.",
                    impact="High selection count makes rules harder to review and port across backends.",
                )
            )

        # Condition complexity
        logic_tokens = sum(condition.count(tok) for tok in [" and ", " or ", " not ", "1 of", "all of"])
        if logic_tokens > 3:
            penalty = min(20, logic_tokens * 3)
            score -= penalty
            findings.append(
                Finding(
                    code="MAINT-002",
                    severity="medium",
                    category="maintainability",
                    message="Condition expression is complex.",
                    evidence=condition,
                    recommendation="Consider reducing logical branching for easier review and portability.",
                    impact="Complex conditions increase the risk of logic errors and backend translation issues.",
                )
            )

        # Nesting depth
        nested_score = self._estimate_nesting(detection)
        if nested_score > 3:
            score -= min(20, nested_score * 3)
            findings.append(
                Finding(
                    code="MAINT-003",
                    severity="low",
                    category="maintainability",
                    message="Nested detection fields make the rule harder to review.",
                    evidence=f"nesting depth: {nested_score}",
                    recommendation="Reduce nested field structures or extract repeated patterns.",
                    impact="Deep nesting slows human review and breaks some backend converters.",
                )
            )

        # Overly long condition string
        if len(condition) > 200:
            score -= 8
            findings.append(
                Finding(
                    code="MAINT-004",
                    severity="low",
                    category="maintainability",
                    message="Condition string is unusually long.",
                    evidence=f"length: {len(condition)} chars",
                    recommendation="Break long conditions into named selection blocks for clarity.",
                    impact="Long condition strings are error-prone and hard to diff in version control.",
                )
            )

        # No condition at all (if detection exists)
        if detection and "condition" not in detection:
            score -= 15
            findings.append(
                Finding(
                    code="MAINT-005",
                    severity="high",
                    category="maintainability",
                    message="Detection block has selection(s) but no condition.",
                    evidence=f"keys: {', '.join(keys)}",
                    recommendation="Add a condition field referencing the selection blocks.",
                    impact="Without a condition, no backend can compile this rule.",
                )
            )

        # Large value lists
        for key in keys:
            val = detection.get(key)
            list_size = self._count_leaf_values(val)
            if list_size > 30:
                score -= min(10, (list_size - 30) // 5)
                findings.append(
                    Finding(
                        code="MAINT-006",
                        severity="low",
                        category="maintainability",
                        message=f"Selection '{key}' has a very large value set ({list_size} values).",
                        evidence=f"{key}: {list_size} leaf values",
                        recommendation="Consider using a lookup table or splitting into focused sub-rules.",
                        impact="Large value sets are slow to compile and hard to review line by line.",
                    )
                )
                break  # report once

        return max(0, score), findings

    def _estimate_nesting(self, data: Any, depth: int = 0) -> int:
        if isinstance(data, dict):
            if not data:
                return depth
            return max(self._estimate_nesting(v, depth + 1) for v in data.values())
        if isinstance(data, list):
            if not data:
                return depth
            return max(self._estimate_nesting(v, depth + 1) for v in data)
        return depth

    def _count_leaf_values(self, data: Any) -> int:
        if isinstance(data, dict):
            return sum(self._count_leaf_values(v) for v in data.values())
        if isinstance(data, list):
            return sum(self._count_leaf_values(v) for v in data)
        return 1
