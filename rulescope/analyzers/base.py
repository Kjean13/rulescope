from __future__ import annotations

"""Base protocol for RuleScope analyzers.

I defined this protocol so that custom analyzers can be plugged in
without modifying the core engine. Any class with an `analyze(rule)`
method returning (score, findings) is valid.
"""

from typing import Protocol, runtime_checkable

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule


@runtime_checkable
class RuleAnalyzer(Protocol):
    """Protocol that all per-rule analyzers must satisfy.

    To create a custom analyzer, implement a class with an ``analyze`` method
    that accepts a ``DetectionRule`` and returns ``(score, findings)``.
    Score is 0-100; findings is a list of ``Finding`` objects.

    Example::

        class MyCustomAnalyzer:
            def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
                findings = []
                score = 100
                if not rule.references:
                    score -= 10
                    findings.append(Finding(
                        code="CUSTOM-001", severity="low", category="custom",
                        message="No external references.", recommendation="Add URLs.",
                    ))
                return max(0, score), findings
    """

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]: ...
