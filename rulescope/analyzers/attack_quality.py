from __future__ import annotations

"""ATT&CK mapping quality analyzer.

Checks that rules have proper tactic + technique tags, valid IDs,
sub-technique precision, and no typos in tactic names.
"""

import re

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule

KNOWN_TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
}

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


class AttackQualityAnalyzer:
    """Evaluate ATT&CK tagging hygiene and coverage quality."""

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        findings: list[Finding] = []
        score = 100

        attack_tags = [t for t in rule.tags if t.lower().startswith("attack.")]

        if not attack_tags:
            score -= 15
            findings.append(
                Finding(
                    code="ATK-001",
                    severity="medium",
                    category="attack",
                    message="Rule has no ATT&CK tags.",
                    evidence="tags: " + (", ".join(rule.tags) if rule.tags else "(none)"),
                    recommendation="Add at least one ATT&CK tactic and technique tag.",
                    impact="Untagged rules are invisible to coverage analysis and heatmaps.",
                )
            )
            return max(0, score), findings

        # Normalize hyphens to underscores — SigmaHQ uses 'defense-evasion',
        # ATT&CK matrix and our lookup use 'defense_evasion'
        tactics = [
            t.replace("attack.", "").lower().replace("-", "_")
            for t in attack_tags
            if not TECHNIQUE_RE.match(t.replace("attack.", ""))
        ]
        techniques = [t.replace("attack.", "").upper() for t in attack_tags if TECHNIQUE_RE.match(t.replace("attack.", ""))]

        if not tactics:
            score -= 8
            findings.append(
                Finding(
                    code="ATK-002",
                    severity="low",
                    category="attack",
                    message="Rule has technique tags but no tactic tag.",
                    evidence=", ".join(attack_tags),
                    recommendation="Add the parent tactic (e.g., attack.execution) for full mapping.",
                    impact="Missing tactics break tactic-level coverage dashboards.",
                )
            )

        if not techniques:
            score -= 10
            findings.append(
                Finding(
                    code="ATK-003",
                    severity="medium",
                    category="attack",
                    message="Rule has tactic tags but no specific technique.",
                    evidence=", ".join(attack_tags),
                    recommendation="Map to at least one ATT&CK technique ID (e.g., attack.t1059.001).",
                    impact="Tactic-only tagging provides no granularity for coverage gaps.",
                )
            )

        unknown_tactics = [t for t in tactics if t not in KNOWN_TACTICS]
        if unknown_tactics:
            score -= 5
            findings.append(
                Finding(
                    code="ATK-004",
                    severity="low",
                    category="attack",
                    message="Unknown ATT&CK tactic name(s).",
                    evidence=", ".join(unknown_tactics),
                    recommendation="Check spelling against the ATT&CK Enterprise matrix.",
                    impact="Misspelled tactics silently break coverage aggregation.",
                )
            )

        bad_techniques = [t for t in techniques if not TECHNIQUE_RE.match(t)]
        if bad_techniques:
            score -= 5
            findings.append(
                Finding(
                    code="ATK-005",
                    severity="low",
                    category="attack",
                    message="Malformed ATT&CK technique ID(s).",
                    evidence=", ".join(bad_techniques),
                    recommendation="Use format Txxxx or Txxxx.xxx.",
                    impact="Malformed IDs are ignored by coverage tools.",
                )
            )

        has_subtechnique = any("." in t for t in techniques)
        if techniques and not has_subtechnique:
            score -= 3
            findings.append(
                Finding(
                    code="ATK-006",
                    severity="info",
                    category="attack",
                    message="Rule maps to parent techniques only, no sub-techniques.",
                    evidence=", ".join(techniques),
                    recommendation="Map to sub-techniques where applicable for precise coverage.",
                    impact="Parent-only mapping overstates coverage breadth.",
                )
            )

        return max(0, score), findings
