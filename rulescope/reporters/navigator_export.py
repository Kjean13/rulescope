from __future__ import annotations

"""ATT&CK Navigator layer exporter.

Generates a JSON layer file compatible with MITRE ATT&CK Navigator
and DeTT&CT. Each technique is colored by average rule quality score.
"""

import json
from collections import defaultdict

from rulescope.models.report import CatalogReport


def export_navigator_layer(report: CatalogReport, name: str = "RuleScope Coverage") -> str:
    """Generate a Navigator layer JSON from a CatalogReport."""
    technique_scores: dict[str, list[int]] = defaultdict(list)
    technique_rules: dict[str, list[str]] = defaultdict(list)

    for rule in report.rules:
        for tech in rule.attack_techniques:
            technique_scores[tech.upper()].append(rule.scores.overall)
            technique_rules[tech.upper()].append(rule.title or rule.path)

    techniques = []
    for tech_id, scores in sorted(technique_scores.items()):
        avg = round(sum(scores) / len(scores)) if scores else 0
        color = _score_to_color(avg)
        comment = f"RuleScope avg: {avg}/100, rules: {len(scores)}\n" + "\n".join(f"- {r}" for r in technique_rules[tech_id][:5])
        techniques.append({
            "techniqueID": tech_id,
            "score": avg,
            "color": color,
            "comment": comment,
            "enabled": True,
            "metadata": [
                {"name": "rulescope_score", "value": str(avg)},
                {"name": "rule_count", "value": str(len(scores))},
            ],
        })

    layer = {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Detection coverage from RuleScope scan of {report.target} ({report.summary.total_rules} rules, avg rule score {report.summary.average_score}/100, catalog health {report.summary.catalog_health_score}/100)",
        "gradient": {
            "colors": ["#ff6666", "#ffcc00", "#66cc66"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Score < 50 (critical)", "color": "#ff6666"},
            {"label": "Score 50-74 (needs work)", "color": "#ffcc00"},
            {"label": "Score 75+ (solid)", "color": "#66cc66"},
        ],
        "techniques": techniques,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
    }
    return json.dumps(layer, indent=2, ensure_ascii=False)


def _score_to_color(score: int) -> str:
    if score >= 75:
        return "#66cc66"
    if score >= 50:
        return "#ffcc00"
    return "#ff6666"
