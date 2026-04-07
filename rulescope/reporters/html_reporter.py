from __future__ import annotations

"""HTML report generator with radar chart, filters, and executive summary.

Uses Jinja2 template from reporters/templates/report.html.
The report is a single self-contained HTML file with embedded
SVG radar, JavaScript filtering, and responsive CSS.
"""

import json
from pathlib import Path

from jinja2 import Template

from rulescope.i18n import get_lang, localize_report_for_render, pillar_label, score_band_label, t, translate_text
from rulescope.models.report import CatalogReport

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class HtmlReporter:
    def render(self, report: CatalogReport) -> str:
        report = localize_report_for_render(report)
        template_path = _TEMPLATE_DIR / "report.html"
        template_text = template_path.read_text(encoding="utf-8")

        # Prepare radar chart data
        pillars = report.summary.average_pillars.model_dump()
        pillar_json = json.dumps(pillars)

        # Severity distribution for JS filtering
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for rule in report.rules:
            for f in rule.findings:
                if f.severity in severity_counts:
                    severity_counts[f.severity] += 1

        is_fr = get_lang() == "fr"
        labels = {
            "html_lang": "fr" if is_fr else "en",
            "title": "Rapport RuleScope" if is_fr else "RuleScope Report",
            "budget": t("budget_label"),
            "budget_state": "VALIDÉ" if is_fr and report.summary.budget_result.passed else "ÉCHOUÉ" if is_fr else "PASSED" if report.summary.budget_result.passed else "FAILED",
            "priority_actions": t("priority_actions"),
            "no_critical_actions": t("no_critical_actions_required"),
            "rules_analyzed": t("rules_analyzed").capitalize(),
            "median_score": "Score médian" if is_fr else "Median score",
            "duplicate_clusters": "Groupes de doublons" if is_fr else "Duplicate clusters",
            "overlap_pairs": t("overlap_pairs"),
            "high_noise_rules": t("high_noise_rules"),
            "weak_rules": t("weak_rules"),
            "invalid_rules": t("invalid_rules"),
            "total_findings": t("total_findings"),
            "quality_pillars": t("quality_pillars"),
            "budget_failures": t("governance_budget_failures"),
            "attack_coverage": "Couverture ATT&CK" if is_fr else "ATT&CK Coverage",
            "technical_debt": t("technical_debt_by_category"),
            "scores_by_logsource": t("scores_by_logsource"),
            "duplicate_clusters_title": t("duplicate_clusters"),
            "rule_details": t("rule_details"),
            "search_placeholder": t("search_rules_placeholder"),
            "all": t("all"),
            "critical": t("critical"),
            "high": t("high"),
            "medium": t("medium"),
            "low_info": t("low_info"),
            "score_lt_70": t("score_lt_70"),
        }

        return Template(template_text).render(
            report=report,
            s=report.summary,
            pillar_json=pillar_json,
            severity_counts_json=json.dumps(severity_counts),
            labels=labels,
            score_band_label=score_band_label,
            pillar_label=pillar_label,
            translate_text=translate_text,
            is_fr=is_fr,
        )
