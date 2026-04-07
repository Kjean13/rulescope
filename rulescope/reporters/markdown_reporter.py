from __future__ import annotations

"""Markdown reporter — generates catalog and compare reports in Markdown.

Suitable for GitHub PR comments, wiki pages, and CI artifacts.
"""

from rulescope.i18n import get_lang, localize_finding, pillar_label, score_band_label, t, translate_text
from rulescope.models.report import CatalogReport, CompareReport


class MarkdownReporter:
    def render(self, report) -> str:
        if isinstance(report, CompareReport):
            return self._render_compare(report)
        return self._render_catalog(report)

    def _render_catalog(self, report: CatalogReport) -> str:
        lines: list[str] = []
        s = report.summary
        is_fr = get_lang() == "fr"
        lines.extend([
            "# Rapport RuleScope" if is_fr else "# RuleScope Report",
            "",
            f"- **{'Cible' if is_fr else 'Target'}:** `{report.target}`",
            f"- **{'Généré le' if is_fr else 'Generated'}:** `{report.generated_at}`",
            f"- **{'Version' if is_fr else 'Version'}:** `{report.version}`",
            "",
            "## Résumé du catalogue" if is_fr else "## Catalog Summary",
            "",
            f"| {t('metric')} | {t('value')} |",
            "|--------|-------|",
            f"| {'Score moyen par règle' if is_fr else 'Average Rule Score'} | **{s.average_score}/100** |",
            f"| {'Score de santé catalogue' if is_fr else 'Catalog Health Score'} | **{s.catalog_health_score}/100** ({score_band_label(s.score_band)}) |",
            f"| {'Score médian' if is_fr else 'Median Score'} | {s.median_score} |",
            f"| {'Nombre total de règles' if is_fr else 'Total Rules'} | {s.total_rules} |",
            f"| {'Paires de doublons' if is_fr else 'Duplicate Pairs'} | {s.duplicate_pairs} |",
            f"| {'Paires de chevauchement' if is_fr else 'Overlap Pairs'} | {s.overlap_pairs} |",
            f"| {'Règles à bruit élevé' if is_fr else 'High-Noise Rules'} | {s.high_noise_rules} |",
            f"| {'Métadonnées faibles' if is_fr else 'Weak Metadata'} | {s.weak_metadata_rules} |",
            f"| {'Règles faibles' if is_fr else 'Weak Rules'} | {s.weak_rules} |",
            f"| {'Règles invalides' if is_fr else 'Invalid Rules'} | {s.invalid_rules} |",
            f"| {'Nombre total de constats' if is_fr else 'Total Findings'} | {s.debt.total_findings} |",
            f"| {'État du budget' if is_fr else 'Budget Status'} | {t('budget_passed') if s.budget_result.passed else t('budget_failed')} |",
            "",
            "## Scores moyens par pilier" if is_fr else "## Average Pillar Scores",
            "",
            f"| {'Pilier' if is_fr else 'Pillar'} | {t('score')} |",
            "|--------|-------|",
        ])
        for name, value in s.average_pillars.model_dump().items():
            lines.append(f"| {pillar_label(name)} | {value} |")
        lines.append("")
        if s.budget_result.failures:
            lines.extend(["## Échecs du budget de gouvernance" if is_fr else "## Governance Budget Failures", ""])
            lines.extend([f"- {translate_text(failure)}" for failure in s.budget_result.failures])
            lines.append("")
        if s.priority_actions:
            lines.extend(["## Actions prioritaires" if is_fr else "## Priority Actions", ""])
            lines.extend([f"- {translate_text(action)}" for action in s.priority_actions])
            lines.append("")
        if report.duplicate_clusters:
            lines.extend(["## Groupes de doublons" if is_fr else "## Duplicate Clusters", ""])
            for idx, cluster in enumerate(report.duplicate_clusters, start=1):
                lines.append(f"- Cluster {idx}: {', '.join(f'`{item}`' for item in cluster)}")
            lines.append("")
        if report.overlap_pairs:
            lines.extend(["## Paires de chevauchement" if is_fr else "## Overlap Pairs", "", f"| {'Gauche' if is_fr else 'Left'} | {'Droite' if is_fr else 'Right'} | {'Similarité' if is_fr else 'Similarity'} | {'Motif' if is_fr else 'Reason'} |", "|------|-------|------------|--------|"])
            for pair in report.overlap_pairs[:20]:
                lines.append(f"| `{pair.left}` | `{pair.right}` | {pair.similarity}% | {pair.reason} |")
            lines.append("")
        if s.debt.categories:
            lines.extend([
                "## Dette technique par catégorie" if is_fr else "## Technical Debt by Category",
                "",
                f"| {'Catégorie' if is_fr else 'Category'} | {'Constats' if is_fr else 'Findings'} | {'Critique' if is_fr else 'Critical'} | {'Élevé' if is_fr else 'High'} | {'Moyen' if is_fr else 'Medium'} | {'Faible' if is_fr else 'Low'} | Info |",
                "|----------|----------|----------|------|--------|-----|------|",
            ])
            for cat in s.debt.categories:
                lines.append(f"| {cat.category} | {cat.count} | {cat.critical} | {cat.high} | {cat.medium} | {cat.low} | {cat.info} |")
            lines.append("")
        if s.debt.top_recommendations:
            lines.extend(["## Correctifs les plus fréquents" if is_fr else "## Most Frequent Remediations", ""])
            lines.extend([f"- {translate_text(rec.recommendation)} ({rec.count})" for rec in s.debt.top_recommendations])
            lines.append("")
        if s.coverage:
            lines.extend([
                "## Couverture ATT&CK" if is_fr else "## ATT&CK Coverage",
                "",
                f"| {'Tactique' if is_fr else 'Tactic'} | {'Techniques' if is_fr else 'Techniques'} | {'Règles' if is_fr else 'Rules'} | {'Qualité moy.' if is_fr else 'Avg Quality'} | {'Bande' if is_fr else 'Band'} | {'Fragile' if is_fr else 'Fragile'} | {'Risque de concentration' if is_fr else 'Concentration Risk'} |",
                "|--------|-----------|-------|-------------|------|---------|--------------------|",
            ])
            for cov in s.coverage:
                lines.append(f"| {cov.tactic} | {cov.technique_count} | {cov.rule_count} | {cov.avg_quality}/100 | {score_band_label(cov.quality_band)} | {cov.fragile} | {cov.concentration_risk} |")
            lines.append("")
        lines.extend(["## Détail des règles" if is_fr else "## Rule Details", ""])
        for rule in sorted(report.rules, key=lambda x: x.scores.overall):
            lines.extend([
                f"### {rule.title or rule.path}",
                f"- **{'Chemin' if is_fr else 'Path'}:** `{rule.path}`",
                f"- **{t('score')} :** **{rule.scores.overall}/100**",
                f"- {'Métad.' if is_fr else 'Meta'}: {rule.scores.metadata} | {'Maint.' if is_fr else 'Maint'}: {rule.scores.maintainability} | {'Bruit' if is_fr else 'Noise'}: {rule.scores.noise} | {'Struct.' if is_fr else 'Struct'}: {rule.scores.structural} | {'Doc' if is_fr else 'Doc'}: {rule.scores.documentation} | ATK: {rule.scores.attack_quality} | {'Faibl.' if is_fr else 'Weak'}: {rule.scores.weakness}",
            ])
            if rule.findings:
                lines.append(f"- **{'Constats' if is_fr else 'Findings'}:**")
                for f in rule.findings:
                    lf = localize_finding(f)
                    lines.append(f"  - `{lf.code}` [{lf.severity}] — {lf.message}")
                    if lf.recommendation:
                        lines.append(f"    > {lf.recommendation}")
            lines.append("")
        return "\n".join(lines)

    def _render_compare(self, report: CompareReport) -> str:
        s = report.summary
        is_fr = get_lang() == "fr"
        title = "# Rapport de comparaison RuleScope" if is_fr else "# RuleScope Compare Report"
        summary_title = "## Résumé" if is_fr else "## Summary"
        takeaways_title = "## Points clés" if is_fr else "## Takeaways"
        regressions_title = "## Régressions les plus fortes" if is_fr else "## Strongest Regressions"
        improvements_title = "## Améliorations les plus fortes" if is_fr else "## Strongest Improvements"
        lines = [
            title,
            "",
            f"- **{'Généré le' if is_fr else 'Generated'}:** `{report.generated_at}`",
            f"- **Verdict:** **{translate_text(s.summary_verdict)}**",
            "",
            summary_title,
            "",
            f"| {t('metric')} | {'Référence' if is_fr else 'Baseline'} | {'Candidat' if is_fr else 'Candidate'} | {t('delta')} |",
            "|--------|----------|-----------|-------|",
            f"| {'Score catalogue' if is_fr else 'Catalog score'} | {s.baseline_score} | {s.candidate_score} | {s.score_delta:+d} |",
            f"| {'Paires de doublons' if is_fr else 'Duplicate pairs'} | - | - | {s.duplicate_delta:+d} |",
            f"| {'Paires de chevauchement' if is_fr else 'Overlap pairs'} | - | - | {s.overlap_delta:+d} |",
            f"| {'Règles faibles' if is_fr else 'Weak rules'} | - | - | {s.weak_rule_delta:+d} |",
            f"| {t('compare_semantic_regressions')} | - | - | {s.semantic_regressions:+d} |",
            f"| {t('compare_semantic_improvements')} | - | - | {s.semantic_improvements:+d} |",
            "",
        ]
        if s.key_takeaways:
            lines.extend([takeaways_title, ""])
            lines.extend([f"- {translate_text(item)}" for item in s.key_takeaways])
            lines.append("")
        if report.strongest_regressions:
            lines.extend([regressions_title, ""])
            for item in report.strongest_regressions:
                lines.append(f"- `{item.path}` — {item.baseline_score} → {item.candidate_score} ({item.delta:+d})")
                for change in item.semantic_changes[:3]:
                    summary = translate_text(change.summary)
                    lines.append(f"  - {summary} ({change.detail})" if change.detail else f"  - {summary}")
            lines.append("")
        if report.strongest_improvements:
            lines.extend([improvements_title, ""])
            lines.extend([f"- `{item.path}` — {item.baseline_score} → {item.candidate_score} ({item.delta:+d})" for item in report.strongest_improvements])
            lines.append("")
        return "\n".join(lines)
