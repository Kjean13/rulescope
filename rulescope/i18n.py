from __future__ import annotations

"""Internationalization — English and French support.

All user-facing CLI strings go through t(key). Language is detected
from RULESCOPE_LANG env, system locale, or --lang flag.
Switchable at runtime via /lang in the interactive console.
"""

import os
from typing import Any

_current_lang: str = "en"

STRINGS: dict[str, dict[str, str]] = {
    "welcome_banner": {"en": "Welcome to", "fr": "Bienvenue dans"},
    "console_help": {
        "en": "[bold cyan]/help[/bold cyan] all commands  •  [bold cyan]/intro[/bold cyan] product overview  •  [bold cyan]/tips[/bold cyan] usage tips  •  [bold cyan]/clear[/bold cyan] clear screen  •  [bold cyan]/exit[/bold cyan] quit",
        "fr": "[bold cyan]/help[/bold cyan] toutes les commandes  •  [bold cyan]/intro[/bold cyan] présentation  •  [bold cyan]/tips[/bold cyan] astuces  •  [bold cyan]/clear[/bold cyan] effacer  •  [bold cyan]/exit[/bold cyan] quitter",
    },
    "intro_text": {
        "en": (
            "[bold]RuleScope[/bold] is a governance console for detection rules.\n\n"
            "It helps you:\n"
            "• audit Sigma catalogs for duplicates, overlap, weak metadata and noisy logic\n"
            "• compare baseline vs candidate rule packs before merge\n"
            "• explain weak rules in analyst-friendly language\n"
            "• generate reports for CI, pull requests and release reviews\n"
            "• export ATT&CK Navigator layers for coverage visualization\n\n"
            "Best entry points:\n"
            "• [cyan]scan <path> --top-issues 10[/cyan]\n"
            "• [cyan]explain <rule-or-folder>[/cyan]\n"
            "• [cyan]compare <baseline> <candidate> --fail-on-regression[/cyan]\n"
            "• [cyan]report <path> -o report.html[/cyan]\n"
            "• [cyan]navigator <path> -o layer.json[/cyan]"
        ),
        "fr": (
            "[bold]RuleScope[/bold] est une console de gouvernance pour les règles de détection.\n\n"
            "Il vous permet de :\n"
            "• auditer les catalogues Sigma (doublons, chevauchements, métadonnées, bruit)\n"
            "• comparer des packs baseline vs candidat avant merge\n"
            "• expliquer les règles faibles dans un langage orienté analyste\n"
            "• générer des rapports pour la CI, les PR et les revues de release\n"
            "• exporter des couches ATT&CK Navigator pour visualiser la couverture\n\n"
            "Points d'entrée recommandés :\n"
            "• [cyan]scan <path> --top-issues 10[/cyan]\n"
            "• [cyan]explain <dossier-ou-règle>[/cyan]\n"
            "• [cyan]compare <baseline> <candidate> --fail-on-regression[/cyan]\n"
            "• [cyan]report <path> -o report.html[/cyan]\n"
            "• [cyan]navigator <path> -o layer.json[/cyan]"
        ),
    },
    "tips_text": {
        "en": (
            "[bold]Console tips[/bold]\n\n"
            "• Use [cyan]scan <path> --top-issues 10[/cyan] for a fast first look.\n"
            "• Use [cyan]explain <folder> --all --max-rules 5[/cyan] to review the weakest N rules in one pass.\n"
            "• Use [cyan]compare <baseline> <candidate> --fail-on-regression[/cyan] before merge.\n"
            "• Use [cyan]doctor[/cyan] to confirm the active Python and RuleScope path.\n"
            "• Use [cyan]maintainers <path>[/cyan] to surface ownership hotspots.\n"
            "• Use [cyan]/lang fr[/cyan] to switch to French."
        ),
        "fr": (
            "[bold]Astuces console[/bold]\n\n"
            "• Utilisez [cyan]scan <path> --top-issues 10[/cyan] pour un premier aperçu rapide.\n"
            "• Utilisez [cyan]explain <dossier> --all --max-rules 5[/cyan] pour revoir les N règles les plus faibles.\n"
            "• Utilisez [cyan]compare <baseline> <candidate> --fail-on-regression[/cyan] avant le merge.\n"
            "• Utilisez [cyan]doctor[/cyan] pour vérifier l'environnement Python et RuleScope.\n"
            "• Utilisez [cyan]maintainers <path>[/cyan] pour identifier les hotspots.\n"
            "• Utilisez [cyan]/lang en[/cyan] pour passer en anglais."
        ),
    },
    "did_you_know": {
        "en": "[bold]Did you know?[/bold]\nYou can scan, explain, compare and gate detection catalogs with one console.\nLearn more with [bold cyan]/help[/bold cyan].",
        "fr": "[bold]Le saviez-vous ?[/bold]\nVous pouvez scanner, expliquer, comparer et contrôler des catalogues de détection depuis cette console.\nEn savoir plus avec [bold cyan]/help[/bold cyan].",
    },
    "introduce_yourself": {"en": "Introduce Yourself", "fr": "Présentation"},
    "console_commands_title": {"en": "RuleScope Console Commands", "fr": "Commandes de la console RuleScope"},
    "command": {"en": "Command", "fr": "Commande"},
    "purpose": {"en": "Purpose", "fr": "Objectif"},
    "product_overview": {"en": "Product overview", "fr": "Présentation du produit"},
    "tips": {"en": "Tips", "fr": "Astuces"},
    "clear": {"en": "Clear", "fr": "Effacer"},
    "quit": {"en": "Quit", "fr": "Quitter"},
    "language_prompt_title": {"en": "Select language", "fr": "Choisissez la langue"},
    "language_prompt_body": {
        "en": "[1] English\n[2] Français\n\nPress Enter to keep the detected default.",
        "fr": "[1] English\n[2] Français\n\nAppuyez sur Entrée pour garder la langue détectée.",
    },
    "language_prompt": {"en": "Language", "fr": "Langue"},
    "language_selected_en": {"en": "Language set to English.", "fr": "Langue définie sur l'anglais."},
    "language_selected_fr": {"en": "Language set to French.", "fr": "Langue définie sur le français."},
    "lang_switched_en": {"en": "Language switched to English.", "fr": "Langue changée en anglais."},
    "lang_switched_fr": {"en": "Language switched to French.", "fr": "Langue changée en français."},
    "redrawing_interface": {"en": "Redrawing interface...", "fr": "Redessin de l'interface..."},
    "unknown_command": {"en": "Unknown command", "fr": "Commande inconnue"},
    "unknown_shell_hint": {
        "en": "Unknown RuleScope command. Shell commands are not available inside the interactive console.",
        "fr": "Commande RuleScope inconnue. Les commandes shell ne sont pas disponibles dans la console interactive.",
    },
    "exiting_console": {"en": "Exiting RuleScope console.", "fr": "Sortie de la console RuleScope."},
    "watching_for_changes": {"en": "Watching for changes... (Ctrl+C to stop)", "fr": "Surveillance des changements... (Ctrl+C pour arrêter)"},
    "watch_compact_title": {"en": "RuleScope Watch", "fr": "Surveillance RuleScope"},
    "watch_scan": {"en": "Scan", "fr": "Scan"},
    "watch_delta": {"en": "Delta", "fr": "Delta"},
    "watch_no_previous_scan": {"en": "first scan", "fr": "premier scan"},
    "watch_no_change": {"en": "No score change since previous scan.", "fr": "Aucun changement de score depuis le scan précédent."},
    "watch_new_findings": {"en": "New findings", "fr": "Nouveaux constats"},
    "watch_new_invalid": {"en": "New invalid rules", "fr": "Nouvelles règles invalides"},
    "watch_new_critical": {"en": "New critical findings", "fr": "Nouveaux constats critiques"},
    "watch_status": {"en": "Status", "fr": "Statut"},
    "watch_summary": {"en": "Summary", "fr": "Résumé"},
    "watch_changes": {"en": "Changes since previous scan", "fr": "Évolutions depuis le scan précédent"},
    "watch_top_issues": {"en": "Top issues", "fr": "Problèmes principaux"},
    "watch_path": {"en": "Target", "fr": "Cible"},
    "watch_rules": {"en": "Rules", "fr": "Règles"},
    "watch_invalid": {"en": "Invalid", "fr": "Invalides"},
    "watch_duplicates": {"en": "Duplicates", "fr": "Doublons"},
    "watch_overlap": {"en": "Overlap", "fr": "Chevauchements"},
    "watch_weak": {"en": "Weak", "fr": "Faibles"},
    "governance_budget": {"en": "Governance budget", "fr": "Budget de gouvernance"},
    "budget_passed": {"en": "passed", "fr": "validé"},
    "budget_failed": {"en": "failed", "fr": "échoué"},
    "priority_actions": {"en": "Priority actions", "fr": "Actions prioritaires"},
    "weakest_rules": {"en": "Weakest rules", "fr": "Règles les plus faibles"},
    "most_frequent_remediations": {"en": "Most frequent remediations", "fr": "Remédiations les plus fréquentes"},
    "top_issues": {"en": "Top issues", "fr": "Problèmes principaux"},
    "average_pillars": {"en": "Average pillars", "fr": "Piliers moyens"},
    "metric": {"en": "Metric", "fr": "Métrique"},
    "value": {"en": "Value", "fr": "Valeur"},
    "pillar": {"en": "Pillar", "fr": "Pilier"},
    "score": {"en": "Score", "fr": "Score"},
    "all_gates_passed": {"en": "All quality gates passed.", "fr": "Toutes les portes qualité sont validées."},
    "gate_fail": {"en": "GATE FAIL", "fr": "ÉCHEC PORTE"},
    "report_written_to": {"en": "Report written to", "fr": "Rapport écrit dans"},
    "navigator_written_to": {"en": "Navigator layer written to", "fr": "Couche Navigator exportée dans"},
    "compare_report_written_to": {"en": "Compare report written to", "fr": "Rapport de comparaison écrit dans"},
    "rule": {"en": "Rule", "fr": "Règle"},
    "delta": {"en": "Delta", "fr": "Écart"},
    "baseline_short": {"en": "Base", "fr": "Réf."},
    "candidate_short": {"en": "Cand", "fr": "Cand."},
    "compare_score_delta": {"en": "Score delta", "fr": "Écart de score"},
    "compare_duplicate_delta": {"en": "Duplicate delta", "fr": "Écart de doublons"},
    "compare_overlap_delta": {"en": "Overlap delta", "fr": "Écart de chevauchements"},
    "compare_weak_rule_delta": {"en": "Weak-rule delta", "fr": "Écart de règles faibles"},
    "compare_changed_rules": {"en": "Changed rules", "fr": "Règles modifiées"},
    "compare_improved_rules": {"en": "Improved rules", "fr": "Règles améliorées"},
    "compare_regressed_rules": {"en": "Regressed rules", "fr": "Règles régressées"},
    "compare_semantic_regressions": {"en": "Semantic regressions", "fr": "Régressions sémantiques"},
    "compare_semantic_improvements": {"en": "Semantic improvements", "fr": "Améliorations sémantiques"},
    "compare_new_critical": {"en": "New high/critical findings", "fr": "Nouveaux constats high/critical"},
    "no_rules_found": {"en": "No rules found.", "fr": "Aucune règle trouvée."},
    "config_error": {"en": "Configuration error", "fr": "Erreur de configuration"},
    "invalid_path": {"en": "Invalid {label} path", "fr": "Chemin {label} invalide"},
    "unsupported_format": {"en": "Unsupported format", "fr": "Format non supporté"},
    "unsupported_compare_format": {"en": "Unsupported compare format", "fr": "Format de comparaison non supporté"},
    "rules_analyzed": {"en": "rules analyzed", "fr": "règles analysées"},
    "with_attack_mappings": {"en": "with ATT&CK mappings", "fr": "avec des mappings ATT&CK"},
    "takeaways": {"en": "Takeaways", "fr": "Points clés"},
    "strongest_regressions": {"en": "Strongest regressions", "fr": "Régressions les plus fortes"},
    "strongest_improvements": {"en": "Strongest improvements", "fr": "Améliorations les plus fortes"},
    "catalog_governance_view": {"en": "Catalog governance view", "fr": "Vue gouvernance du catalogue"},
    "worst_rules": {"en": "Worst rules", "fr": "Pires règles"},
    "category_hotspots": {"en": "Category hotspots", "fr": "Hotspots par catégorie"},
    "logsource_hotspots": {"en": "Logsource hotspots", "fr": "Hotspots par logsource"},
    "top_recurring_actions": {"en": "Top recurring actions", "fr": "Actions récurrentes principales"},
    "cmd_scan": {"en": "Analyze one rule or a whole catalog.", "fr": "Analyser une règle ou un catalogue entier."},
    "cmd_explain": {"en": "Explain the weakest rule, or the weakest N rules with --all.", "fr": "Expliquer la règle la plus faible, ou les N plus faibles avec --all."},
    "cmd_compare": {"en": "Detect quality regressions before merge.", "fr": "Détecter les régressions qualité avant le merge."},
    "cmd_report": {"en": "Export a shareable report.", "fr": "Exporter un rapport partageable."},
    "cmd_ci": {"en": "Run CI quality gate (score threshold + duplicate limit).", "fr": "Exécuter la porte qualité CI (seuil de score + limite de doublons)."},
    "cmd_maintainers": {"en": "Surface catalog hotspots for reviewers and maintainers.", "fr": "Identifier les hotspots pour les reviewers et mainteneurs."},
    "cmd_navigator": {"en": "Export ATT&CK Navigator layer.", "fr": "Exporter une couche ATT&CK Navigator."},
    "cmd_doctor": {"en": "Show active Python and RuleScope environment info.", "fr": "Afficher l'environnement Python et RuleScope."},
    "cmd_version": {"en": "Show installed RuleScope version.", "fr": "Afficher la version de RuleScope."},
    "cmd_benchmark": {"en": "Benchmark RuleScope against a catalog and report performance.", "fr": "Benchmarker RuleScope sur un catalogue et générer un rapport de performance."},
    "cmd_watch": {"en": "Watch a file or directory and re-scan on changes.", "fr": "Surveiller un fichier ou dossier et re-scanner à chaque modification."},
    "cmd_lang": {"en": "Switch language (en/fr).", "fr": "Changer la langue (en/fr)."},
    "duplicate_pairs": {"en": "Duplicate pairs", "fr": "Paires de doublons"},
    "overlap_pairs": {"en": "Overlap pairs", "fr": "Paires de chevauchement"},
    "high_noise_rules": {"en": "High-noise rules", "fr": "Règles bruyantes"},
    "weak_metadata": {"en": "Weak metadata", "fr": "Métadonnées faibles"},
    "weak_rules": {"en": "Weak rules", "fr": "Règles faibles"},
    "invalid_rules": {"en": "Invalid rules", "fr": "Règles invalides"},
    "total_findings": {"en": "Total findings", "fr": "Total des constats"},
    "target": {"en": "Target", "fr": "Cible"},
    "median": {"en": "Median", "fr": "Médian"},
    "files": {"en": "files", "fr": "fichiers"},
    "parsed": {"en": "parsed", "fr": "analysés"},
    "failures": {"en": "failures", "fr": "échecs"},
    "total_time": {"en": "total", "fr": "au total"},
    "report_exported_to": {"en": "Report exported to", "fr": "Rapport exporté dans"},
    "benchmark_running": {"en": "Benchmarking", "fr": "Benchmark du catalogue"},
    "doctor_title": {"en": "RuleScope Environment", "fr": "Environnement RuleScope"},
    "item": {"en": "Item", "fr": "Élément"},
    "rulescope_version": {"en": "RuleScope version", "fr": "Version de RuleScope"},
    "platform": {"en": "Platform", "fr": "Plateforme"},
    "benchmark_summary_line": {"en": "{total} files, {parsed} parsed, {failures} failures, {time}ms total, {rate} rules/sec", "fr": "{total} fichiers, {parsed} analysés, {failures} échecs, {time} ms au total, {rate} règles/s"},
    "report_summary_line": {"en": "{total} rules analyzed, score {score}/100 ({band})", "fr": "{total} règles analysées, score {score}/100 ({band})"},
    "navigator_summary_line": {"en": "{total} rules, {mapped} with ATT&CK mappings", "fr": "{total} règles, {mapped} avec des mappings ATT&CK"},
    "benchmark_usage": {"en": "Usage: benchmark <path> [--output FILE]", "fr": "Usage : benchmark <chemin> [--output FICHIER]"},
    "score_band_excellent": {"en": "Excellent", "fr": "Excellent"},
    "score_band_good": {"en": "Good", "fr": "Bon"},
    "score_band_needs_work": {"en": "Needs work", "fr": "À retravailler"},
    "score_band_high_risk": {"en": "High risk", "fr": "Risque élevé"},
    "score_band_critical": {"en": "Critical", "fr": "Critique"},
    "severity_critical": {"en": "critical", "fr": "critique"},
    "severity_high": {"en": "high", "fr": "élevé"},
    "severity_medium": {"en": "medium", "fr": "moyen"},
    "severity_low": {"en": "low", "fr": "faible"},
    "severity_info": {"en": "info", "fr": "info"},
    "severity_focus": {"en": "Severity focus", "fr": "Focus sévérité"},
    "findings": {"en": "Findings", "fr": "Constats"},
    "review_focus": {"en": "Review focus", "fr": "Axes de revue"},
    "semantic_profile": {"en": "Semantic profile", "fr": "Profil sémantique"},
    "recommended_improvements": {"en": "Recommended improvements", "fr": "Améliorations recommandées"},
    "immediate_next_steps": {"en": "Immediate next steps:", "fr": "Actions immédiates :"},
    "then_harden_rule": {"en": "Then harden the rule:", "fr": "Puis durcissez la règle :"},
    "next_hardening_steps": {"en": "Next hardening steps:", "fr": "Étapes suivantes de durcissement :"},
    "explain_scope_title": {"en": "Explain scope", "fr": "Périmètre d'explication"},
    "explain_scope_file": {"en": "Explaining the selected rule file. Use a folder path to let RuleScope choose the weakest rules.", "fr": "Explication du fichier de règle sélectionné. Utilisez un dossier pour laisser RuleScope choisir les règles les plus faibles."},
    "explain_scope_single": {"en": "Folder mode without --all explains only the single weakest rule out of {total} analyzed. Add --all --max-rules N for a broader review.", "fr": "En mode dossier sans --all, seule la règle la plus faible parmi {total} analysées est expliquée. Ajoutez --all --max-rules N pour une revue plus large."},
    "explain_scope_all": {"en": "Folder mode with --all explains the weakest {count} rule(s) out of {total} analyzed. It does not dump every rule in the folder.", "fr": "En mode dossier avec --all, RuleScope explique les {count} règle(s) les plus faibles sur {total} analysées. Il n'affiche pas toutes les règles du dossier."},
    "explain_panel_title_single": {"en": "Explain", "fr": "Explication"},
    "explain_panel_title_all": {"en": "Explain {index}/{total}", "fr": "Explication {index}/{total}"},
    "watch_stopped": {"en": "Stopped watching for changes.", "fr": "Surveillance arrêtée."},
    "watch_rescan_reason": {"en": "Rescan reason", "fr": "Raison du rescan"},
    "watch_reason_initial": {"en": "Initial scan", "fr": "Scan initial"},
    "watch_reason_manual": {"en": "Manual refresh", "fr": "Rafraîchissement manuel"},
    "watch_reason_changed": {"en": "Change detected in: {files}", "fr": "Changement détecté dans : {files}"},
    "watch_no_top_issues": {"en": "No current issues in the top-issues view.", "fr": "Aucun problème courant dans la vue des problèmes principaux."},
    "quality_pillars": {"en": "Quality Pillars", "fr": "Piliers de qualité"},
    "governance_budget_failures": {"en": "Governance Budget Failures", "fr": "Échecs du budget de gouvernance"},
    "technical_debt_by_category": {"en": "Technical Debt by Category", "fr": "Dette technique par catégorie"},
    "scores_by_logsource": {"en": "Scores by Logsource", "fr": "Scores par logsource"},
    "duplicate_clusters": {"en": "Duplicate Clusters", "fr": "Groupes de doublons"},
    "rule_details": {"en": "Rule Details", "fr": "Détail des règles"},
    "search_rules_placeholder": {"en": "Search rules by name, code, or path...", "fr": "Rechercher par nom de règle, code ou chemin..."},
    "all": {"en": "All", "fr": "Toutes"},
    "critical": {"en": "Critical", "fr": "Critique"},
    "high": {"en": "High", "fr": "Élevé"},
    "medium": {"en": "Medium", "fr": "Moyen"},
    "low_info": {"en": "Low+Info", "fr": "Faible+Info"},
    "score_lt_70": {"en": "Score < 70", "fr": "Score < 70"},
    "budget_label": {"en": "Budget", "fr": "Budget"},
    "no_critical_actions_required": {"en": "No critical actions required.", "fr": "Aucune action critique requise."},
}


def set_lang(lang: str) -> None:
    global _current_lang
    code = (lang or "").lower().strip()
    _current_lang = "fr" if code.startswith("fr") else "en"


def get_lang() -> str:
    return _current_lang


def t(key: str, **kwargs: Any) -> str:
    entry = STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(_current_lang, entry.get("en", key))
    if kwargs:
        text = text.format(**kwargs)
    return text




def init_lang(lang: str | None = None) -> str:
    """Initialize rendering language deterministically.

    CLI subcommands and reporters default to English unless the caller
    explicitly selects a language or RULESCOPE_LANG is set. This keeps
    scripted usage and tests stable across host locales. Interactive
    console language selection remains handled by the CLI.
    """
    env_lang = os.environ.get("RULESCOPE_LANG", "").lower().strip()
    if isinstance(lang, str) and lang.strip():
        resolved = lang.strip()
    elif env_lang in ("fr", "french", "en", "english"):
        resolved = "fr" if env_lang.startswith("fr") else "en"
    else:
        resolved = "en"
    set_lang(resolved)
    return get_lang()


def score_band_label(text: str) -> str:
    mapping = {
        "Excellent": "score_band_excellent",
        "Good": "score_band_good",
        "Needs work": "score_band_needs_work",
        "High risk": "score_band_high_risk",
        "Critical": "score_band_critical",
    }
    key = mapping.get(text)
    return t(key) if key else text


def pillar_label(name: str) -> str:
    mapping = {
        "metadata": {"en": "metadata", "fr": "métadonnées"},
        "maintainability": {"en": "maintainability", "fr": "maintenabilité"},
        "noise": {"en": "noise", "fr": "bruit"},
        "structural": {"en": "structural", "fr": "structure"},
        "documentation": {"en": "documentation", "fr": "documentation"},
        "attack_quality": {"en": "attack_quality", "fr": "qualité ATT&CK"},
        "weakness": {"en": "weakness", "fr": "faiblesse"},
    }
    return mapping.get(name, {}).get(get_lang(), name)


def severity_label(level: str) -> str:
    return t(f"severity_{level.lower()}") if level else level

def detect_system_lang() -> str:
    env_lang = os.environ.get("RULESCOPE_LANG", "").lower().strip()
    if env_lang in ("fr", "french"):
        return "fr"
    if env_lang in ("en", "english"):
        return "en"
    locale_lang = os.environ.get("LANG", "").lower()
    if locale_lang.startswith("fr"):
        return "fr"
    return "en"


# Canonical finding translations. The engine keeps English codes/messages as the
# source of truth; rendering layers translate them at display time.
FINDING_MESSAGES = {
    "PARSE-001": {"fr": "Échec du parsing YAML."},
    "DUP-001": {"fr": "La règle a des doublons ou des homologues très similaires."},
    "OVL-001": {"fr": "La règle chevauche fortement d'autres règles sur la même logsource."},
    "ATK-001": {"fr": "La règle n'a aucun tag ATT&CK."},
    "ATK-002": {"fr": "La règle a des tags de technique mais aucun tag de tactique."},
    "ATK-003": {"fr": "La règle a des tags de tactique mais aucune technique précise."},
    "ATK-004": {"fr": "La règle mappe trop de tactiques ATT&CK pour sa logique actuelle."},
    "ATK-005": {"fr": "Le mapping ATT&CK semble trop large ou imprécis."},
    "ATK-006": {"fr": "La règle ne mappe que des techniques parentes, sans sous-technique."},
    "DOC-001": {"fr": "Le titre n'est pas capitalisé correctement."},
    "DOC-002": {"fr": "Le titre est trop générique pour être utile."},
    "DOC-003": {"fr": "La description est trop succincte."},
    "DOC-004": {"fr": "La description pourrait être plus détaillée."},
    "DOC-005": {"fr": "Les faux positifs déclarés sont des placeholders trop génériques."},
    "DOC-006": {"fr": "Certaines références ne sont pas des URL valides."},
    "MAINT-001": {"fr": "Le bloc de détection contient beaucoup de sélections."},
    "MAINT-002": {"fr": "L'expression de condition est complexe."},
    "MAINT-003": {"fr": "Des champs de détection imbriqués rendent la règle plus difficile à relire."},
    "MAINT-004": {"fr": "La chaîne de condition est anormalement longue."},
    "MAINT-005": {"fr": "La détection a des noms de sélecteurs peu cohérents ou ambigus."},
    "MAINT-006": {"fr": "La structure de la règle est plus complexe que nécessaire pour sa finalité."},
    "META-001": {"fr": "Il manque des métadonnées importantes à la règle."},
    "META-002": {"fr": "L'identifiant de la règle n'est pas un UUID valide."},
    "META-003": {"fr": "Le statut de la règle n'est pas aligné avec un cycle de vie Sigma clair."},
    "META-004": {"fr": "Le niveau de sévérité n'est pas standardisé ou manque de justification."},
    "META-005": {"fr": "La description est trop courte pour expliquer l'intention analyste."},
    "META-006": {"fr": "La règle a trop peu de tags."},
    "META-007": {"fr": "La règle n'a pas de date de création."},
    "NOISE-001": {"fr": "La règle utilise de nombreux jokers et risque d'être trop large."},
    "NOISE-002": {"fr": "La règle s'appuie fortement sur des motifs de type expression régulière."},
    "NOISE-003": {"fr": "Les indications sur les faux positifs sont absentes."},
    "NOISE-004": {"fr": "Une règle de forte sévérité s'appuie sur des champs processus trop génériques."},
    "NOISE-005": {"fr": "Sévérité haute/critique avec une logique de détection très faible."},
    "NOISE-006": {"fr": "Presque toutes les valeurs de détection utilisent des jokers."},
    "NOISE-007": {"fr": "La règle utilise des jokers en préfixe qui forcent des scans texte coûteux."},
    "STRUCT-001": {"fr": "La règle n'a pas de logsource valide."},
    "STRUCT-002": {"fr": "La logsource n'a ni produit ni catégorie."},
    "STRUCT-003": {"fr": "La règle n'a pas de bloc de détection valide."},
    "STRUCT-004": {"fr": "Le bloc de détection ne définit pas de condition."},
    "STRUCT-005": {"fr": "La structure du bloc de détection est invalide."},
    "STRUCT-006": {"fr": "Le titre de la règle est anormalement long."},
    "STRUCT-007": {"fr": "La condition référence des sélecteurs non définis."},
    "STRUCT-008": {"fr": "Certains sélecteurs sont définis mais jamais utilisés dans la condition."},
    "WEAK-001": {"fr": "La règle repose sur un seul bloc de sélection."},
    "WEAK-002": {"fr": "La règle utilise plusieurs valeurs fortement basées sur des jokers."},
    "WEAK-003": {"fr": "La règle dépend surtout d'une logique basée sur contains."},
    "WEAK-004": {"fr": "La règle a une faible diversité de champs."},
    "WEAK-005": {"fr": "La sévérité déclarée est plus forte que la logique de détection sous-jacente."},
    "WEAK-006": {"fr": "La condition utilise une négation pure sans sélecteur positif."},
    "WEAK-007": {"fr": "La détection ne contient que des filtres/exclusions sans sélection positive."},
    "WEAK-008": {"fr": "La règle repose sur des valeurs trop vagues pour décrire un comportement réellement distinctif."},
    "WEAK-009": {"fr": "La précision sémantique de la règle est trop faible pour son intention déclarée."},
    "CORR-001": {"fr": "La règle de corrélation n'a ni type ni référence vers des règles sources."},
    "CORR-002": {"fr": "La règle de corrélation n'a pas de champs group-by."},
    "CORR-003": {"fr": "La règle de corrélation n'a pas de fenêtre temporelle."},
    "CORR-004": {"fr": "La règle de corrélation ne référence aucune règle source et n'a pas de détection inline."},
}
FINDING_RECOMMENDATIONS = {
    "PARSE-001": {"fr": "Corrigez la syntaxe YAML ou la structure non supportée."},
    "DUP-001": {"fr": "Relisez la logique dupliquée et envisagez une fusion ou une refactorisation."},
    "OVL-001": {"fr": "Identifiez les candidats à la fusion ou documentez clairement la différenciation."},
    "ATK-001": {"fr": "Ajoutez au moins une tactique et une technique ATT&CK."},
    "ATK-002": {"fr": "Ajoutez un tag de tactique ATT&CK cohérent avec la technique."},
    "ATK-003": {"fr": "Ajoutez une technique ou sous-technique ATT&CK plus précise."},
    "ATK-004": {"fr": "Réduisez le mapping ATT&CK aux tactiques réellement couvertes."},
    "ATK-005": {"fr": "Revoyez le mapping ATT&CK pour gagner en précision et éviter les techniques vagues."},
    "ATK-006": {"fr": "Mappez la règle vers une sous-technique quand c'est pertinent."},
    "DOC-001": {"fr": "Utilisez une casse titre pour améliorer la lisibilité dans les dashboards."},
    "DOC-002": {"fr": "Utilisez un titre descriptif qui exprime clairement le comportement suspect détecté."},
    "DOC-003": {"fr": "Décrivez ce que la règle détecte, pourquoi c'est important et quelles sources sont attendues."},
    "DOC-004": {"fr": "Ajoutez du contexte sur le comportement menaçant et les attentes liées à la source de données."},
    "DOC-005": {"fr": "Remplacez les placeholders par de vrais scénarios bénins attendus."},
    "DOC-006": {"fr": "Corrigez ou remplacez les références non valides par de vraies URL."},
    "MAINT-001": {"fr": "Scindez la règle ou simplifiez la structure logique lorsque c'est possible."},
    "MAINT-002": {"fr": "Réduisez l'embranchement logique pour faciliter la revue et la portabilité."},
    "MAINT-003": {"fr": "Réduisez les structures de champs imbriquées ou extrayez les motifs répétés."},
    "MAINT-004": {"fr": "Raccourcissez la condition pour qu'elle reste compréhensible en revue."},
    "MAINT-005": {"fr": "Clarifiez les noms de sélecteurs et rendez la condition plus explicite."},
    "MAINT-006": {"fr": "Réduisez la complexité structurelle avant de promouvoir la règle."},
    "META-001": {"fr": "Complétez les métadonnées manquantes pour améliorer la maintenabilité et la portabilité."},
    "META-002": {"fr": "Utilisez un UUID v4 pour identifier la règle de manière unique."},
    "META-003": {"fr": "Normalisez le statut avec un cycle de vie Sigma tel que experimental, test, stable ou deprecated."},
    "META-004": {"fr": "Alignez la sévérité sur un niveau supporté et documentez sa justification."},
    "META-005": {"fr": "Étendez la description afin qu'un reviewer comprenne le comportement, l'intention et le contexte d'activation attendu."},
    "META-006": {"fr": "Ajoutez des tags plus riches : tactique/technique ATT&CK, plateforme, et tags de thème détection."},
    "META-007": {"fr": "Ajoutez une date de création pour améliorer la traçabilité et la maintenance future."},
    "NOISE-001": {"fr": "Resserrez les valeurs de correspondance ou ajoutez des exclusions pour réduire le bruit."},
    "NOISE-002": {"fr": "Documentez la justification et validez le niveau attendu de faux positifs."},
    "NOISE-003": {"fr": "Documentez des scénarios bénins réalistes pour aider le triage analyste."},
    "NOISE-004": {"fr": "Ajoutez des contraintes contextuelles ou baissez la sévérité jusqu'à validation."},
    "NOISE-005": {"fr": "Renforcez la logique de détection ou baissez la sévérité pour réaligner risque et confiance."},
    "NOISE-006": {"fr": "Remplacez certains jokers par des valeurs exactes ou des startswith/endswith."},
    "NOISE-007": {"fr": "Remplacez les motifs '*valeur' par 'valeur*', '|endswith' ou des correspondances exactes quand c'est possible."},
    "STRUCT-001": {"fr": "Complétez les informations de logsource pour lever toute ambiguïté sur la source d'événements."},
    "STRUCT-002": {"fr": "Ajoutez product ou category à la logsource pour améliorer le routage et les contrôles qualité."},
    "STRUCT-003": {"fr": "Complétez la section detection ; une règle sans détection valide ne doit pas être mergée."},
    "STRUCT-004": {"fr": "Ajoutez une clause condition pour expliciter la logique de détection."},
    "STRUCT-005": {"fr": "Réparez la structure de détection avant toute revue qualité."},
    "STRUCT-006": {"fr": "Corrigez la structure invalide en priorité ; les autres constats sont secondaires tant que le parsing n'est pas stable."},
    "STRUCT-007": {"fr": "Corrigez la condition pour ne référencer que des sélecteurs définis."},
    "STRUCT-008": {"fr": "Référencez les sélecteurs inutilisés dans la condition ou supprimez le code mort."},
    "WEAK-001": {"fr": "Ajoutez un ou plusieurs sélecteurs discriminants pour améliorer la sélectivité."},
    "WEAK-002": {"fr": "Remplacez les jokers larges par des valeurs plus spécifiques ou des filtres complémentaires."},
    "WEAK-003": {"fr": "Préférez endswith, startswith, des valeurs exactes ou des filtres contextuels parent/process."},
    "WEAK-004": {"fr": "Mélangez image, parent, ligne de commande, utilisateur ou chemin pour renforcer l'intention de détection."},
    "WEAK-005": {"fr": "Renforcez la détection ou baissez la sévérité jusqu'à un niveau plus crédible."},
    "WEAK-006": {"fr": "Ajoutez une sélection positive avant la négation : une condition purement 'not X' matche tout."},
    "WEAK-007": {"fr": "Ajoutez un bloc de sélection positif qui décrit ce que la règle cible, pas seulement des exclusions."},
    "CORR-001": {"fr": "Ajoutez un type de corrélation (event_count, value_count, temporal) et référencez les règles de base."},
    "CORR-002": {"fr": "Ajoutez des champs de group-by pour cadrer la corrélation (ex. IP source, utilisateur)."},
    "CORR-003": {"fr": "Ajoutez une fenêtre temporelle (ex. 5m, 1h) pour borner la corrélation."},
    "CORR-004": {"fr": "Ajoutez une liste 'rules' pointant vers les règles de base par ID ou nom."},
}
TEXT_TRANSLATIONS = {
    "Metadata debt hurts reviewability, ownership, and lifecycle tracking.": {"fr": "La dette de métadonnées nuit à la revue, à l'attribution et au suivi du cycle de vie."},
    "Documentation debt slows triage and makes reviewer intent harder to preserve.": {"fr": "La dette documentaire ralentit le triage et rend l'intention du reviewer plus difficile à préserver."},
    "Noise issues raise false-positive risk and erode analyst trust.": {"fr": "Les problèmes de bruit augmentent le risque de faux positifs et érodent la confiance des analystes."},
    "Weakness issues reduce selectivity and can make the rule hard to operate at scale.": {"fr": "Les problèmes de faiblesse réduisent la sélectivité et compliquent l'exploitation de la règle à l'échelle."},
    "Coverage issues reduce ATT&CK reporting quality and content governance value.": {"fr": "Les problèmes de couverture réduisent la qualité du reporting ATT&CK et la valeur de gouvernance du contenu."},
    "Maintainability issues increase rule debt and future change risk.": {"fr": "Les problèmes de maintenabilité augmentent la dette des règles et le risque lors des futurs changements."},
    "Structural issues can invalidate the rule or make later findings unreliable.": {"fr": "Les problèmes structurels peuvent invalider la règle ou rendre les constats suivants peu fiables."},
    "This area deserves targeted cleanup before merge.": {"fr": "Cette zone mérite un nettoyage ciblé avant le merge."},
    "No findings.": {"fr": "Aucun constat."},
    "Rule: ": {"fr": "Règle : "},
    "Path: ": {"fr": "Chemin : "},
    "Overall score: ": {"fr": "Score global : "},
    "Severity focus: ": {"fr": "Focus sévérité : "},
    "Findings:": {"fr": "Constats :"},
    "Review focus:": {"fr": "Axes de revue :"},
    "Semantic profile:": {"fr": "Profil sémantique :"},
    "Recommended improvements:": {"fr": "Améliorations recommandées :"},
    "Waiting for first scan...": {"fr": "En attente du premier scan..."},
    "Add a second selector around parent process, user, or command line so the rule is not driven by a single block.": {"fr": "Ajoutez un second sélecteur autour du parent process, de l'utilisateur ou de la ligne de commande pour que la règle ne repose pas sur un seul bloc."},
    "Where possible, replace contains modifiers with startswith, endswith, or exact tokens tied to known attacker tradecraft.": {"fr": "Quand c'est possible, remplacez les modificateurs contains par startswith, endswith ou des tokens exacts liés à un tradecraft attaquant connu."},
    "Increase field diversity by combining image, command line, parent image, or user context in the same rule.": {"fr": "Augmentez la diversité des champs en combinant image, ligne de commande, parent image ou contexte utilisateur dans la même règle."},
    "Add at least one ATT&CK tactic and one technique tag so the rule contributes to coverage governance.": {"fr": "Ajoutez au moins une tactique et une technique ATT&CK pour que la règle contribue à la gouvernance de couverture."},
    "Document 2-3 concrete benign scenarios in falsepositives, such as admin scripts, software deployment, or IT troubleshooting.": {"fr": "Documentez 2 ou 3 scénarios bénins concrets dans falsepositives, par exemple scripts d'administration, déploiement logiciel ou dépannage IT."},
    "Expand the description with intent, expected trigger path, and what a reviewer should verify first during triage.": {"fr": "Étendez la description avec l'intention, le chemin d'activation attendu et ce qu'un reviewer doit vérifier en premier pendant le triage."},
    "This rule already looks production-ready. Keep validating it against real telemetry before promoting severity.": {"fr": "Cette règle semble déjà prête pour la production. Continuez à la valider sur de la télémétrie réelle avant d'augmenter sa sévérité."},
    "Immediate next steps:": {"fr": "Actions immédiates :"},
    "Then harden the rule:": {"fr": "Puis durcissez la règle :"},
    "Next hardening steps:": {"fr": "Étapes suivantes de durcissement :"},
    "Re-run the scan after the rule parses cleanly so downstream findings reflect the real logic.": {"fr": "Relancez le scan une fois que la règle parse correctement afin que les constats suivants reflètent la vraie logique."},
}

TEXT_TRANSLATIONS.update({
    "Catalog quality improved meaningfully over baseline.": {"fr": "La qualité du catalogue s'est améliorée de façon nette par rapport à la référence."},
    "Semantic improvements detected: 1.": {"fr": "Améliorations sémantiques détectées : 1."},
    "Duplicate pairs delta: +1.": {"fr": "Écart des paires de doublons : +1."},
    "Duplicate pairs delta: -1.": {"fr": "Écart des paires de doublons : -1."},
    "Overlap pairs delta: +1.": {"fr": "Écart des paires de chevauchement : +1."},
    "Overlap pairs delta: -1.": {"fr": "Écart des paires de chevauchement : -1."},
    "Candidate pack introduces broader semantic overlap that may duplicate alerts.": {"fr": "Le pack candidat introduit davantage de chevauchements sémantiques, avec un risque d'alertes en doublon."},
    "Logsource changed between baseline and candidate.": {"fr": "La logsource a changé entre la référence et le candidat."},
    "Rule became broader due to additional wildcard matching.": {"fr": "La règle est devenue plus large à cause de jokers supplémentaires."},
    "Rule became more selective by reducing wildcard usage.": {"fr": "La règle est devenue plus sélective en réduisant l'usage des jokers."},
    "Candidate relies more on contains-style matching.": {"fr": "Le candidat s'appuie davantage sur des correspondances de type contains."},
    "Candidate adds more exact or bounded modifiers.": {"fr": "Le candidat ajoute plus de modificateurs exacts ou bornés."},
    "Candidate lost field diversity and may carry less context.": {"fr": "Le candidat a perdu en diversité de champs et peut porter moins de contexte."},
    "Candidate gained field diversity and investigative context.": {"fr": "Le candidat gagne en diversité de champs et en contexte d'investigation."},
    "Candidate has fewer selector blocks, reducing discrimination.": {"fr": "Le candidat comporte moins de blocs de sélection, ce qui réduit le pouvoir discriminant."},
    "Candidate adds selector blocks that may improve confidence.": {"fr": "Le candidat ajoute des blocs de sélection susceptibles d'améliorer la confiance analytique."},
    "Candidate exposes less ATT&CK technique coverage metadata.": {"fr": "Le candidat expose moins de métadonnées de couverture ATT&CK au niveau des techniques."},
    "Candidate increases ATT&CK technique coverage metadata.": {"fr": "Le candidat augmente les métadonnées de couverture ATT&CK au niveau des techniques."},
    "Severity increased without stronger rule quality.": {"fr": "La sévérité a augmenté sans renforcement de la qualité de la règle."},
    "Severity was reduced while quality stayed stable or improved.": {"fr": "La sévérité a été abaissée alors que la qualité est restée stable ou s'est améliorée."},
    "Condition logic became materially more complex.": {"fr": "La logique de condition est devenue sensiblement plus complexe."},
    "Condition logic became simpler and easier to review.": {"fr": "La logique de condition est devenue plus simple et plus facile à relire."},
})


def translate_text(text: str) -> str:
    if get_lang() == 'en' or not text:
        return text
    translated = TEXT_TRANSLATIONS.get(text, {}).get(get_lang())
    if translated:
        return translated
    import re
    patterns = [
        (r"^Fix (\d+) invalid or structurally broken rules first\.$", r"Corrigez d'abord \1 règle(s) invalide(s) ou structurellement cassée(s)."),
        (r'^Review (\d+) duplicate clusters to reduce redundant detections\.$', r'Revoyez \1 cluster(s) de doublons pour réduire les détections redondantes.'),
        (r'^Tune or narrow (\d+) high-noise rules before production rollout\.$', r'Ajustez ou resserrez \1 règle(s) bruyante(s) avant un déploiement en production.'),
        (r'^Complete metadata on (\d+) weakly documented rules\.$', r'Complétez les métadonnées de \1 règle(s) faiblement documentée(s).'),
        (r'^Harden (\d+) analytically weak rules before promoting them to production severity\.$', r'Durcissez \1 règle(s) analytiquement faible(s) avant de les promouvoir à une sévérité de production.'),
        (r'^Strengthen fragile ATT&CK coverage in: (.+)\.$', r'Renforcez la couverture ATT&CK fragile dans : \1.'),
        (r'^Catalog score delta: ([+-]?\d+) points\.$', r'Écart du score catalogue : \1 point(s).'),
        (r'^Semantic regressions detected: (\d+)\.$', r'Régressions sémantiques détectées : \1.'),
        (r'^Analytically weak rules delta: ([+-]?\d+)\.$', r'Écart de règles analytiquement faibles : \1.'),
        (r'^Rules added/removed: ([+-]?\d+) / ([+-]?\d+)\.$', r'Règles ajoutées/supprimées : \1 / \2.'),
        (r'^Rules with material regressions: (\d+)\.$', r'Règles avec régressions significatives : \1.'),
        (r'^New high/critical findings introduced: (\d+)\.$', r'Nouveaux constats high/critical introduits : \1.'),
        (r'^Replace at least (\d+) wildcard-heavy values with bounded patterns or exact switches to reduce broad matches\.$', r'Remplacez au moins \1 valeur(s) très basées sur des jokers par des motifs bornés ou des commutateurs exacts pour réduire les correspondances trop larges.'),
        (r'^Merge or retire duplicate logic found in (\d+) nearby rule\(s\) to reduce redundant alerts\.$', r'Fusionnez ou retirez la logique dupliquée trouvée dans \1 règle(s) proche(s) afin de réduire les alertes redondantes.'),
        (r'^Document or refactor (\d+) overlap relationship\(s\) so alert ownership stays clear\.$', r'Documentez ou refactorisez \1 relation(s) de chevauchement afin que la responsabilité des alertes reste claire.'),
    ]
    for pattern, repl in patterns:
        if re.match(pattern, text):
            return re.sub(pattern, repl, text)
    return text


def localize_finding(finding: Any) -> Any:
    if get_lang() == 'en':
        return finding
    clone = finding.model_copy(deep=True)
    clone.message = FINDING_MESSAGES.get(finding.code, {}).get(get_lang(), finding.message)
    if finding.recommendation:
        clone.recommendation = FINDING_RECOMMENDATIONS.get(finding.code, {}).get(get_lang(), finding.recommendation)
    if getattr(finding, 'impact', ''):
        clone.impact = translate_text(finding.impact)
    return clone


def localize_report_for_render(report: Any) -> Any:
    if get_lang() == 'en':
        return report
    clone = report.model_copy(deep=True)
    if hasattr(clone, 'rules'):
        for rule in clone.rules:
            if hasattr(rule, 'findings'):
                rule.findings = [localize_finding(f) for f in rule.findings]
    try:
        for rec in clone.summary.debt.top_recommendations:
            rec.recommendation = translate_text(rec.recommendation)
    except Exception:
        pass
    return clone

TEXT_TRANSLATIONS.update({
    "Review for merge candidates or document differentiation.": {"fr": "Identifiez les candidats au merge ou documentez clairement la différenciation."},
    "Prefer endswith, startswith, exact values, or contextual parent/process filters.": {"fr": "Préférez endswith, startswith, des valeurs exactes ou des filtres contextuels parent/process."},
    "Add one or more discriminating selectors to improve selectivity.": {"fr": "Ajoutez un ou plusieurs sélecteurs discriminants pour améliorer la sélectivité."},
    "Review duplicated logic and consider merge or refactor.": {"fr": "Revoyez la logique dupliquée et envisagez une fusion ou une refactorisation."},
    "Map to sub-techniques where applicable for precise coverage.": {"fr": "Mappez vers des sous-techniques lorsque c'est pertinent pour une couverture plus précise."},
    "Tighten matching values or add exclusions to reduce noise.": {"fr": "Resserrez les valeurs de correspondance ou ajoutez des exclusions pour réduire le bruit."},
    "Either enrich the detection logic or lower the severity level.": {"fr": "Renforcez la logique de détection ou baissez le niveau de sévérité."},
    "Either harden the detection or downgrade the severity until it becomes selective enough.": {"fr": "Renforcez la détection ou baissez la sévérité jusqu'à ce qu'elle devienne assez sélective."},
    "Document realistic benign scenarios for analyst triage.": {"fr": "Documentez des scénarios bénins réalistes pour aider le triage analyste."},
    "Populate the missing metadata to improve maintainability and portability.": {"fr": "Complétez les métadonnées manquantes pour améliorer la maintenabilité et la portabilité."},
    "Mix process, parent, command line, user, or image path fields for stronger intent.": {"fr": "Mélangez process, parent, ligne de commande, utilisateur ou chemin d'image pour une intention plus forte."},
})

TEXT_TRANSLATIONS.update({
    "Quality dropped materially; review the changed rules before merge.": {"fr": "La qualité a baissé de manière notable ; relisez les règles modifiées avant le merge."},
    "Regression": {"fr": "Régression"},
    "Improved": {"fr": "Amélioration"},
    "Stable": {"fr": "Stable"},
})
